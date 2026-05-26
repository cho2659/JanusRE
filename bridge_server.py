"""
frida_bridge.py
===============
frida_bridge_server.py + call_graph_view.py 통합 단일 파일.

역할:
  1. PySide6 GUI (왼쪽: 타겟 모듈 / 중앙: 콜 그래프 / 오른쪽: 로드 모듈)
  2. Frida 에이전트 실행 및 트레이스 수신
  3. 트레이스 후처리 (raw VA → module+offset)
  4. Ghidra Script TCP 서버 (포트 8763)
  5. 트레이스 저장/불러오기 (JSON)
  6. IDA Pro 스타일 콜스택 그래프 위젯 (CallGraphPanel)

실행:
  python frida_bridge.py             # GUI 모드
  python frida_bridge.py --headless  # GUI 없이 서버만

의존성:
  pip install PySide6 frida networkx
  frida-compile agent.ts -o agent.js

call_graph_view.py 구조:
  CallGraphPanel
    ├── QTabWidget        ← 스레드별 탭
    ├── SearchPanel       ← 검색창 + ◀▶ 탐색
    └── GraphView (per thread)
          └── GraphScene
                ├── NodeItem    (QGraphicsItem)
                └── EdgeItem    (QGraphicsPathItem)

렌더링 파이프라인 (프리징 없음):
  TraceSession
    → CallTreeBuilder.build()   [메인스레드, 빠름]
    → LayoutWorker.run()        [QThread, 계산 무거움]
    → GraphScene.apply()        [메인스레드, 그리기만]
"""

from __future__ import annotations

import bisect
import ctypes
import json
import math
import os
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Optional
from ctypes import wintypes

import frida
import networkx as nx
from PySide6.QtCore import (
    Qt, QThread, Signal, QObject, QRectF, QPointF,
)
from PySide6.QtGui import (
    QAction,
    QPainter, QPen, QBrush, QColor, QFont,
    QFontMetrics, QPainterPath, QWheelEvent,
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QSplitter,
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QListWidget, QListWidgetItem, QMenu, QFileDialog,
    QMessageBox, QStatusBar, QTreeWidget, QTreeWidgetItem,
    QGraphicsScene, QGraphicsView, QGraphicsItem,
    QGraphicsPathItem, QTabWidget, QLineEdit,
)

AGENT_JS_PATH      = Path(__file__).parent / "frida_agent" / "agent.js"
GHIDRA_SERVER_HOST = "0.0.0.0"
GHIDRA_SERVER_PORT = 8763
PE_MACHINE_I386    = 0x014C
PE_MACHINE_AMD64   = 0x8664
PE_MACHINE_ARM64   = 0xAA64


def dbg(msg: str):
    print("[frida_delta] {}".format(msg), flush=True)


# ============================================================
# 색상 (IDA Pro 라이트 테마)
# ============================================================

C_BG          = QColor("#F5F5F5")   # 캔버스 배경
C_NODE_BG     = QColor("#FFFFFF")   # 일반 노드
C_NODE_BORDER = QColor("#C0C8D0")   # 노드 테두리
C_NODE_SEL    = QColor("#0078D4")   # 선택 강조
C_NODE_SEARCH = QColor("#D4820A")   # 검색 강조
C_NODE_ENTRY  = QColor("#E8F4E8")   # 진입 노드 배경
C_NODE_EXIT   = QColor("#FDE8E8")   # 종료 노드 배경
C_TEXT_FUNC   = QColor("#1F3864")   # 함수명 (진한 네이비)
C_TEXT_ADDR   = QColor("#0060A8")   # 주소 (IDA 블루)
C_TEXT_SUB    = QColor("#6B7280")   # 보조 텍스트
C_TEXT_ARG    = QColor("#005FAF")   # 인자 레지스터
C_TEXT_RET    = QColor("#007050")   # 반환값
C_EDGE_CALL   = QColor("#0078D4")   # call 엣지
C_EDGE_RET    = QColor("#9CA3AF")   # ret 엣지
C_EDGE_SYNC   = QColor("#B45309")   # sync 엣지
C_EDGE_SPAWN  = QColor("#7C3AED")   # spawn 엣지

FONT_MAIN = QFont("Consolas", 9)
FONT_ADDR = QFont("Consolas", 8)
FONT_SUB  = QFont("Consolas", 8)

# 노드 크기 상수
NODE_W   = 280
PAD      = 8
LINE_H   = 16
H_GAP    = 140
V_GAP    = 48
ARROW_SZ = 7


# ============================================================
# 데이터 모델 (call_graph_view)
# ============================================================

class CallNode:
    __slots__ = (
        "node_id", "module", "symbol", "offset",
        "tid", "call_seq", "trace_seq", "depth",
        "args", "retval",
        "children_ids", "parent_id",
        "spawn_tid", "spawned_by_id",
        "is_entry", "is_exit",
        "expanded",
    )

    def __init__(self, node_id: str, module: str, symbol: str,
                 offset: int, tid: int, call_seq: int, depth: int):
        self.node_id        = node_id
        self.module         = module
        self.symbol         = symbol
        self.offset         = offset
        self.tid            = tid
        self.call_seq       = call_seq
        self.trace_seq      = call_seq
        self.depth          = depth
        self.args:          Optional[dict] = None
        self.retval:        Optional[str]  = None
        self.children_ids:  list[str] = []
        self.parent_id:     Optional[str]  = None
        self.spawn_tid:     Optional[int]  = None
        self.spawned_by_id: Optional[str]  = None
        self.is_entry = False
        self.is_exit  = False
        self.expanded = False

    def label(self) -> str:
        return self.symbol if self.symbol else "{}+{}".format(
            self.module, hex(self.offset))

    def addr_str(self) -> str:
        return "{}!{}".format(self.module, hex(self.offset))


class CallEdge:
    __slots__ = ("src_id", "dst_id", "kind", "tid")

    def __init__(self, src_id: str, dst_id: str, kind: str, tid: int):
        self.src_id = src_id
        self.dst_id = dst_id
        self.kind   = kind   # "call" | "sync" | "spawn" | "flow"
        self.tid    = tid


# ============================================================
# CallTreeBuilder
# ============================================================

class CallTreeBuilder:
    """
    TraceSession → {tid: (nodes, edges)} 변환.

    스냅샷 매칭:
      postprocess_events가 seq를 보존하지 않으므로
      이벤트 인덱스(call_seq)를 기반으로 스냅샷 배열의
      같은 인덱스 위치 스냅샷을 사용한다.
      (enter 스냅샷 인덱스 = call 이벤트 순서, kind=0)
      (ret   스냅샷 인덱스 = ret  이벤트 순서, kind=1)
    """

    def __init__(self, symbol_resolver=None):
        self._symbol_resolver = symbol_resolver

    def build(self, session) -> dict[int, tuple[dict, list]]:
        # 스냅샷을 (tid, kind) → 순서 큐로 구성
        enter_snaps: dict[int, list[dict]] = {}
        ret_snaps:   dict[int, list[dict]] = {}
        for snap in session.snapshots:
            tid  = snap.get("tid", 0)
            kind = snap.get("kind", 0)
            if kind == 0:
                enter_snaps.setdefault(tid, []).append(snap)
            else:
                ret_snaps.setdefault(tid, []).append(snap)

        # 스레드별 이벤트 분리
        by_tid: dict[int, list[dict]] = {}
        for ev in session.events:
            if ev.get("type") not in ("call", "ret"):
                continue
            tid = ev.get("thread_id", 0)
            by_tid.setdefault(tid, []).append(ev)

        sync_by_tid: dict[int, list[dict]] = {}
        for ev in getattr(session, "sync_events", []):
            tid = ev.get("tid", 0)
            sync_by_tid.setdefault(tid, []).append(ev)

        # spawn 이벤트: child_tid → spawn
        spawn_by_child: dict[int, dict] = {
            s["child_tid"]: s for s in getattr(session, "spawn_events", [])
        }

        result: dict[int, tuple[dict, list]] = {}
        for tid in sorted(set(by_tid.keys()) | set(sync_by_tid.keys())):
            events = by_tid.get(tid, [])
            nodes, edges = self._build_thread(
                tid, events,
                enter_snaps.get(tid, []),
                ret_snaps.get(tid, []),
                sync_by_tid.get(tid, []),
            )
            result[tid] = (nodes, edges)

        self._link_spawns(result, spawn_by_child)
        return result

    def _build_thread(
        self, tid: int, events: list[dict],
        enter_snaps: list[dict],
        ret_snaps:   list[dict],
        sync_events: list[dict],
    ) -> tuple[dict, list]:
        nodes: dict[str, CallNode] = {}
        edges: list[CallEdge]      = []
        stack: list[str]           = []
        call_counter: dict[str, int] = {}
        call_seq  = 0
        enter_idx = 0
        ret_idx   = 0

        timeline = (
            [(ev.get("seq", i), "trace", ev) for i, ev in enumerate(events)]
            + [(ev.get("seq", i), "sync", ev) for i, ev in enumerate(sync_events)]
        )
        timeline.sort(key=lambda item: item[0])

        for _, item_kind, ev in timeline:
            if item_kind == "sync":
                node_id = "sync_{}_{}".format(tid, ev.get("seq", call_seq))
                node = CallNode(
                    node_id  = node_id,
                    module   = "[sync]",
                    symbol   = self._sync_label(ev),
                    offset   = 0,
                    tid      = tid,
                    call_seq = call_seq,
                    depth    = len(stack),
                )
                node.trace_seq = ev.get("seq", call_seq)
                call_seq += 1
                if stack:
                    node.parent_id = stack[-1]
                    if stack[-1] in nodes:
                        nodes[stack[-1]].children_ids.append(node_id)
                    edges.append(CallEdge(stack[-1], node_id, "sync", tid))
                else:
                    node.is_entry = True
                nodes[node_id] = node
                continue

            ev_type = ev.get("type")
            if ev_type == "call":
                dst_mod = ev.get("dst_module", "unknown")
                dst_off = self._hex(ev.get("dst_offset", "0x0"))
                dst_sym = self._display_symbol(
                    dst_mod, ev.get("dst_offset", "0x0"))
                if not dst_sym:
                    dst_sym = ev.get("dst_symbol", "")

                base_key = "{}+{}".format(dst_mod, hex(dst_off))
                call_counter[base_key] = call_counter.get(base_key, 0) + 1
                node_id = "{}_{}".format(base_key, call_counter[base_key])

                node = CallNode(
                    node_id  = node_id,
                    module   = dst_mod,
                    symbol   = dst_sym,
                    offset   = dst_off,
                    tid      = tid,
                    call_seq = call_seq,
                    depth    = len(stack),
                )
                node.trace_seq = ev.get("seq", call_seq)
                call_seq += 1

                # enter 스냅샷 (순서 기반)
                if enter_idx < len(enter_snaps):
                    snap = enter_snaps[enter_idx]
                    node.args = {
                        "arch": snap.get("arch", "x64"),
                        "rcx": snap.get("rcx", ""),
                        "rdx": snap.get("rdx", ""),
                        "r8":  snap.get("r8",  ""),
                        "r9":  snap.get("r9",  ""),
                    }
                    enter_idx += 1

                # exit 판별
                lbl = (dst_sym or "").lower()
                if any(x in lbl for x in ("exit", "terminate", "abort")):
                    node.is_exit = True

                if stack:
                    node.parent_id = stack[-1]
                    if stack[-1] in nodes:
                        nodes[stack[-1]].children_ids.append(node_id)
                    edges.append(CallEdge(stack[-1], node_id, "call", tid))
                else:
                    node.is_entry = True

                nodes[node_id] = node
                stack.append(node_id)

            elif ev_type == "ret" and stack:
                ret_node_id = stack[-1]
                # ret 스냅샷 (순서 기반)
                if ret_idx < len(ret_snaps) and ret_node_id in nodes:
                    snap = ret_snaps[ret_idx]
                    nodes[ret_node_id].retval = snap.get("rax", "")
                    ret_idx += 1
                stack.pop()

        self._link_roots_by_time(nodes, edges, tid)
        return nodes, edges

    @staticmethod
    def _sync_label(ev: dict) -> str:
        kind = ev.get("kind", "sync")
        handle = ev.get("handle", "")
        msg_id = ev.get("msg_id", None)
        if msg_id is not None:
            return "{} msg={}".format(kind, msg_id)
        if handle:
            return "{} {}".format(kind, handle)
        return kind

    def _display_symbol(self, module: str, offset_hex: str) -> str:
        if not self._symbol_resolver:
            return ""
        try:
            return self._symbol_resolver(module, offset_hex) or ""
        except Exception:
            return ""

    @staticmethod
    def _link_roots_by_time(nodes: dict[str, CallNode],
                            edges: list[CallEdge], tid: int):
        roots = sorted(
            [n for n in nodes.values() if n.parent_id is None],
            key=lambda n: n.call_seq)
        for prev, cur in zip(roots, roots[1:]):
            edges.append(CallEdge(prev.node_id, cur.node_id, "flow", tid))

    @staticmethod
    def _hex(v) -> int:
        try:
            return int(str(v).strip(), 16)
        except Exception:
            return 0

    @staticmethod
    def _link_spawns(
        result: dict[int, tuple[dict, list]],
        spawn_by_child: dict[int, dict],
    ):
        for child_tid, spawn_ev in spawn_by_child.items():
            parent_tid = spawn_ev.get("parent_tid", -1)
            creator_va = spawn_ev.get("creator_va", "unknown")
            if parent_tid not in result or child_tid not in result:
                continue

            parent_nodes, parent_edges = result[parent_tid]
            child_nodes, _             = result[child_tid]

            # 부모: creator_va로 가장 가까운 노드 찾기
            creator_id: Optional[str] = None
            if creator_va != "unknown":
                try:
                    va_int = int(creator_va, 16)
                except Exception:
                    va_int = 0
                best_dist = float("inf")
                for nid, n in parent_nodes.items():
                    dist = abs(n.offset - va_int)
                    if dist < best_dist:
                        best_dist = dist
                        creator_id = nid

            # 자식: 루트 노드
            child_root_id: Optional[str] = None
            for nid, n in child_nodes.items():
                if n.is_entry:
                    child_root_id = nid
                    break

            if creator_id and child_root_id:
                parent_nodes[creator_id].spawn_tid = child_tid
                child_nodes[child_root_id].spawned_by_id = creator_id
                parent_edges.append(
                    CallEdge(creator_id, child_root_id, "spawn", parent_tid))


# ============================================================
# LayoutWorker (QThread)
# ============================================================

class LayoutWorker(QObject):
    layout_done = Signal(dict)  # {node_id: (x, y)}

    def __init__(self, nodes: dict[str, CallNode],
                 edges: list[CallEdge], visible: set[str]):
        super().__init__()
        self._nodes   = nodes
        self._edges   = edges
        self._visible = visible

    def run(self):
        self.layout_done.emit(self._compute())

    def _compute(self) -> dict[str, tuple[float, float]]:
        vis = {nid: n for nid, n in self._nodes.items()
               if nid in self._visible}
        if not vis:
            return {}

        positions: dict[str, tuple[float, float]] = {}
        row_h = max(self._node_h(), 260) + V_GAP
        col_w = NODE_W + H_GAP

        for idx, n in enumerate(sorted(vis.values(), key=lambda x: x.call_seq)):
            positions[n.node_id] = (n.depth * col_w, idx * row_h)

        return positions

    def _node_h(self) -> int:
        """NodeItem._calc_height()와 반드시 일치해야 함."""
        return PAD * 2 + LINE_H * 10


# ============================================================
# NodeItem
# ============================================================

class NodeItem(QGraphicsItem):

    Type = QGraphicsItem.UserType + 1

    # 노드 클릭 시 씬으로 알리기 위한 콜백 (씬에서 주입)
    on_selected_cb = None   # callable(node_id)
    on_toggle_cb   = None   # callable(node_id)

    def __init__(self, node: CallNode, nodes_ref: dict[str, CallNode]):
        super().__init__()
        self._node     = node
        self._nodes    = nodes_ref
        self._searched = False
        self._toggle_hotspots: list[tuple[QRectF, str]] = []
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setAcceptHoverEvents(True)
        self._h = self._calc_height()

    def type(self): return self.Type

    @property
    def node(self): return self._node

    def set_searched(self, v: bool):
        self._searched = v
        self.update()

    def _calc_height(self) -> int:
        """LayoutWorker._node_h()와 기준값 공유 (LINE_H * 10 최소)."""
        lines = 3  # 함수명 + 주소 + 구분선 여백
        n = self._node
        if n.args:
            lines += 5
        if n.retval:
            lines += 2
        vis_ch = [c for c in n.children_ids if c in self._nodes]
        if vis_ch:
            lines += min(len(vis_ch), 5) + 1
        if n.spawn_tid is not None:
            lines += 1
        return max(PAD * 2 + lines * LINE_H, PAD * 2 + LINE_H * 10)

    def boundingRect(self) -> QRectF:
        return QRectF(0, 0, NODE_W, self._h)

    def paint(self, painter: QPainter, option, widget=None):
        n = self._node
        w, h = NODE_W, self._h
        sel = self.isSelected()
        self._toggle_hotspots = []

        # 배경색
        if n.is_entry:  bg = C_NODE_ENTRY
        elif n.is_exit: bg = C_NODE_EXIT
        else:           bg = C_NODE_BG

        # 테두리
        if sel:              border, bw = C_NODE_SEL,    2
        elif self._searched: border, bw = C_NODE_SEARCH, 2
        else:                border, bw = C_NODE_BORDER, 1

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QBrush(bg))
        painter.setPen(QPen(border, bw))
        painter.drawRoundedRect(0, 0, w, h, 4, 4)

        y = PAD
        x = PAD

        # 함수명
        painter.setFont(FONT_MAIN)
        painter.setPen(QPen(C_TEXT_FUNC))
        lbl = n.label()
        if len(lbl) > 32: lbl = lbl[:29] + "…"
        painter.drawText(x, y + LINE_H - 2, lbl)
        y += LINE_H

        # 주소
        painter.setFont(FONT_ADDR)
        painter.setPen(QPen(C_TEXT_ADDR))
        painter.drawText(x, y + LINE_H - 2, n.addr_str())
        y += LINE_H

        # 구분선
        painter.setPen(QPen(QColor("#E2E8F0"), 1))
        painter.drawLine(PAD, y + 2, w - PAD, y + 2)
        y += 6

        # 인자
        if n.args:
            painter.setFont(FONT_SUB)
            painter.setPen(QPen(C_TEXT_SUB))
            painter.drawText(x, y + LINE_H - 2, "args:")
            y += LINE_H
            painter.setFont(FONT_ADDR)
            painter.setPen(QPen(C_TEXT_ARG))
            regs = ("arg0", "arg1", "arg2", "arg3")
            if n.args.get("arch") != "ia32":
                regs = ("rcx", "rdx", "r8", "r9")
            for idx, reg in enumerate(("rcx", "rdx", "r8", "r9")):
                val = n.args.get(reg, "")
                if val:
                    txt = "  {}={}".format(regs[idx], val[:20])
                    painter.drawText(x, y + LINE_H - 2, txt)
                    y += LINE_H

        # 반환값
        if n.retval:
            painter.setFont(FONT_SUB)
            painter.setPen(QPen(C_TEXT_SUB))
            painter.drawText(x, y + LINE_H - 2, "ret:")
            y += LINE_H
            painter.setFont(FONT_ADDR)
            painter.setPen(QPen(C_TEXT_RET))
            painter.drawText(x + 4, y + LINE_H - 2,
                             "  rax={}".format(n.retval[:24]))
            y += LINE_H

        # 하위 호출 목록 (1단계)
        vis_ch = [c for c in n.children_ids if c in self._nodes]
        if vis_ch:
            painter.setFont(FONT_SUB)
            painter.setPen(QPen(C_TEXT_SUB))
            state = "[펼침]" if n.expanded else "[+]"
            self._toggle_hotspots.append(
                (QRectF(x, y, w - PAD * 2, LINE_H), n.node_id))
            painter.drawText(x, y + LINE_H - 2,
                             "calls({}) {}".format(len(vis_ch), state))
            y += LINE_H
            shown = vis_ch[:5]
            painter.setFont(FONT_ADDR)
            for cid in shown:
                cn = self._nodes.get(cid)
                if not cn: continue
                arrow = "v" if cn.expanded else ">"
                painter.setPen(QPen(C_TEXT_SUB))
                painter.drawText(x + 6, y + LINE_H - 2, arrow)
                self._toggle_hotspots.append(
                    (QRectF(x + 2, y, w - PAD * 2 - 2, LINE_H), cid))
                painter.setPen(QPen(C_TEXT_FUNC if cn.symbol else C_TEXT_ADDR))
                cl = cn.label()
                if len(cl) > 30: cl = cl[:27] + "…"
                painter.drawText(x + 20, y + LINE_H - 2, cl)
                y += LINE_H
            if len(vis_ch) > 5:
                painter.setPen(QPen(C_TEXT_SUB))
                painter.drawText(x + 6, y + LINE_H - 2,
                                 "  … +{}".format(len(vis_ch) - 5))

        # spawn 링크
        if n.spawn_tid is not None:
            painter.setFont(FONT_SUB)
            painter.setPen(QPen(C_EDGE_SPAWN))
            painter.drawText(x, h - PAD - 2,
                             "→ Thread {}".format(n.spawn_tid))

    def mouseDoubleClickEvent(self, event):
        self._node.expanded = not self._node.expanded
        self.update()
        if self.on_toggle_cb:
            self.on_toggle_cb(self._node.node_id)

    def mousePressEvent(self, event):
        pos = event.position() if hasattr(event, "position") else event.pos()
        for rect, node_id in self._toggle_hotspots:
            if rect.contains(pos):
                target = self._nodes.get(node_id)
                if target:
                    target.expanded = not target.expanded
                    self.update()
                    if self.on_toggle_cb:
                        self.on_toggle_cb(target.node_id)
                    event.accept()
                    return
        super().mousePressEvent(event)
        if self.on_selected_cb:
            self.on_selected_cb(self._node.node_id)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionChange:
            scene = self.scene()
            if scene and hasattr(scene, "constrain_node_position"):
                return scene.constrain_node_position(self._node.node_id, value)
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            scene = self.scene()
            if scene and hasattr(scene, "edges_update"):
                scene.edges_update()
            if scene and hasattr(scene, "node_moved"):
                if not getattr(scene, "applying_positions", False):
                    scene.node_moved.emit(
                        self._node.node_id, self.pos().x(), self.pos().y())
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event):
        self.setToolTip("{}\nTID:{} depth:{} seq:{}".format(
            self._node.addr_str(), self._node.tid,
            self._node.depth, self._node.call_seq))
        super().hoverEnterEvent(event)


# ============================================================
# EdgeItem
# ============================================================

class EdgeItem(QGraphicsPathItem):

    def __init__(self, edge: CallEdge,
                 src: NodeItem, dst: NodeItem):
        super().__init__()
        self._edge = edge
        self._src  = src
        self._dst  = dst
        self._label = dst.node.label()
        self._label_pos = QPointF()
        self._label_rect = QRectF()
        color = {
            "call":  C_EDGE_CALL,
            "sync":  C_EDGE_SYNC,
            "spawn": C_EDGE_SPAWN,
            "flow":  C_EDGE_RET,
        }.get(edge.kind, C_EDGE_CALL)
        style = (Qt.PenStyle.DashLine
                 if edge.kind in ("spawn", "flow") else Qt.PenStyle.SolidLine)
        self.setPen(QPen(color, 1.5, style))
        self.setZValue(-1)
        self.refresh()

    def boundingRect(self) -> QRectF:
        return super().boundingRect().united(self._label_rect).adjusted(-4, -4, 4, 4)

    def paint(self, painter: QPainter, option, widget=None):
        super().paint(painter, option, widget)
        if self._edge.kind not in ("call", "sync"):
            return
        painter.setFont(FONT_SUB)
        painter.setPen(QPen(C_TEXT_SUB))
        painter.drawText(self._label_pos, self._label)

    def refresh(self):
        self.prepareGeometryChange()
        sr = self._src.boundingRect()
        dr = self._dst.boundingRect()
        sp = self._src.pos()
        dp = self._dst.pos()

        # 좌→우 호출 흐름. 부모의 자식 호출 순서별 고정 앵커에서 시작한다.
        sx = sp.x() + sr.width()
        sy = sp.y() + sr.height() / 2.0
        children = [
            cid for cid in self._src.node.children_ids
            if cid in self._src._nodes
        ]
        children.sort(key=lambda cid: self._src._nodes[cid].call_seq)
        if self._edge.dst_id in children:
            rank = children.index(self._edge.dst_id)
            spacing = max(12.0, (sr.height() - PAD * 2) / (len(children) + 1))
            sy = sp.y() + PAD + spacing * (rank + 1)
        dx = dp.x()
        dy = dp.y() + dr.height() / 2.0
        mid_x = (sx + dx) / 2.0

        path = QPainterPath()
        path.moveTo(sx, sy)
        path.cubicTo(mid_x, sy, mid_x, dy, dx, dy)

        # 화살촉 (도착 방향 기준)
        tang_x = dx - mid_x
        tang_y = dy - dy
        length = math.hypot(tang_x, tang_y)
        if length > 0:
            nx_ = tang_x / length
            ny_ = tang_y / length
        else:
            nx_, ny_ = 1.0, 0.0

        aw = ARROW_SZ
        lx = dx - aw * (nx_ * 0.5 + ny_ * 0.866)
        ly = dy - aw * (ny_ * 0.5 - nx_ * 0.866)
        rx = dx - aw * (nx_ * 0.5 - ny_ * 0.866)
        ry = dy - aw * (ny_ * 0.5 + nx_ * 0.866)

        path.moveTo(dx, dy)
        path.lineTo(lx, ly)
        path.moveTo(dx, dy)
        path.lineTo(rx, ry)

        label = self._dst.node.label()
        if len(label) > 26:
            label = label[:23] + "..."
        self._label = label
        fm = QFontMetrics(FONT_SUB)
        label_w = min(180, fm.horizontalAdvance(label))
        label_h = LINE_H
        self._label_pos = QPointF(sx - label_w - 6, sy + 4)
        self._label_rect = QRectF(
            self._label_pos.x(), self._label_pos.y() - label_h + 2,
            label_w + 4, label_h + 4)
        self.setPath(path)


# ============================================================
# GraphScene
# ============================================================

class GraphScene(QGraphicsScene):
    node_selected = Signal(str)  # node_id
    node_moved = Signal(str, float, float)

    def __init__(self):
        super().__init__()
        self.setBackgroundBrush(QBrush(C_BG))
        self._node_items: dict[str, NodeItem] = {}
        self._edge_items: list[EdgeItem]      = []
        self._nodes: dict[str, CallNode] = {}
        self.applying_positions = False

    def rebuild(self, nodes: dict[str, CallNode],
                edges: list[CallEdge], visible: set[str]):
        self.clear()
        self._node_items.clear()
        self._edge_items.clear()
        self._nodes = nodes

        for nid in visible:
            n = nodes[nid]
            item = NodeItem(n, nodes)
            item.on_selected_cb = self.node_selected.emit
            item.on_toggle_cb   = lambda nid_: self.node_selected.emit("__toggle__:" + nid_)
            self.addItem(item)
            self._node_items[nid] = item

        for edge in edges:
            if edge.src_id in self._node_items and edge.dst_id in self._node_items:
                ei = EdgeItem(edge,
                              self._node_items[edge.src_id],
                              self._node_items[edge.dst_id])
                self.addItem(ei)
                self._edge_items.append(ei)

    def apply_positions(self, positions: dict[str, tuple[float, float]]):
        self.applying_positions = True
        try:
            for nid, (x, y) in positions.items():
                if nid in self._node_items:
                    self._node_items[nid].setPos(x, y)
        finally:
            self.applying_positions = False
            self.edges_update()
            self.update()

    def constrain_node_position(self, node_id: str, value):
        if self.applying_positions or node_id not in self._node_items:
            return value
        p = QPointF(value)
        node = self._nodes.get(node_id)
        if not node:
            return p

        col_min = 0.0
        if node.parent_id and node.parent_id in self._node_items:
            parent = self._node_items[node.parent_id]
            col_min = parent.pos().x() + parent.boundingRect().width() + 40.0
        p.setX(max(p.x(), col_min))

        ordered = sorted(
            (it.node for it in self._node_items.values()),
            key=lambda n: n.call_seq)
        idx = next((i for i, n in enumerate(ordered) if n.node_id == node_id), -1)
        min_gap = 36.0
        if idx > 0:
            prev_item = self._node_items.get(ordered[idx - 1].node_id)
            if prev_item:
                p.setY(max(p.y(), prev_item.pos().y() + min_gap))
        if 0 <= idx < len(ordered) - 1:
            next_item = self._node_items.get(ordered[idx + 1].node_id)
            if next_item:
                p.setY(min(p.y(), next_item.pos().y() - min_gap))
        return p

    def edges_update(self):
        for ei in self._edge_items:
            ei.refresh()

    def highlight(self, node_ids: list[str]):
        for item in self._node_items.values():
            item.set_searched(False)
        for nid in node_ids:
            if nid in self._node_items:
                self._node_items[nid].set_searched(True)

    def focus_node(self, node_id: str) -> Optional[NodeItem]:
        item = self._node_items.get(node_id)
        if item:
            self.clearSelection()
            item.setSelected(True)
            self.node_selected.emit(node_id)
        return item


# ============================================================
# GraphView
# ============================================================

class GraphView(QGraphicsView):

    def __init__(self, scene: GraphScene):
        super().__init__(scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(
            QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(
            QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QBrush(C_BG))
        self._zoom = 1.0

    def wheelEvent(self, event: QWheelEvent):
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self._zoom = max(0.1, min(self._zoom * factor, 8.0))
        self.setTransform(self.transform().scale(factor, factor))

    def fit_all(self):
        br = self.scene().itemsBoundingRect()
        if not br.isEmpty():
            self.fitInView(br.adjusted(-20, -20, 20, 20),
                           Qt.AspectRatioMode.KeepAspectRatio)

    def focus_on(self, node_id: str):
        item = self.scene().focus_node(node_id)
        if item:
            self.centerOn(item)

    def reset_zoom(self):
        self.resetTransform()
        self._zoom = 1.0


# ============================================================
# SearchPanel
# ============================================================

class SearchPanel(QWidget):
    search_submitted = Signal(str)   # query
    goto_node        = Signal(str)   # node_id

    def __init__(self, parent=None):
        super().__init__(parent)
        ly = QHBoxLayout(self)
        ly.setContentsMargins(2, 2, 2, 2)
        ly.setSpacing(4)

        self._edit = QLineEdit()
        self._edit.setPlaceholderText("함수명 / 오프셋 검색…")
        self._edit.setFixedWidth(240)
        self._edit.setStyleSheet(
            "background:#FFFFFF;color:#1E293B;"
            "border:1px solid #C0C8D0;border-radius:3px;padding:2px 4px;")
        self._edit.returnPressed.connect(self._submit)
        ly.addWidget(self._edit)

        for label, slot in [("검색", self._submit),
                             ("◀",   self._prev),
                             ("▶",   self._next)]:
            b = QPushButton(label)
            b.setFixedWidth(42 if label == "검색" else 28)
            b.setStyleSheet(
                "background:#0078D4;color:white;"
                "border:none;border-radius:3px;padding:2px 6px;")
            b.clicked.connect(slot)
            ly.addWidget(b)

        self._info = QLabel("")
        self._info.setStyleSheet("color:#6B7280;font-size:11px;")
        ly.addWidget(self._info)
        ly.addStretch()

        self._results: list[str] = []
        self._idx = 0

    def set_results(self, ids: list[str]):
        self._results = ids
        self._idx     = 0
        self._info.setText("{} 결과".format(len(ids)) if ids else "없음")
        if ids:
            self.goto_node.emit(ids[0])

    def _submit(self):
        q = self._edit.text().strip()
        if q:
            self.search_submitted.emit(q)

    def _prev(self):
        if not self._results: return
        self._idx = (self._idx - 1) % len(self._results)
        self.goto_node.emit(self._results[self._idx])

    def _next(self):
        if not self._results: return
        self._idx = (self._idx + 1) % len(self._results)
        self.goto_node.emit(self._results[self._idx])


# ============================================================
# CallGraphPanel  ← MainWindow에서 사용
# ============================================================

class CallGraphPanel(QWidget):
    # Ghidra sync 요청: (module, hex_offset)
    sync_requested = Signal(str, str)
    symbol_refresh_requested = Signal()
    annotate_requested = Signal()
    xref_requested = Signal()
    symbol_modules_requested = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._session_data: dict[int, tuple[dict, list]] = {}
        self._current_tid:  Optional[int] = None
        self._views:        dict[int, tuple[GraphScene, GraphView]] = {}
        self._layout_thread: Optional[QThread] = None
        self._symbol_resolver = None
        self._manual_positions: dict[int, dict[str, tuple[float, float]]] = {}
        self._laid_out_tids: set[int] = set()
        self._pending_focus: dict[int, str] = {}

        ly = QVBoxLayout(self)
        ly.setContentsMargins(0, 0, 0, 0)
        ly.setSpacing(0)

        # 툴바
        tb = QWidget()
        tb.setStyleSheet("background:#EEF2F7;border-bottom:1px solid #D1D9E0;")
        tb_ly = QHBoxLayout(tb)
        tb_ly.setContentsMargins(4, 3, 4, 3)
        tb_ly.setSpacing(6)

        self._search = SearchPanel()
        self._search.search_submitted.connect(self._on_search)
        self._search.goto_node.connect(self._on_goto)
        tb_ly.addWidget(self._search)

        for label, slot, width in [
            ("이름 갱신", self.symbol_refresh_requested.emit, 72),
            ("주석 적용", self.annotate_requested.emit, 72),
            ("XRef 추가", self.xref_requested.emit, 72),
            ("전체보기", self._fit_all, 56),
            ("1:1", self._reset_zoom, 32),
        ]:
            b = QPushButton(label)
            b.setFixedWidth(width)
            b.setStyleSheet(
                "background:#FFFFFF;color:#1E293B;"
                "border:1px solid #C0C8D0;border-radius:3px;padding:2px 6px;")
            b.clicked.connect(slot)
            tb_ly.addWidget(b)

        ly.addWidget(tb)

        # 스레드 탭
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet("""
            QTabWidget::pane{border:1px solid #D1D9E0;background:#F5F5F5;}
            QTabBar::tab{background:#EEF2F7;color:#6B7280;
                         padding:5px 14px;border:1px solid #D1D9E0;
                         border-bottom:none;margin-right:2px;border-radius:3px 3px 0 0;}
            QTabBar::tab:selected{background:#FFFFFF;color:#1E293B;
                                  font-weight:bold;border-bottom:2px solid #0078D4;}
            QTabBar::tab:hover{background:#DBEAFE;color:#1E293B;}
        """)
        self._tabs.currentChanged.connect(self._on_tab_changed)
        ly.addWidget(self._tabs, 1)

        # 플레이스홀더
        self._placeholder = QLabel(
            "트레이스 완료 후 그래프가 표시됩니다.\n"
            "더블클릭: 펼치기/접기  |  휠: 줌  |  드래그: 이동")
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._placeholder.setStyleSheet("color:#9CA3AF;font-size:13px;")
        ly.addWidget(self._placeholder)
        self._tabs.hide()

    # ── 공개 API ────────────────────────────────────────────

    def load_session(self, session):
        """TraceSession 수신 시 호출."""
        self._placeholder.hide()
        self._tabs.show()

        builder = CallTreeBuilder(self._symbol_resolver)
        self._session_data = builder.build(session)
        self._manual_positions = {}
        self._laid_out_tids = set()
        self._apply_initial_expansion()

        self._tabs.clear()
        self._views.clear()

        for tid in sorted(self._session_data.keys()):
            self._add_tab(tid)

        if self._session_data:
            main_tid = sorted(self._session_data.keys())[0]
            self._current_tid = main_tid
            self._relayout(main_tid)

    def _apply_initial_expansion(self):
        tids = sorted(self._session_data.keys())
        if not tids:
            return
        main_tid = tids[0]
        for tid, (nodes, _) in self._session_data.items():
            for n in nodes.values():
                n.expanded = False

            terminal = self._terminal_node(nodes)
            if tid == main_tid or (terminal and terminal.is_exit):
                if terminal:
                    self._expand_to(nodes, terminal.node_id)

    def _terminal_node(self, nodes: dict[str, CallNode]) -> Optional[CallNode]:
        if not nodes:
            return None
        exits = [n for n in nodes.values() if n.is_exit]
        if exits:
            return max(exits, key=lambda n: n.call_seq)
        return max(nodes.values(), key=lambda n: n.call_seq)

    def sync_from_ghidra(self, module: str, offset_hex: str):
        """Ghidra sync → 해당 노드 선택."""
        try:
            offset = int(offset_hex, 16)
        except Exception:
            return
        for tid, (nodes, _) in self._session_data.items():
            for nid, n in nodes.items():
                if n.module.lower() == module.lower() and n.offset == offset:
                    self._switch_to_tid(tid)
                    if tid in self._views:
                        _, view = self._views[tid]
                        view.focus_on(nid)
                    return

    def goto_node_token(self, token: str):
        self._on_goto(token)

    def function_entries(self) -> list[dict]:
        counts: dict[tuple[str, int], int] = {}
        entries: list[dict] = []
        for tid, (nodes, _) in self._session_data.items():
            for nid, n in nodes.items():
                if n.module.startswith("[") or n.module == "unknown":
                    continue
                key = (n.module.lower(), n.offset)
                counts[key] = counts.get(key, 0) + 1
                entries.append({
                    "module": n.module,
                    "offset": hex(n.offset),
                    "tid": tid,
                    "node_id": nid,
                    "call_seq": n.call_seq,
                    "trace_seq": n.trace_seq,
                    "fallback": n.symbol,
                    "key": key,
                })
        for entry in entries:
            entry["count"] = counts.get(entry["key"], 1)
        entries.sort(key=lambda e: (e["trace_seq"], e["tid"], e["call_seq"]))
        return entries

    def set_symbol_resolver(self, resolver):
        self._symbol_resolver = resolver

    # ── 탭 ──────────────────────────────────────────────────

    def _add_tab(self, tid: int):
        scene = GraphScene()
        view  = GraphView(scene)
        scene.node_selected.connect(
            lambda nid, t=tid: self._on_node_signal(t, nid))
        scene.node_moved.connect(
            lambda nid, x, y, t=tid: self._remember_position(t, nid, x, y))
        self._views[tid] = (scene, view)
        tids   = sorted(self._session_data.keys())
        suffix = " (main)" if tid == tids[0] else ""
        self._tabs.addTab(view, "Thread {}{}".format(tid, suffix))

    def _switch_to_tid(self, tid: int):
        tids = sorted(self._session_data.keys())
        if tid in tids:
            self._tabs.setCurrentIndex(tids.index(tid))

    # ── 레이아웃 ────────────────────────────────────────────

    def _relayout(self, tid: int):
        if tid not in self._session_data or tid not in self._views:
            return
        nodes, edges = self._session_data[tid]
        scene, view  = self._views[tid]

        visible = self._visible_nodes(nodes)
        scene.rebuild(nodes, edges, visible)

        # 워커 스레드
        if self._layout_thread and self._layout_thread.isRunning():
            self._layout_thread.quit()
            self._layout_thread.wait()

        worker = LayoutWorker(nodes, edges, visible)
        thread = QThread()
        worker.moveToThread(thread)
        worker.layout_done.connect(
            lambda pos, s=scene, v=view: self._apply(s, v, pos))
        thread.started.connect(worker.run)
        self._layout_thread = thread
        thread.start()

    def _apply(self, scene: GraphScene, view: GraphView,
               pos: dict[str, tuple[float, float]]):
        tid = None
        for t, (s, _) in self._views.items():
            if s is scene:
                tid = t
                break
        if tid is not None:
            saved = self._manual_positions.get(tid, {})
            for nid, saved_pos in saved.items():
                if nid in pos:
                    pos[nid] = saved_pos
        scene.apply_positions(pos)
        if tid is None or tid not in self._laid_out_tids:
            view.fit_all()
            if tid is not None:
                self._laid_out_tids.add(tid)
        if tid is not None and tid in self._pending_focus:
            view.focus_on(self._pending_focus.pop(tid))
        if self._layout_thread:
            self._layout_thread.quit()

    def _remember_position(self, tid: int, node_id: str, x: float, y: float):
        self._manual_positions.setdefault(tid, {})[node_id] = (x, y)

    def _visible_nodes(self, nodes: dict[str, CallNode]) -> set[str]:
        visible: set[str] = set()
        for n in nodes.values():
            if n.parent_id is None:
                visible.add(n.node_id)
                if n.expanded:
                    self._collect(n, nodes, visible)
        return visible

    def _collect(self, node: CallNode,
                 nodes: dict[str, CallNode], visible: set[str]):
        for cid in node.children_ids:
            if cid not in nodes:
                continue
            visible.add(cid)
            if nodes[cid].expanded:
                self._collect(nodes[cid], nodes, visible)

    # ── 이벤트 핸들러 ────────────────────────────────────────

    def _on_tab_changed(self, idx: int):
        if idx < 0:
            return
        tids = sorted(self._session_data.keys())
        if idx < len(tids):
            self._current_tid = tids[idx]
            self._relayout(self._current_tid)

    def _on_node_signal(self, tid: int, signal: str):
        """씬에서 오는 node_selected 시그널 처리."""
        if signal.startswith("__toggle__:"):
            node_id = signal[len("__toggle__:"):]
            # expanded는 NodeItem.mouseDoubleClickEvent에서 이미 토글됨
            nodes, _ = self._session_data.get(tid, ({}, []))
            mods = self._modules_around(nodes, node_id)
            if mods:
                self.symbol_modules_requested.emit(mods)
            self._relayout(tid)
        else:
            # 선택 → Ghidra sync
            nodes, _ = self._session_data.get(tid, ({}, []))
            n = nodes.get(signal)
            if n and not n.module.startswith("["):
                self.sync_requested.emit(n.module, hex(n.offset))

    def visible_modules(self) -> list[str]:
        mods: set[str] = set()
        for tid, (nodes, _) in self._session_data.items():
            visible = self._visible_nodes(nodes)
            for nid in visible:
                n = nodes.get(nid)
                if n and n.module and not n.module.startswith("["):
                    mods.add(n.module)
        return sorted(mods)

    def _modules_around(self, nodes: dict[str, CallNode],
                        node_id: str) -> list[str]:
        n = nodes.get(node_id)
        if not n:
            return []
        mods = {n.module}
        for cid in n.children_ids:
            ch = nodes.get(cid)
            if ch:
                mods.add(ch.module)
        return sorted(m for m in mods if m and not m.startswith("["))

    def _on_search(self, query: str):
        if not self._session_data:
            return
        q = query.lower()
        results: list[str] = []
        for tid, (nodes, _) in self._session_data.items():
            for nid, n in nodes.items():
                hay = " ".join([
                    n.label(), n.addr_str(), n.module,
                    hex(n.offset), "{}+{}".format(n.module, hex(n.offset)),
                    "{}!{}".format(n.module, hex(n.offset)),
                ]).lower()
                if q in hay:
                    results.append("{}|{}".format(tid, nid))

        for token in results:
            t_s, nid = token.split("|", 1)
            t = int(t_s)
            nodes, _ = self._session_data[t]
            self._expand_to(nodes, nid)

        if self._current_tid in self._session_data:
            self._relayout(self._current_tid)
        self._search.set_results(results)

    def _expand_to(self, nodes: dict[str, CallNode], node_id: str):
        cur = nodes.get(node_id)
        while cur and cur.parent_id:
            p = nodes.get(cur.parent_id)
            if p:
                p.expanded = True
            cur = p

    def _on_goto(self, node_id: str):
        tid = self._current_tid
        if "|" in node_id:
            t_s, node_id = node_id.split("|", 1)
            tid = int(t_s)
            nodes, _ = self._session_data.get(tid, ({}, []))
            self._expand_to(nodes, node_id)
            self._pending_focus[tid] = node_id
            self._switch_to_tid(tid)
            self._relayout(tid)
        if tid in self._views:
            _, view = self._views[tid]
            view.focus_on(node_id)

    def _fit_all(self):
        if self._current_tid in self._views:
            _, view = self._views[self._current_tid]
            view.fit_all()

    def _reset_zoom(self):
        if self._current_tid in self._views:
            _, view = self._views[self._current_tid]
            view.reset_zoom()


# ============================================================
# ModuleTimeline – raw VA → (module, offset)
# ============================================================

class _ModSnap:
    __slots__ = ("seq", "action", "name", "base", "size")
    def __init__(self, seq, action, name, base, size):
        self.seq = seq; self.action = action; self.name = name
        self.base = base; self.size = size


class ModuleTimeline:
    def __init__(self, mod_events: list[dict]):
        self._evs = sorted(
            [_ModSnap(e["seq"], e["action"], e["name"],
                      int(e["base"], 16), e["size"])
             for e in mod_events],
            key=lambda x: x.seq)
        self._seqs = [e.seq for e in self._evs]

    def resolve(self, va: int, seq: int) -> tuple[str, int]:
        idx = bisect.bisect_right(self._seqs, seq) - 1
        active: dict[str, _ModSnap] = {}
        for i in range(idx + 1):
            ev = self._evs[i]
            k  = ev.name.lower()
            if ev.action == "load": active[k] = ev
            else:                   active.pop(k, None)
        for snap in active.values():
            if snap.base <= va < snap.base + snap.size:
                return (snap.name, va - snap.base)
        return ("unknown", va)


def postprocess(raw_events: list[dict],
                mod_events: list[dict]) -> list[dict]:
    """raw VA → (module, offset). 호출 스택 복원을 위해 반복 이벤트를 보존한다."""
    tl   = ModuleTimeline(mod_events)
    out:  list[dict] = []
    for ev in raw_events:
        seq    = ev["seq"]
        src_va = int(ev["src"], 16)
        dst_va = int(ev["dst"], 16)
        kind   = "call" if ev["k"] == 0 else "ret"
        tid    = ev["tid"]
        sm, so = tl.resolve(src_va, seq)
        dm, do = tl.resolve(dst_va, seq)
        if sm == "unknown" and ev.get("src_module"):
            sm = ev.get("src_module", sm)
            so = CallTreeBuilder._hex(ev.get("src_offset", hex(so)))
        if dm == "unknown" and ev.get("dst_module"):
            dm = ev.get("dst_module", dm)
            do = CallTreeBuilder._hex(ev.get("dst_offset", hex(do)))
        out.append({"src_module": sm, "src_offset": hex(so),
                    "dst_module": dm, "dst_offset": hex(do),
                    "src_symbol": ev.get("src_symbol", ""),
                    "dst_symbol": ev.get("dst_symbol", ""),
                    "type": kind, "thread_id": tid, "seq": seq})
    return out


def read_pe_machine(path: str) -> Optional[int]:
    try:
        dbg("PE check: {}".format(path))
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                dbg("PE check failed: missing MZ")
                return None
            f.seek(0x3C)
            pe_off = int.from_bytes(f.read(4), "little")
            f.seek(pe_off)
            if f.read(4) != b"PE\0\0":
                dbg("PE check failed: missing PE signature")
                return None
            machine = int.from_bytes(f.read(2), "little")
            dbg("PE machine: {} ({})".format(hex(machine), pe_machine_name(machine)))
            return machine
    except Exception as e:
        dbg("PE check exception: {}".format(e))
        return None


def pe_machine_name(machine: Optional[int]) -> str:
    names = {
        PE_MACHINE_I386: "x86",
        PE_MACHINE_AMD64: "x64",
        PE_MACHINE_ARM64: "arm64",
    }
    return names.get(machine, "unknown")


class _ThreadEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


def enumerate_process_threads(pid: int) -> list[int]:
    if os.name != "nt":
        dbg("thread snapshot skipped: os.name={}".format(os.name))
        return []
    dbg("thread snapshot begin: pid={}".format(pid))
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        dbg("thread snapshot failed: pid={}".format(pid))
        return []
    tids: list[int] = []
    entry = _ThreadEntry32()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        ok = kernel32.Thread32First(snapshot, ctypes.byref(entry))
        while ok:
            if entry.th32OwnerProcessID == pid:
                tids.append(int(entry.th32ThreadID))
            ok = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    dbg("thread snapshot result: pid={} tids={}".format(pid, tids))
    return tids


# ============================================================
# TraceSession
# ============================================================

class TraceSession:
    def __init__(self):
        self.session_id    = str(uuid.uuid4())
        self.events:       list[dict] = []
        self.raw_events:   list[dict] = []
        self.snapshots:    list[dict] = []
        self.mod_events:   list[dict] = []
        self.sync_events:  list[dict] = []
        self.spawn_events: list[dict] = []
        self.modules:      list[str]  = []
        self.reason = ""
        self.saved  = False
        self.graph: nx.DiGraph = nx.DiGraph()

    def is_empty(self) -> bool:
        return len(self.raw_events) == 0

    def build_graph(self):
        self.graph.clear()
        for ev in self.events:
            if ev.get("type") != "call": continue
            s = "{}+{}".format(ev["src_module"], ev["src_offset"])
            d = "{}+{}".format(ev["dst_module"], ev["dst_offset"])
            self.graph.add_edge(s, d, tid=ev.get("thread_id", 0))

    def to_dict(self) -> dict:
        return {
            "session_id":   self.session_id,
            "events":       [self._event_for_save(e) for e in self.events],
            "raw_events":   self.raw_events,
            "snapshots":    self.snapshots,
            "mod_events":   self.mod_events,
            "sync_events":  self.sync_events,
            "spawn_events": self.spawn_events,
            "modules":      self.modules,
            "reason":       self.reason,
        }

    @staticmethod
    def from_dict(d: dict) -> "TraceSession":
        s = TraceSession()
        s.session_id   = d.get("session_id", str(uuid.uuid4()))
        s.events       = [TraceSession._event_for_save(e)
                          for e in d.get("events", [])]
        s.raw_events   = d.get("raw_events", [])
        s.snapshots    = d.get("snapshots", [])
        s.mod_events   = d.get("mod_events", [])
        s.sync_events  = d.get("sync_events", [])
        s.spawn_events = d.get("spawn_events", [])
        s.modules      = d.get("modules", [])
        s.reason       = d.get("reason", "loaded")
        s.saved        = True
        s.build_graph()
        return s

    @staticmethod
    def _event_for_save(ev: dict) -> dict:
        out = dict(ev)
        out.pop("src_symbol", None)
        out.pop("dst_symbol", None)
        return out


# ============================================================
# Frida 워커
# ============================================================

class FridaWorker(QObject):
    status_changed = Signal(str)
    trace_complete = Signal(TraceSession)
    error_occurred = Signal(str)
    finished = Signal()

    def __init__(self, target_path: str, project_files: list[str]):
        super().__init__()
        self._target        = target_path
        self._project_files = project_files
        self._session       = None
        self._script        = None
        self._pid           = None
        self._done          = False
        self._stopping      = False
        self._finished      = False
        self._detached      = False
        self._trace_done_event = threading.Event()
        self._chunk_lock    = threading.Lock()
        self._chunk_events: list[dict] = []
        self._chunk_snapshots: list[dict] = []
        self._chunk_mod_events: list[dict] = []
        self._chunk_sync_events: list[dict] = []
        self._chunk_spawn_events: list[dict] = []
        self._session_id: Optional[str] = None

    def start_trace(self):
        dbg("start_trace requested: target={}".format(self._target))
        machine = read_pe_machine(self._target)
        if machine not in (PE_MACHINE_AMD64, PE_MACHINE_I386):
            dbg("start_trace rejected: machine={}".format(pe_machine_name(machine)))
            self.error_occurred.emit(
                "지원하지 않는 대상 아키텍처입니다: {}. "
                "이 도구는 Windows x64 또는 WoW64 x86 PE를 추적합니다.".format(
                    pe_machine_name(machine)))
            self._finish()
            return
        try:
            src = AGENT_JS_PATH.read_text(encoding="utf-8")
            dbg("agent loaded from disk: {} bytes={}".format(
                AGENT_JS_PATH, len(src)))
        except FileNotFoundError:
            dbg("agent missing: {}".format(AGENT_JS_PATH))
            self.error_occurred.emit("agent.js 없음: frida-compile agent.ts -o agent.js")
            self._finish()
            return
        try:
            resumed = False
            dbg("frida.spawn begin")
            self._pid     = frida.spawn(self._target)
            dbg("frida.spawn ok: pid={}".format(self._pid))
            initial_tids  = enumerate_process_threads(self._pid)
            dbg("frida.attach begin: pid={}".format(self._pid))
            self._session = frida.attach(self._pid)
            self._session.on("detached", self._on_detached)
            dbg("frida.attach ok: pid={}".format(self._pid))
            self._script  = self._session.create_script(src)
            self._script.on("message", self._on_msg)
            dbg("script.load begin")
            self._script.load()
            dbg("script.load ok")
            if self._project_files:
                dbg("set_targets begin: count={}".format(len(self._project_files)))
                self._script.exports_sync.set_targets(self._project_files)
                dbg("set_targets ok")
            dbg("start_trace rpc begin before resume: tids={}".format(initial_tids))
            self._script.exports_sync.start_trace(initial_tids)
            dbg("start_trace rpc ok before resume")
            dbg("frida.resume begin: pid={}".format(self._pid))
            frida.resume(self._pid)
            resumed = True
            dbg("frida.resume ok: pid={}".format(self._pid))
            self.status_changed.emit(
                "트레이스 시작: {}  arch:{}  tids:{}".format(
                    self._target, pe_machine_name(machine),
                    ",".join(str(t) for t in initial_tids)))
        except Exception as e:
            dbg("start_trace exception: {!r}".format(e))
            self.error_occurred.emit("Frida: {}".format(e))
            if resumed:
                self.status_changed.emit(
                    "트레이스 초기화 실패 - 대상 프로세스는 계속 실행 중")
                self._pid = None
            else:
                self._kill_spawned()
            self._cleanup()
            self._finish()

    def stop_trace(self):
        dbg("stop_trace requested")
        if self._stopping:
            dbg("stop_trace ignored: already stopping")
            return
        self._stopping = True
        self.status_changed.emit("트레이스 강제 종료 요청")

        if self._script and not self._done:
            done = threading.Event()
            errors: list[Exception] = []

            def request_stop():
                try:
                    dbg("stop_trace rpc begin")
                    self._script.exports_sync.stop_trace()
                    dbg("stop_trace rpc ok")
                except Exception as e:
                    dbg("stop_trace rpc exception: {!r}".format(e))
                    errors.append(e)
                finally:
                    done.set()

            t = threading.Thread(
                target=request_stop, name="FridaStopTrace", daemon=True)
            t.start()
            done.wait(timeout=1.5)
            if not done.is_set():
                dbg("stop_trace rpc timeout")
                self.status_changed.emit("stop RPC 지연 - 대상 프로세스 kill")
            elif errors and not self._done:
                self.status_changed.emit("stop: {}".format(errors[0]))
            else:
                dbg("waiting trace_complete after stop rpc")
                if self._trace_done_event.wait(timeout=1.0):
                    dbg("trace_complete received after stop rpc")
                else:
                    dbg("trace_complete wait timeout after stop rpc")

        self._kill_spawned()
        if not self._done:
            self._cleanup()
            self._finish()

    def _on_msg(self, message: dict, _data):
        dbg("frida message: {}".format(message))
        if message.get("type") == "error":
            msg = message.get("description", "unknown")
            if self._stopping:
                self.status_changed.emit("Frida: {}".format(msg))
            else:
                self.error_occurred.emit(msg)
                self._kill_spawned()
                self._cleanup()
                self._finish()
            return
        if message.get("type") != "send":
            return
        pl = message.get("payload", {})
        mt = pl.get("type", "")

        if mt == "status":
            self.status_changed.emit(pl.get("text", ""))
        elif mt == "trace_chunk":
            self._append_trace_payload(pl)
            self.status_changed.emit(
                "trace chunk raw:{} mod:{} sync:{}".format(
                    len(pl.get("events", [])),
                    len(pl.get("mod_events", [])),
                    len(pl.get("sync_events", []))))

        elif mt == "trace_complete":
            self._append_trace_payload(pl)
            self._done = True
            self._trace_done_event.set()
            sess = self._build_session(pl.get("reason", "exit"))

            self.trace_complete.emit(sess)
            self.status_changed.emit(
                "완료 raw:{} → dedup:{}".format(
                    len(sess.raw_events), len(sess.events)))
            self._cleanup()
            self._finish()

    def _on_detached(self, *args):
        dbg("frida detached: {}".format(args))
        self._detached = True
        if self._done or self._finished:
            return
        self.status_changed.emit("대상 프로세스 종료 감지")
        self._pid = None
        if self._chunk_events or self._chunk_mod_events:
            dbg("finalize from cached chunks after detach")
            self._done = True
            self._trace_done_event.set()
            self.trace_complete.emit(self._build_session("detached"))
        self._cleanup()
        self._finish()

    def _append_trace_payload(self, pl: dict):
        with self._chunk_lock:
            self._session_id = pl.get("session_id", self._session_id)
            self._chunk_events.extend(pl.get("events", []))
            self._chunk_snapshots.extend(pl.get("snapshots", []))
            self._chunk_mod_events.extend(pl.get("mod_events", []))
            self._chunk_sync_events.extend(pl.get("sync_events", []))
            self._chunk_spawn_events.extend(pl.get("spawn_events", []))
            dbg("chunk cache totals raw:{} mod:{} sync:{} spawn:{}".format(
                len(self._chunk_events),
                len(self._chunk_mod_events),
                len(self._chunk_sync_events),
                len(self._chunk_spawn_events)))

    def _build_session(self, reason: str) -> TraceSession:
        with self._chunk_lock:
            raw = list(self._chunk_events)
            snapshots = list(self._chunk_snapshots)
            mods = list(self._chunk_mod_events)
            sync_events = list(self._chunk_sync_events)
            spawn_events = list(self._chunk_spawn_events)
            session_id = self._session_id

        evs = postprocess(raw, mods)
        names = sorted({e["name"] for e in mods if e["action"] == "load"})

        sess = TraceSession()
        if session_id:
            sess.session_id = session_id
        sess.raw_events = raw
        sess.events = evs
        sess.snapshots = snapshots
        sess.mod_events = mods
        sess.sync_events = sync_events
        sess.spawn_events = spawn_events
        sess.modules = names
        sess.reason = reason
        sess.build_graph()
        return sess

    def _cleanup(self):
        dbg("cleanup begin")
        for obj, m in [(self._script, "unload"), (self._session, "detach")]:
            if m == "detach" and self._detached:
                dbg("cleanup detach skipped: already detached")
                continue
            if obj:
                try:
                    dbg("cleanup {} begin".format(m))
                    getattr(obj, m)()
                    dbg("cleanup {} ok".format(m))
                except Exception as e:
                    dbg("cleanup {} exception: {!r}".format(m, e))
        self._script = self._session = None
        dbg("cleanup end")

    def _kill_spawned(self):
        if self._pid is None:
            dbg("kill skipped: no pid")
            return
        try:
            dbg("frida.kill begin: pid={}".format(self._pid))
            frida.kill(self._pid)
            dbg("frida.kill ok: pid={}".format(self._pid))
            self.status_changed.emit("대상 프로세스 종료: pid={}".format(self._pid))
        except Exception as e:
            dbg("frida.kill exception: {!r}".format(e))
        finally:
            self._pid = None

    def _finish(self):
        if self._finished:
            return
        dbg("worker finished")
        self._finished = True
        self.finished.emit()


# ============================================================
# Ghidra Script TCP 서버
# ============================================================

class GhidraServerWorker(QObject):
    status_changed    = Signal(str)
    ghidra_connected  = Signal(bool)
    project_info_recv = Signal(list)      # 파일 목록
    sync_recv         = Signal(str, str)  # (module, offset_hex) Ghidra→클라이언트

    def __init__(self):
        super().__init__()
        self._conn:    Optional[socket.socket] = None
        self._lock     = threading.Lock()
        self._pending: Optional[TraceSession]  = None
        self._running  = False
        self._project_files: set[str] = set()
        self._symbol_cache: dict[str, list[dict]] = {}

        # RPC 요청-응답: req_id → (threading.Event, result_list)
        self._rpc: dict[str, tuple[threading.Event, list]] = {}
        self._rpc_lock = threading.Lock()

    def run_server(self):
        self._running = True
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((GHIDRA_SERVER_HOST, GHIDRA_SERVER_PORT))
        srv.listen(5)
        srv.settimeout(1.0)
        self.status_changed.emit(
            "Ghidra 서버 대기: {}:{}".format(GHIDRA_SERVER_HOST, GHIDRA_SERVER_PORT))
        while self._running:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            threading.Thread(
                target=self._handle, args=(conn, addr), daemon=True).start()
        srv.close()

    def _handle(self, conn: socket.socket, addr):
        buf = ""
        try:
            # 첫 메시지: connect
            while "\n" not in buf:
                c = conn.recv(4096)
                if not c: return
                buf += c.decode("utf-8", errors="replace")
            line, buf = buf.split("\n", 1)
            msg = json.loads(line.strip())
            if not (msg.get("type") == "connect" and msg.get("client") == "ghidra"):
                return

            self._send(conn, {"type": "connect_ack", "status": "ok",
                               "message": "Registered."})
            with self._lock: self._conn = conn
            self.ghidra_connected.emit(True)
            self.status_changed.emit("Ghidra 연결: {}".format(addr))

            for line in self._lines(conn, buf):
                try: m = json.loads(line)
                except: continue
                t = m.get("type", "")

                if t == "project_info":
                    files = m.get("files", [])
                    self._project_files = {f.lower() for f in files}
                    self.status_changed.emit(
                        "project_info: {}개".format(len(files)))
                    self.project_info_recv.emit(files)

                elif t == "annotate_result":
                    self.status_changed.emit(
                        "주석 완료 적용:{} 스킵:{}".format(
                            m.get("applied", 0), m.get("skipped", 0)))

                elif t == "xref_result":
                    self.status_changed.emit(
                        "XRef 완료 적용:{} 스킵:{}".format(
                            m.get("applied", 0), m.get("skipped", 0)))

                elif t == "rpc_response":
                    req_id = m.get("req_id", "")
                    with self._rpc_lock:
                        entry = self._rpc.pop(req_id, None)
                    if entry:
                        entry[1].append(m)
                        entry[0].set()

                elif t == "sync":
                    self.sync_recv.emit(
                        m.get("module", ""), m.get("offset", "0x0"))

                elif t == "disconnect":
                    self.status_changed.emit("Ghidra disconnect")
                    break

        except Exception as e:
            self.status_changed.emit("Ghidra 오류: {}".format(e))
        finally:
            try: self._send(conn, {"type": "disconnect", "client": "server"})
            except: pass
            try: conn.close()
            except: pass
            with self._lock: self._conn = None
            self.ghidra_connected.emit(False)
            self.status_changed.emit("Ghidra 연결 해제")

    # ── 세션 전송 ────────────────────────────────────────────

    def send_annotations(self, session: TraceSession):
        with self._lock: conn = self._conn
        if conn:
            self._do_send_annotations(conn, session)
        else:
            self.status_changed.emit("Ghidra 미연결 - 주석 적용 불가")

    def send_xrefs(self, session: TraceSession):
        with self._lock: conn = self._conn
        if conn:
            evs = self._events_for_ghidra(session)
            self._send(conn, {
                "type": "xref", "client": "frida",
                "session_id": session.session_id, "reason": session.reason,
                "events": evs,
            })
            self.status_changed.emit(
                "Ghidra XRef 추가 요청: {} call".format(len(evs)))
        else:
            self.status_changed.emit("Ghidra 미연결 - XRef 추가 불가")

    def is_connected(self) -> bool:
        with self._lock:
            return self._conn is not None

    def _do_send_annotations(self, conn: socket.socket, session: TraceSession):
        evs = self._events_for_ghidra(session)
        self._send(conn, {
            "type": "annotate", "client": "frida",
            "session_id": session.session_id, "reason": session.reason,
            "events": evs,
        })
        self.status_changed.emit(
            "Ghidra 주석 적용 요청: {} call (전체 {} 중)".format(
                len(evs),
                len([e for e in session.events if e.get("type") == "call"])))

    def _events_for_ghidra(self, session: TraceSession) -> list[dict]:
        pf = self._project_files

        def in_proj(mod: str) -> bool:
            nl = mod.lower()
            st = nl.rsplit(".", 1)[0]
            return nl in pf or any(st == f.rsplit(".", 1)[0] for f in pf)

        if pf:
            evs = [e for e in session.events
                   if e.get("type") == "call"
                   and (in_proj(e.get("src_module", ""))
                        or in_proj(e.get("dst_module", "")))]
        else:
            evs = [e for e in session.events if e.get("type") == "call"]

        out: list[dict] = []
        for ev in evs:
            item = dict(ev)
            for prefix in ("src", "dst"):
                sym = self.resolve_symbol(
                    item.get("{}_module".format(prefix), ""),
                    item.get("{}_offset".format(prefix), "0x0"))
                if sym:
                    item["{}_symbol".format(prefix)] = sym
            out.append(item)
        return out

    def refresh_symbols_for_session(self, session: TraceSession,
                                    refresh: bool = False) -> int:
        loaded = 0
        modules = sorted({
            e.get(k, "")
            for e in session.events
            for k in ("src_module", "dst_module")
            if e.get(k, "") and e.get(k, "") != "unknown"
        })
        for mod in modules:
            if not self._module_in_project(mod):
                continue
            if self._symbols_for_module(mod, refresh):
                loaded += 1
        return loaded

    def _module_key(self, mod: str) -> str:
        return mod.lower().rsplit(".", 1)[0]

    def _module_in_project(self, mod: str) -> bool:
        if not self._project_files:
            return True
        nl = mod.lower()
        st = self._module_key(mod)
        return nl in self._project_files or any(
            st == f.rsplit(".", 1)[0] for f in self._project_files)

    def _symbols_for_module(self, mod: str, refresh: bool) -> list[dict]:
        key = self._module_key(mod)
        if not refresh and key in self._symbol_cache:
            return self._symbol_cache[key]
        rsp = self.ghidra_rpc("symbols", {"module": mod}, timeout=20.0)
        symbols: list[dict] = []
        if rsp and rsp.get("ok"):
            result = rsp.get("result", {})
            symbols = result.get("symbols", []) if isinstance(result, dict) else []
        symbols.sort(key=lambda s: self._safe_int(s.get("offset", "0x0")))
        self._symbol_cache[key] = symbols
        return symbols

    def refresh_symbols_for_module(self, mod: str, refresh: bool = True) -> int:
        return len(self._symbols_for_module(mod, refresh=refresh))

    def resolve_symbol(self, mod: str, offset_hex: str) -> str:
        if not mod or mod == "unknown":
            return ""
        offset = self._safe_int(offset_hex)
        symbols = self._symbol_cache.get(self._module_key(mod), [])
        best = None
        for sym in symbols:
            start = self._safe_int(sym.get("offset", "0x0"))
            end_s = sym.get("end")
            end = self._safe_int(end_s) if end_s else None
            if start == offset:
                best = (sym, 0)
                break
            if end is not None and start <= offset < end:
                best = (sym, offset - start)
        if not best:
            return ""
        name = best[0].get("name", "")
        delta = best[1]
        if not name:
            return ""
        return "{}+{}".format(name, hex(delta)) if delta else name

    @staticmethod
    def _safe_int(v) -> int:
        try:
            return int(str(v), 16)
        except Exception:
            return 0

    # ── Ghidra sync 전송 (그래프 → Ghidra) ──────────────────

    def send_sync(self, module: str, offset_hex: str):
        with self._lock: conn = self._conn
        if conn:
            self._send(conn, {
                "type": "sync", "module": module, "offset": offset_hex})

    # ── Ghidra RPC (동기) ─────────────────────────────────

    def ghidra_rpc(self, method: str, params: dict,
                   timeout: float = 30.0) -> Optional[dict]:
        with self._lock: conn = self._conn
        if conn is None: return None
        req_id = str(uuid.uuid4())
        ev     = threading.Event()
        holder: list = []
        with self._rpc_lock:
            self._rpc[req_id] = (ev, holder)
        self._send(conn, {
            "type": "rpc_request", "req_id": req_id,
            "method": method, "params": params,
        })
        if not ev.wait(timeout=timeout):
            with self._rpc_lock: self._rpc.pop(req_id, None)
            return None
        return holder[0] if holder else None

    def stop(self):
        self._running = False
        with self._lock: conn = self._conn
        if conn:
            try: self._send(conn, {"type": "disconnect", "client": "server"})
            except: pass

    @staticmethod
    def _send(conn: socket.socket, obj: dict):
        try:
            conn.sendall(
                (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
        except: pass

    @staticmethod
    def _lines(conn: socket.socket, initial: str = ""):
        buf = initial
        conn.settimeout(None)
        while True:
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if line: yield line
            try: chunk = conn.recv(65536)
            except: break
            if not chunk: break
            buf += chunk.decode("utf-8", errors="replace")


# ============================================================
# GUI – 왼쪽 패널
# ============================================================

class LeftPanel(QWidget):
    start_trace_requested = Signal(str)   # 절대경로
    stop_trace_requested  = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._path_cache: dict[str, str] = {}
        ly = QVBoxLayout(self)
        ly.setContentsMargins(4, 4, 4, 4)

        lbl = QLabel("타겟 모듈")
        lbl.setStyleSheet("font-weight:bold;color:#1E293B;")
        ly.addWidget(lbl)

        self._list = QListWidget()
        self._list.setStyleSheet(
            "background:#FFFFFF;color:#1E293B;"
            "border:1px solid #D1D9E0;border-radius:3px;")
        self._list.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self._list.customContextMenuRequested.connect(self._ctx)
        ly.addWidget(self._list)

        sep = QLabel("로드된 모듈")
        sep.setStyleSheet("font-weight:bold;color:#1E293B;margin-top:6px;")
        ly.addWidget(sep)

        self._loaded = QListWidget()
        self._loaded.setStyleSheet(
            "background:#FAFAFA;color:#6B7280;"
            "border:1px solid #D1D9E0;border-radius:3px;")
        ly.addWidget(self._loaded)

        self._stop_btn = QPushButton("■  트레이스 강제 종료")
        self._stop_btn.setEnabled(False)
        self._stop_btn.setStyleSheet(
            "background:#DC2626;color:white;"
            "border:none;border-radius:3px;padding:5px;")
        self._stop_btn.clicked.connect(self.stop_trace_requested)
        ly.addWidget(self._stop_btn)

    def set_project_files(self, files: list[str]):
        self._list.clear()
        for f in sorted(files):
            item = QListWidgetItem(f)
            if f.lower().endswith(".exe"):
                item.setForeground(Qt.GlobalColor.cyan)
            self._list.addItem(item)

    def update_loaded_modules(self, modules: list[str]):
        existing = {self._loaded.item(i).text()
                    for i in range(self._loaded.count())}
        for m in sorted(modules):
            if m not in existing:
                self._loaded.addItem(QListWidgetItem(m))

    def set_tracing(self, active: bool):
        self._stop_btn.setEnabled(active)

    def _ctx(self, pos):
        item = self._list.itemAt(pos)
        if not item or not item.text().lower().endswith(".exe"):
            return
        fname = item.text()
        menu  = QMenu(self)
        act   = QAction("▶  트레이스 시작: {}".format(fname), self)
        act.triggered.connect(lambda: self._request(fname))
        menu.addAction(act)
        menu.exec(self._list.mapToGlobal(pos))

    def _request(self, fname: str):
        if fname in self._path_cache:
            self.start_trace_requested.emit(self._path_cache[fname])
            return
        for d in [Path.cwd(), Path(__file__).parent]:
            p = d / fname
            if p.exists():
                self._path_cache[fname] = str(p)
                self.start_trace_requested.emit(str(p))
                return
        path, _ = QFileDialog.getOpenFileName(
            self, "'{}' 위치 지정".format(fname), "",
            "{} ({});;모든 파일 (*)".format(fname, fname))
        if path:
            self._path_cache[fname] = path
            self.start_trace_requested.emit(path)


# ============================================================
# GUI – 오른쪽 패널 (함수 검색)
# ============================================================

class FunctionSearchPanel(QWidget):
    function_selected = Signal(str, str, str)  # (module, offset_hex, graph_token)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._session = None
        self._symbol_resolver = None
        self._entries: list[dict] = []

        ly = QVBoxLayout(self)
        ly.setContentsMargins(4, 4, 4, 4)
        lbl = QLabel("함수 검색")
        lbl.setStyleSheet("font-weight:bold;color:#1E293B;")
        ly.addWidget(lbl)

        self._edit = QLineEdit()
        self._edit.setPlaceholderText("함수명 / 모듈 / 오프셋 검색...")
        self._edit.setStyleSheet(
            "background:#FFFFFF;color:#1E293B;"
            "border:1px solid #C0C8D0;border-radius:3px;padding:3px 5px;")
        self._edit.textChanged.connect(self._apply_filter)
        ly.addWidget(self._edit)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["함수", "위치"])
        self._tree.setRootIsDecorated(False)
        self._tree.itemActivated.connect(self._activate)
        self._tree.itemDoubleClicked.connect(self._activate)
        self._tree.setStyleSheet(
            "background:#FFFFFF;color:#1E293B;"
            "border:1px solid #D1D9E0;border-radius:3px;"
            "QHeaderView::section{background:#EEF2F7;color:#1E293B;"
            "border:none;padding:3px;font-weight:bold;}")
        ly.addWidget(self._tree)

    def set_symbol_resolver(self, resolver):
        self._symbol_resolver = resolver

    def set_session(self, session):
        self._session = session
        self._rebuild_entries()

    def set_graph_entries(self, entries: list[dict]):
        self._entries = entries
        self._apply_filter()

    def refresh_names(self):
        self._rebuild_entries()

    def _rebuild_entries(self):
        self._entries = []
        if not self._session:
            self._apply_filter()
            return

        seen: dict[tuple[str, str], dict] = {}
        for ev in self._session.events:
            if ev.get("type") != "call":
                continue
            mod = ev.get("dst_module", "")
            off = ev.get("dst_offset", "0x0")
            if not mod or mod == "unknown":
                continue
            key = (mod.lower(), off.lower())
            seen[key] = {"count": seen.get(key, {}).get("count", 0) + 1}

        order = 0
        for ev in self._session.events:
            if ev.get("type") != "call":
                continue
            mod = ev.get("dst_module", "")
            off = ev.get("dst_offset", "0x0")
            if not mod or mod == "unknown":
                continue
            key = (mod.lower(), off.lower())
            self._entries.append({
                "module": mod,
                "offset": off,
                "tid": ev.get("thread_id", 0),
                "node_id": "",
                "call_seq": order,
                "trace_seq": ev.get("seq", order),
                "count": seen.get(key, {}).get("count", 1),
                "fallback": ev.get("dst_symbol", ""),
            })
            order += 1

        self._entries = sorted(
            self._entries, key=lambda e: (e["trace_seq"], e["tid"], e["call_seq"]))
        self._apply_filter()

    def _label_for(self, entry: dict) -> str:
        sym = ""
        if self._symbol_resolver:
            try:
                sym = self._symbol_resolver(
                    entry["module"], entry["offset"]) or ""
            except Exception:
                sym = ""
        label = sym or entry.get("fallback", "")
        if not label:
            label = "{}+{}".format(entry["module"], entry["offset"])
        if entry.get("count", 0) > 1:
            label = "{}  total:{}".format(label, entry["count"])
        label = "T{} #{}  {}".format(
            entry.get("tid", "?"), entry.get("trace_seq", "?"), label)
        return label

    def _apply_filter(self):
        q = self._edit.text().strip().lower()
        self._tree.clear()
        for entry in self._entries:
            label = self._label_for(entry)
            addr = "{}+{}".format(entry["module"], entry["offset"])
            hay = "{} {} thread {} tid {}".format(
                label, addr, entry.get("tid", ""), entry.get("tid", "")).lower()
            if q and q not in hay:
                continue
            item = QTreeWidgetItem([label, addr])
            graph_token = ""
            if entry.get("node_id"):
                graph_token = "{}|{}".format(entry.get("tid"), entry.get("node_id"))
            item.setData(0, Qt.ItemDataRole.UserRole,
                         "{}|{}|{}".format(entry["module"], entry["offset"], graph_token))
            self._tree.addTopLevelItem(item)
        self._tree.resizeColumnToContents(0)

    def _activate(self, item, _column=0):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data or "|" not in data:
            return
        parts = str(data).split("|", 2)
        module = parts[0]
        offset = parts[1] if len(parts) > 1 else "0x0"
        graph_token = parts[2] if len(parts) > 2 else ""
        self.function_selected.emit(module, offset, graph_token)


# ============================================================
# 메인 윈도우
# ============================================================

class MainWindow(QMainWindow):
    _stop_frida_requested = Signal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Frida Bridge  –  리버싱 프레임워크")
        self.resize(1440, 820)
        self.setStyleSheet("""
            QMainWindow { background:#F5F5F5; }
            QWidget { color:#1E293B; }
            QMenu { background:#FFFFFF; color:#1E293B; border:1px solid #D1D9E0; }
            QMenu::item:selected { background:#DBEAFE; }
            QScrollBar:vertical { background:#F5F5F5; width:10px; border:none; }
            QScrollBar::handle:vertical { background:#C0C8D0; border-radius:5px; min-height:20px; }
            QScrollBar::handle:vertical:hover { background:#0078D4; }
            QScrollBar:horizontal { background:#F5F5F5; height:10px; border:none; }
            QScrollBar::handle:horizontal { background:#C0C8D0; border-radius:5px; min-width:20px; }
        """)

        self._session:       Optional[TraceSession]       = None
        self._frida_worker:  Optional[FridaWorker]        = None
        self._frida_thread:  Optional[QThread]            = None
        self._ghidra_worker: Optional[GhidraServerWorker] = None
        self._ghidra_thread: Optional[QThread]            = None
        self._frida_live_threads: list[QThread] = []
        self._frida_live_workers: list[FridaWorker] = []
        self._is_tracing     = False
        self._frida_error_dialog_shown = False
        self._project_files: list[str] = []

        self._setup_menu()
        self._setup_ui()
        self._setup_ghidra_server()

    # ── 메뉴 ────────────────────────────────────────────────

    def _setup_menu(self):
        bar  = self.menuBar()
        bar.setStyleSheet(
            "background:#EEF2F7;color:#1E293B;"
            "border-bottom:1px solid #D1D9E0;")
        menu = bar.addMenu("File")
        for label, shortcut, slot in [
            ("Save Trace…", "Ctrl+S", self._save),
            ("Load Trace…", "Ctrl+O", self._load),
            (None, None, None),
            ("Quit",        "Ctrl+Q", self.close),
        ]:
            if label is None:
                menu.addSeparator()
            else:
                act = QAction(label, self)
                act.setShortcut(shortcut)
                act.triggered.connect(slot)
                menu.addAction(act)

    # ── UI ──────────────────────────────────────────────────

    def _setup_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        ly   = QHBoxLayout(root)
        ly.setContentsMargins(0, 0, 0, 0)
        ly.setSpacing(0)

        h_split = QSplitter(Qt.Orientation.Horizontal)
        h_split.setStyleSheet("QSplitter::handle{background:#D1D9E0;width:2px;}")

        # 왼쪽
        self._left = LeftPanel()
        self._left.setMinimumWidth(200)
        self._left.setMaximumWidth(320)
        self._left.start_trace_requested.connect(self._start_trace)
        self._left.stop_trace_requested.connect(self._stop_trace)
        h_split.addWidget(self._left)

        # 중앙: 콜 그래프
        self._graph = CallGraphPanel()
        self._graph.set_symbol_resolver(self._resolve_ghidra_symbol)
        self._graph.sync_requested.connect(self._on_graph_sync)
        self._graph.symbol_refresh_requested.connect(
            lambda: self._refresh_ghidra_symbols(refresh=True))
        self._graph.annotate_requested.connect(self._apply_ghidra_annotations)
        self._graph.xref_requested.connect(self._apply_ghidra_xrefs)
        self._graph.symbol_modules_requested.connect(
            lambda mods: self._refresh_symbol_modules(
                mods, refresh=False, reload_graph=True))
        h_split.addWidget(self._graph)

        # 오른쪽: 함수 검색
        self._func_panel = FunctionSearchPanel()
        self._func_panel.set_symbol_resolver(self._resolve_ghidra_symbol)
        self._func_panel.function_selected.connect(self._on_function_selected)
        self._func_panel.setMinimumWidth(240)
        self._func_panel.setMaximumWidth(360)
        h_split.addWidget(self._func_panel)

        h_split.setSizes([240, 960, 280])
        ly.addWidget(h_split)

        self._sb = QStatusBar()
        self._sb.setStyleSheet(
            "background:#0078D4;color:white;font-size:12px;padding:2px 6px;")
        self.setStatusBar(self._sb)
        self._st("준비  |  Ghidra Script 연결 대기 중")

    # ── Ghidra 서버 ─────────────────────────────────────────

    def _setup_ghidra_server(self):
        self._ghidra_worker = GhidraServerWorker()
        self._ghidra_thread = QThread()
        self._ghidra_worker.moveToThread(self._ghidra_thread)
        self._ghidra_worker.status_changed.connect(self._st)
        self._ghidra_worker.ghidra_connected.connect(
            lambda c: self._st("Ghidra {}".format("연결됨" if c else "연결 해제")))
        self._ghidra_worker.project_info_recv.connect(self._on_project_info)
        self._ghidra_worker.sync_recv.connect(self._on_ghidra_sync)
        self._ghidra_thread.started.connect(self._ghidra_worker.run_server)
        self._ghidra_thread.start()

    def _on_project_info(self, files: list[str]):
        self._project_files = files
        self._left.set_project_files(files)
        self._st("프로젝트 파일 {}개 수신".format(len(files)))

    def _on_graph_sync(self, module: str, offset_hex: str):
        """그래프 노드 선택 → Ghidra sync."""
        if self._ghidra_worker:
            self._ghidra_worker.send_sync(module, offset_hex)

    def _on_function_selected(self, module: str, offset_hex: str, graph_token: str):
        if graph_token:
            self._graph.goto_node_token(graph_token)
        else:
            self._graph.sync_from_ghidra(module, offset_hex)
        self._on_graph_sync(module, offset_hex)

    def _on_ghidra_sync(self, module: str, offset_hex: str):
        if self._session and self._ghidra_worker:
            self._ghidra_worker.refresh_symbols_for_module(module)
            self._graph.load_session(self._session)
            self._func_panel.set_graph_entries(self._graph.function_entries())
        self._graph.sync_from_ghidra(module, offset_hex)

    def _resolve_ghidra_symbol(self, module: str, offset_hex: str) -> str:
        if not self._ghidra_worker:
            return ""
        return self._ghidra_worker.resolve_symbol(module, offset_hex)

    # ── 트레이스 시작/종료 ────────────────────────────────────

    def _start_trace(self, target_path: str):
        if not self._check_unsaved(): return
        if self._is_tracing:
            self._st("이미 트레이스 중입니다.")
            return
        self._session    = TraceSession()
        self._is_tracing = True
        self._frida_error_dialog_shown = False
        self._left.set_tracing(True)

        self._frida_worker = FridaWorker(target_path, self._project_files)
        self._frida_thread = QThread()
        worker = self._frida_worker
        thread = self._frida_thread
        self._frida_live_workers.append(worker)
        self._frida_live_threads.append(thread)
        self._frida_worker.moveToThread(self._frida_thread)
        self._frida_worker.status_changed.connect(self._st)
        self._frida_worker.trace_complete.connect(self._on_trace_complete)
        self._frida_worker.error_occurred.connect(self._on_frida_error)
        self._frida_worker.finished.connect(
            lambda w=worker: self._on_frida_finished(w))
        self._frida_worker.finished.connect(self._frida_thread.quit)
        self._frida_worker.finished.connect(self._frida_worker.deleteLater)
        self._frida_thread.finished.connect(
            lambda t=thread, w=worker: self._on_frida_thread_finished(t, w))
        self._frida_thread.finished.connect(self._frida_thread.deleteLater)
        self._stop_frida_requested.connect(self._frida_worker.stop_trace)
        self._frida_thread.started.connect(self._frida_worker.start_trace)
        self._frida_thread.start()
        self._st("트레이스 시작: {}".format(target_path))

    def _stop_trace(self):
        if self._frida_worker:
            self._stop_frida_requested.emit()
        self._is_tracing = False
        self._left.set_tracing(False)

    def _on_trace_complete(self, session: TraceSession):
        self._session    = session
        self._is_tracing = False
        self._left.set_tracing(False)
        self._left.update_loaded_modules(session.modules)
        self._graph.load_session(session)
        self._func_panel.set_graph_entries(self._graph.function_entries())
        self._st("트레이스 완료  이벤트:{}  스냅샷:{}  모듈:{}".format(
            len(session.events), len(session.snapshots), len(session.modules)))

    def _refresh_ghidra_symbols(self, refresh: bool = False,
                                reload_graph: bool = True):
        if not self._session or self._session.is_empty():
            self._st("Ghidra 이름 갱신: 트레이스 없음")
            return
        if not self._ghidra_worker:
            self._st("Ghidra 이름 갱신: 서버 없음")
            return
        if not self._ghidra_worker.is_connected():
            self._st("Ghidra 이름 갱신: Ghidra 미연결")
            return
        changed = self._refresh_symbol_modules(
            self._graph.visible_modules(), refresh=refresh, reload_graph=False)
        if reload_graph:
            self._graph.load_session(self._session)
            self._func_panel.set_graph_entries(self._graph.function_entries())
        self._st("Ghidra 이름 갱신: {}개 모듈 반영".format(changed))

    def _refresh_symbol_modules(self, modules: list[str],
                                refresh: bool = False,
                                reload_graph: bool = False) -> int:
        if not self._ghidra_worker or not self._ghidra_worker.is_connected():
            return 0
        changed = 0
        for mod in modules:
            if self._ghidra_worker.refresh_symbols_for_module(mod, refresh):
                changed += 1
        if reload_graph and self._session:
            self._graph.load_session(self._session)
            self._func_panel.set_graph_entries(self._graph.function_entries())
        return changed

    def _apply_ghidra_annotations(self):
        if not self._session or self._session.is_empty():
            self._st("주석 적용: 트레이스 없음")
            return
        if not self._ghidra_worker:
            self._st("주석 적용: Ghidra 서버 없음")
            return
        if not self._ghidra_worker.is_connected():
            self._st("주석 적용: Ghidra 미연결")
            return
        self._ghidra_worker.refresh_symbols_for_session(
            self._session, refresh=False)
        self._ghidra_worker.send_annotations(self._session)

    def _apply_ghidra_xrefs(self):
        if not self._session or self._session.is_empty():
            self._st("XRef 추가: 트레이스 없음")
            return
        if not self._ghidra_worker:
            self._st("XRef 추가: Ghidra 서버 없음")
            return
        if not self._ghidra_worker.is_connected():
            self._st("XRef 추가: Ghidra 미연결")
            return
        self._ghidra_worker.refresh_symbols_for_session(
            self._session, refresh=False)
        self._ghidra_worker.send_xrefs(self._session)

    def _on_frida_error(self, msg: str):
        self._st("오류: {}".format(msg))
        if not self._frida_error_dialog_shown:
            self._frida_error_dialog_shown = True
            QMessageBox.critical(self, "Frida 오류", msg)
        self._is_tracing = False
        self._left.set_tracing(False)

    def _on_frida_finished(self, worker: FridaWorker):
        self._is_tracing = False
        self._left.set_tracing(False)
        try:
            self._stop_frida_requested.disconnect(worker.stop_trace)
        except Exception:
            pass

    def _on_frida_thread_finished(
        self, thread: QThread, worker: FridaWorker,
    ):
        dbg("frida qthread finished")
        if self._frida_worker is worker:
            self._frida_worker = None
        if self._frida_thread is thread:
            self._frida_thread = None
        try:
            self._frida_live_workers.remove(worker)
        except ValueError:
            pass
        try:
            self._frida_live_threads.remove(thread)
        except ValueError:
            pass

    # ── 저장 / 불러오기 ─────────────────────────────────────

    def _save(self) -> bool:
        if not self._session or self._session.is_empty():
            QMessageBox.information(self, "저장", "저장할 트레이스가 없습니다.")
            return False
        path, _ = QFileDialog.getSaveFileName(
            self, "트레이스 저장", "", "JSON (*.json);;모든 파일 (*)")
        if not path: return False
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._session.to_dict(), f,
                          ensure_ascii=False, indent=2)
            self._session.saved = True
            self._st("저장: {}".format(path))
            return True
        except Exception as e:
            QMessageBox.critical(self, "저장 오류", str(e))
            return False

    def _load(self):
        if not self._check_unsaved(): return
        path, _ = QFileDialog.getOpenFileName(
            self, "트레이스 불러오기", "", "JSON (*.json);;모든 파일 (*)")
        if not path: return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            sess = TraceSession.from_dict(data)
            self._session = sess
            self._left.update_loaded_modules(sess.modules)
            self._graph.load_session(sess)
            self._func_panel.set_graph_entries(self._graph.function_entries())
            self._st("불러오기: {}  이벤트:{}".format(path, len(sess.events)))
        except Exception as e:
            QMessageBox.critical(self, "불러오기 오류", str(e))

    def _check_unsaved(self) -> bool:
        if not (self._session and not self._session.saved
                and not self._session.is_empty()):
            return True
        r = QMessageBox.question(
            self, "이전 트레이스",
            "저장되지 않은 트레이스가 있습니다. 저장하시겠습니까?",
            QMessageBox.StandardButton.Save |
            QMessageBox.StandardButton.Discard |
            QMessageBox.StandardButton.Cancel)
        if r == QMessageBox.StandardButton.Save:   return self._save()
        if r == QMessageBox.StandardButton.Cancel: return False
        return True

    def _st(self, msg: str):
        self._sb.showMessage(msg)

    def closeEvent(self, event):
        if not self._check_unsaved():
            event.ignore(); return
        if self._frida_worker:
            try: self._stop_frida_requested.emit()
            except: pass
        if self._ghidra_worker:
            self._ghidra_worker.stop()
        event.accept()


# ============================================================
# 진입점
# ============================================================

def main():
    import sys, argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--headless", action="store_true",
                        help="GUI 없이 Ghidra 서버만 실행")
    args = parser.parse_args()

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    win = MainWindow()
    if not args.headless:
        win.show()
    else:
        print("[headless] Ghidra 서버 실행 중. Ctrl+C로 종료.")

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
