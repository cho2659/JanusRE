"""
frida_bridge.py
===============
frida_bridge_server.py + call_graph_view.py 통합 단일 파일.

역할:
  1. PySide6 GUI (왼쪽: 타겟 모듈 / 중앙: 콜 그래프 / 오른쪽: 로드 모듈)
  2. Frida 에이전트 실행 및 트레이스 수신
  3. 트레이스 후처리 (raw VA → module+offset)
  4. Ghidra Script TCP 클라이언트 (포트 8763)
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
    → LayoutWorker._compute()   [메인스레드, 즉시 좌표 계산]
    → GraphScene.apply()        [메인스레드, 그리기만]
"""

from __future__ import annotations

import bisect
import ctypes
import json
import math
import mmap
import os
import socket
import struct
import threading
import time
import uuid
from pathlib import Path
from typing import Optional
from ctypes import wintypes

import frida
import networkx as nx
from PySide6.QtCore import (
    Qt, QThread, Signal, QObject, QRectF, QPointF, QSettings,
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
    QGraphicsPathItem, QStackedWidget, QLineEdit, QSizePolicy,
)

AGENT_JS_PATH      = Path(__file__).parent / "frida_agent" / "agent.js"
GHIDRA_SERVER_HOST = "127.0.0.1"
GHIDRA_SERVER_PORT = 8763
PE_MACHINE_I386    = 0x014C
PE_MACHINE_AMD64   = 0x8664
PE_MACHINE_ARM64   = 0xAA64


def dbg(msg: str):
    print("[frida_delta] {}".format(msg), flush=True)


# ============================================================
# 색상 (IDA Pro 라이트 테마)
# ============================================================

C_BG           = QColor("#F5F5F5")   # 캔버스 배경
C_NODE_BG      = QColor("#FFFFFF")   # 일반 노드
C_NODE_EXTERNAL= QColor("#F0F4FF")   # 외부 모듈 노드 배경
C_NODE_BORDER  = QColor("#C0C8D0")   # 노드 테두리
C_NODE_BORDER_EXT = QColor("#A0A8C0")# 외부 모듈 노드 테두리
C_NODE_SEL     = QColor("#0078D4")   # 선택 강조
C_NODE_SEARCH  = QColor("#D4820A")   # 검색 강조
C_NODE_ENTRY   = QColor("#E8F4E8")   # 진입 노드 배경
C_NODE_EXIT    = QColor("#FDE8E8")   # 종료 노드 배경
C_TEXT_FUNC    = QColor("#1F3864")   # 함수명 (진한 네이비)
C_TEXT_EXT_MOD = QColor("#6050A0")   # 외부 모듈명 (퍼플)
C_TEXT_ADDR    = QColor("#0060A8")   # 주소 (IDA 블루)
C_TEXT_SUB     = QColor("#6B7280")   # 보조 텍스트
C_TEXT_ARG     = QColor("#005FAF")   # 인자 레지스터
C_TEXT_RET     = QColor("#007050")   # 반환값
C_EDGE_CALL    = QColor("#0078D4")   # call 엣지
C_EDGE_RET     = QColor("#9CA3AF")   # ret 엣지
C_EDGE_SYNC    = QColor("#B45309")   # sync 엣지
C_EDGE_SPAWN   = QColor("#7C3AED")   # spawn 엣지

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
        "src_module", "src_symbol", "src_offset",
        "tid", "call_seq", "trace_seq", "depth",
        "children_ids", "parent_id",
        "spawn_tid", "spawn_start_sym",
        "spawn_child_node_id", "spawn_child_tid",
        "spawned_by_id", "spawned_by_tid",
        "spawned_by_label", "spawn_start_label",
        "is_entry", "is_exit", "is_external",
        "expanded",
    )

    def __init__(self, node_id: str, module: str, symbol: str,
                 offset: int, tid: int, call_seq: int, depth: int):
        self.node_id        = node_id
        self.module         = module
        self.symbol         = symbol
        self.offset         = offset
        self.src_module     = ""
        self.src_symbol     = ""
        self.src_offset     = 0
        self.tid            = tid
        self.call_seq       = call_seq
        self.trace_seq      = call_seq
        self.depth          = depth
        self.children_ids:  list[str] = []
        self.parent_id:     Optional[str]  = None
        self.spawn_tid:          Optional[int]  = None
        self.spawn_start_sym:    str            = ""
        self.spawn_child_node_id: Optional[str] = None   # 자식 스레드 루트 node_id
        self.spawn_child_tid:     Optional[int] = None   # 자식 스레드 TID
        self.spawned_by_id:      Optional[str]  = None
        self.spawned_by_tid:     Optional[int]  = None   # 생성한 부모 스레드 TID
        self.spawned_by_label:   str            = ""
        self.spawn_start_label:  str            = ""
        self.is_entry    = False
        self.is_exit     = False
        self.is_external = False  # 타겟 외부 모듈 함수 호출 노드
        self.expanded    = False

    def label(self) -> str:
        if self.symbol:
            return self.symbol
        if self.is_external and self.module and not self.module.startswith("["):
            return "{}!+{}".format(self.module, hex(self.offset))
        return "{}+{}".format(self.module, hex(self.offset))

    def addr_str(self) -> str:
        if self.module.startswith("["):
            return "Thread {} · seq {}".format(self.tid, self.trace_seq)
        return "{}!{}".format(self.module, hex(self.offset))

    def src_label(self) -> str:
        if self.src_symbol:
            return self.src_symbol
        if self.src_module:
            return "{}+{}".format(self.src_module, hex(self.src_offset))
        return ""

    def src_addr_str(self) -> str:
        if not self.src_module:
            return ""
        return "{}!{}".format(self.src_module, hex(self.src_offset))


class CallEdge:
    __slots__ = ("src_id", "dst_id", "kind", "tid")

    def __init__(self, src_id: str, dst_id: str, kind: str, tid: int):
        self.src_id = src_id
        self.dst_id = dst_id
        self.kind   = kind   # "call" | "jump" | "sync" | "spawn" | "flow"
        self.tid    = tid


# ============================================================
# CallTreeBuilder
# ============================================================

class CallTreeBuilder:
    """TraceSession → {tid: (nodes, edges)} 변환.

    부모-자식 관계 원칙:
      - 부모는 같은 TID의 동적 call stack top으로만 결정한다.
      - call 이벤트: 현재 stack top이 부모이고, 새 dst 함수가 자식이다.
      - jump 이벤트: 현재 stack top이 부모이고, 새 dst 함수가 자식이나 stack push하지 않는다.
      - ret 이벤트: 그래프에 그리지 않고 현재 stack top을 pop한다.
      - stack이 비어 있을 때 나온 call은 새 root다.
      - 시간상 다음 root를 부모/자식으로 연결하지 않는다.

    이유:
      FUN_A가 FUN_B를 호출한 뒤 ret로 빠져나온 다음 FUN_C가 실행되면,
      FUN_C는 FUN_A의 하위 호출이 아니다. 이전 구현의 flow edge는 이런
      "다음 실행"을 점선으로 연결했고, 실제 call 관계처럼 보여 오해를 만들었다.
    """

    def __init__(self, symbol_resolver=None, target_modules: Optional[list[str]] = None):
        self._symbol_resolver = symbol_resolver
        self._target_modules = self._normalize_targets(target_modules or [])

    def build(self, session) -> dict[int, tuple[dict, list]]:
        # 스레드별 이벤트 분리
        by_tid: dict[int, list[dict]] = {}
        for ev in session.events:
            if ev.get("type") not in ("call", "ret", "jump"):
                continue
            if not self._is_graph_event(ev):
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
            if s.get("child_tid") is not None
        }

        result: dict[int, tuple[dict, list]] = {}
        spawn_tids: set[int] = set()
        for s in getattr(session, "spawn_events", []):
            if s.get("parent_tid") is not None:
                spawn_tids.add(int(s.get("parent_tid")))
            if s.get("child_tid") is not None:
                spawn_tids.add(int(s.get("child_tid")))

        exception_by_tid: dict[int, list[dict]] = {}
        for ev in getattr(session, "exception_events", []):
            tid = ev.get("tid", 0)
            exception_by_tid.setdefault(tid, []).append(ev)

        for tid in sorted(
            set(by_tid.keys()) | set(sync_by_tid.keys())
            | set(exception_by_tid.keys()) | spawn_tids
        ):
            events = by_tid.get(tid, [])
            nodes, edges = self._build_thread(
                tid, events,
                sync_by_tid.get(tid, []),
                exception_by_tid.get(tid, []),
            )
            if not nodes:
                nodes, edges = self._build_placeholder_thread(
                    tid, spawn_by_child.get(tid))
            result[tid] = (nodes, edges)

        self._link_spawns(result, spawn_by_child)
        return result

    def _build_thread(
        self, tid: int, events: list[dict],
        sync_events: list[dict],
        exception_events: list[dict],
    ) -> tuple[dict, list]:
        nodes: dict[str, CallNode] = {}
        edges: list[CallEdge]      = []
        stack: list[str]           = []
        call_counter: dict[str, int] = {}
        caller_anchors: dict[tuple[str, str, str], str] = {}
        last_external_node: Optional[str] = None
        last_outbound: Optional[dict] = None
        exception_since_outbound = False
        call_seq = 0

        timeline = (
            [(ev.get("seq", i), "trace", ev) for i, ev in enumerate(events)]
            + [(ev.get("seq", i), "sync", ev) for i, ev in enumerate(sync_events)]
            + [(ev.get("seq", i), "exception", ev)
               for i, ev in enumerate(exception_events)]
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
            if item_kind == "exception":
                if last_outbound:
                    exception_since_outbound = True
                continue

            ev_type = ev.get("type")
            if ev_type in ("call", "jump"):
                src_mod = ev.get("src_module", "unknown")
                src_off = self._hex(ev.get("src_offset", "0x0"))
                src_sym = ev.get("src_symbol", "")
                if not src_sym:
                    src_sym = self._display_symbol(
                        src_mod, ev.get("src_offset", "0x0"))

                dst_mod = ev.get("dst_module", "unknown")
                dst_off = self._hex(ev.get("dst_offset", "0x0"))
                dst_external = bool(ev.get("dst_is_external", False))
                dst_sym = ev.get("dst_symbol", "")
                if not dst_sym:
                    dst_sym = self._display_symbol(
                        dst_mod, ev.get("dst_offset", "0x0"))
                src_tt = self._event_target_flag(ev, "src_tt", src_mod)
                dst_tt = self._event_target_flag(ev, "dst_tt", dst_mod)
                if not src_tt and not dst_tt:
                    continue

                base_key = "{}+{}".format(dst_mod, hex(dst_off))
                call_counter[base_key] = call_counter.get(base_key, 0) + 1
                node_id = "{}_{}".format(base_key, call_counter[base_key])
                parent_id = stack[-1] if stack else None
                inbound_from_external = not src_tt and dst_tt
                tunnel_parent = (
                    inbound_from_external
                    and last_external_node
                    and not exception_since_outbound
                    and self._tunnel_inbound_matches(last_outbound, ev)
                )
                if tunnel_parent:
                    parent_id = last_external_node
                elif (inbound_from_external and last_external_node
                      and exception_since_outbound):
                    parent_id = None
                if ev.get("source") == "target_export":
                    parent_id = self._source_anchor_node(
                        nodes, caller_anchors, tid, src_mod, src_off, src_sym,
                        call_seq, ev.get("seq", call_seq))
                depth = (
                    nodes[parent_id].depth + 1
                    if parent_id and parent_id in nodes
                    else len(stack)
                )

                node = CallNode(
                    node_id  = node_id,
                    module   = dst_mod,
                    symbol   = dst_sym,
                    offset   = dst_off,
                    tid      = tid,
                    call_seq = call_seq,
                    depth    = depth,
                )
                node.trace_seq = ev.get("seq", call_seq)
                node.src_module = src_mod
                node.src_offset = src_off
                node.src_symbol = src_sym
                call_seq += 1

                # 외부 모듈 여부 판별 (타겟 집합에 없는 모듈)
                if (dst_external
                        or (self._target_modules
                        and dst_mod != "unknown"
                        and not dst_mod.startswith("[")
                        and not self._is_target_module(dst_mod))):
                    node.is_external = True
                    if not node.symbol and dst_mod != "unknown":
                        node.symbol = "{}!+{}".format(dst_mod, hex(dst_off))

                # exit 판별
                lbl = (dst_sym or "").lower()
                if any(x in lbl for x in ("exit", "terminate", "abort")):
                    node.is_exit = True

                if parent_id:
                    node.parent_id = parent_id
                    if parent_id in nodes:
                        nodes[parent_id].children_ids.append(node_id)
                    edges.append(CallEdge(parent_id, node_id, ev_type, tid))
                else:
                    node.is_entry = True

                nodes[node_id] = node
                if src_tt and not dst_tt:
                    last_external_node = node_id
                    last_outbound = ev
                    exception_since_outbound = False
                elif tunnel_parent:
                    last_external_node = None
                    last_outbound = None
                    exception_since_outbound = False
                elif inbound_from_external and exception_since_outbound:
                    last_external_node = None
                    last_outbound = None
                    exception_since_outbound = False
                elif src_tt:
                    last_external_node = None
                    last_outbound = None
                    exception_since_outbound = False

                if ev_type == "call":
                    stack.append(node_id)

            elif ev_type == "ret":
                ret_match_idx = self._ret_stack_match_index(stack, nodes, ev)
                if (not exception_since_outbound
                        and self._ret_closes_outbound(last_outbound, ev)):
                    last_external_node = None
                    last_outbound = None
                    exception_since_outbound = False
                self._unwind_stack_for_ret(stack, ret_match_idx)

        return nodes, edges

    def _ret_stack_match_index(
        self,
        stack: list[str],
        nodes: dict[str, CallNode],
        ev: dict,
    ) -> Optional[int]:
        for idx in range(len(stack) - 1, -1, -1):
            node = nodes.get(stack[idx])
            if node and self._node_matches_ret(node, ev):
                return idx
        return None

    def _node_matches_ret(self, node: CallNode, ev: dict) -> bool:
        src_mod = str(ev.get("src_module", "") or "").lower()
        if not src_mod or src_mod == "unknown":
            return False
        if (node.module or "").lower() != src_mod:
            return False

        src_off = self._hex(ev.get("src_offset", "0x0"))
        if node.offset == src_off:
            return True

        return (
            self._symbol_base(node.symbol)
            and self._symbol_base(node.symbol) == self._symbol_base(
                ev.get("src_symbol", ""))
        )

    @staticmethod
    def _symbol_base(symbol: str) -> str:
        base = (symbol or "").strip().lower()
        if "+" in base:
            base = base.rsplit("+", 1)[0].strip()
        return base

    @staticmethod
    def _unwind_stack_for_ret(
        stack: list[str],
        ret_match_idx: Optional[int],
    ):
        if ret_match_idx is None:
            stack.clear()
            return
        del stack[ret_match_idx:]

    def _build_placeholder_thread(
        self, tid: int, spawn_ev: Optional[dict],
    ) -> tuple[dict, list]:
        """이벤트가 아직 없는 스레드도 탭에서 보이도록 시작 노드를 만든다.

        사용자 입력/메시지 루프 이후에만 타겟 함수가 실행되는 스레드는
        NtCreateThread 계열 생성 이벤트만 있고 Stalker call 이벤트가 비어 있을
        수 있다. 이 경우도 분석 대상 스레드이므로 탭을 유지하고, 생성 시점에
        확보한 start routine 정보를 루트 노드로 표시한다.
        """
        module = "[thread]"
        symbol = "Thread {} start".format(tid)
        offset = 0
        trace_seq = 0
        if spawn_ev:
            module = spawn_ev.get("start_module", "") or "[thread]"
            if module == "unknown":
                module = "[thread]"
            symbol = spawn_ev.get("start_symbol", "") or ""
            if not symbol:
                if module.startswith("["):
                    symbol = "Thread {} start".format(tid)
                else:
                    symbol = "{}!{}".format(
                        module, spawn_ev.get("start_offset", "0x0"))
            offset = self._hex(spawn_ev.get("start_offset", "0x0"))
            trace_seq = int(spawn_ev.get("seq", 0))

        node_id = "thread_start_{}".format(tid)
        node = CallNode(
            node_id=node_id,
            module=module,
            symbol=symbol,
            offset=offset,
            tid=tid,
            call_seq=0,
            depth=0,
        )
        node.trace_seq = trace_seq
        node.is_entry = True
        return {node_id: node}, []

    @staticmethod
    def _sync_label(ev: dict) -> str:
        kind = ev.get("kind", "sync")
        handle = ev.get("handle", "")
        msg_id = ev.get("msg_id", None)
        api = ev.get("api", "")
        status = ev.get("status", "")
        handle_gen = ev.get("handle_gen", None)
        names = {
            "set_event": "SetEvent 신호",
            "pulse_event": "PulseEvent 신호",
            "release_mutex": "Mutex 해제",
            "wait_single": "단일 객체 대기",
            "wait_multiple": "다중 객체 대기",
            "queue_apc": "APC 큐 등록",
            "alpc": "ALPC 송수신",
            "post_message": "PostMessage",
            "send_message": "SendMessage",
            "get_message": "GetMessage",
            "peek_message": "PeekMessage",
        }
        label = names.get(kind, kind)
        if api:
            label = "{} {}".format(label, api)
        if status:
            label = "{} status={}".format(label, status)
        if msg_id is not None:
            return "{} msg={}".format(label, msg_id)
        if handle:
            gen = " gen={}".format(handle_gen) if handle_gen else ""
            return "{} handle={}{}".format(label, handle, gen)
        return label

    def _display_symbol(self, module: str, offset_hex: str) -> str:
        return ""

    def _source_anchor_node(
        self,
        nodes: dict[str, CallNode],
        anchors: dict[tuple[str, str, str], str],
        tid: int,
        src_mod: str,
        src_off: int,
        src_sym: str,
        call_seq: int,
        trace_seq: int,
    ) -> Optional[str]:
        if not src_mod or src_mod == "unknown":
            return None
        sym_base = self._symbol_base(src_sym)
        if sym_base:
            key = (src_mod.lower(), "symbol", sym_base)
        else:
            key = (src_mod.lower(), "offset", hex(src_off).lower())
        if key in anchors and anchors[key] in nodes:
            return anchors[key]

        anchor_id = "caller_{}_{}_{}".format(
            tid, len(anchors), abs(hash(key)) & 0xFFFF)
        node = CallNode(
            node_id=anchor_id,
            module=src_mod,
            symbol=src_sym,
            offset=src_off,
            tid=tid,
            call_seq=call_seq,
            depth=0,
        )
        node.trace_seq = trace_seq
        node.is_entry = True
        nodes[anchor_id] = node
        anchors[key] = anchor_id
        return anchor_id

    def _is_graph_event(self, ev: dict) -> bool:
        """수집 이벤트 중 그래프에 표시할 타겟 경계/내부 이벤트만 통과시킨다.

        Stalker/Interceptor는 누락 방지를 위해 넓게 수집하지만, 그래프는
        타겟 내부 호출과 타겟<->외부 경계만 표시한다. 따라서
        내부->외부->외부->내부 흐름은 첫 내부->외부 진입과 마지막
        외부->내부 복귀만 남고, 중간 외부->외부 호출은 숨겨진다.
        """
        if not self._target_modules:
            return True
        src_target = self._is_target_module(ev.get("src_module", ""))
        dst_target = self._is_target_module(ev.get("dst_module", ""))
        return src_target or dst_target

    def _is_external_to_target_ret(self, ev: dict) -> bool:
        if ev.get("type") != "ret":
            return False
        return (
            not self._is_target_module(ev.get("src_module", ""))
            and self._is_target_module(ev.get("dst_module", ""))
        )

    def _event_target_flag(self, ev: dict, field: str, module: str) -> bool:
        if field in ev:
            return bool(ev.get(field))
        return self._is_target_module(module)

    def _same_module_offset(
        self,
        left_mod: str,
        left_off,
        right_mod: str,
        right_off,
    ) -> bool:
        if not left_mod or not right_mod:
            return False
        if left_mod == "unknown" or right_mod == "unknown":
            return False
        if left_mod.lower() != right_mod.lower():
            return False
        return self._hex(left_off) == self._hex(right_off)

    def _tunnel_inbound_matches(
        self,
        outbound: Optional[dict],
        inbound: dict,
    ) -> bool:
        if not outbound:
            return False
        if self._same_module_offset(
            outbound.get("dst_module", ""),
            outbound.get("dst_offset", "0x0"),
            inbound.get("src_module", ""),
            inbound.get("src_offset", "0x0"),
        ):
            return True

        inbound_src_tt = self._event_target_flag(
            inbound, "src_tt", inbound.get("src_module", ""))
        inbound_dst_tt = self._event_target_flag(
            inbound, "dst_tt", inbound.get("dst_module", ""))
        return not inbound_src_tt and inbound_dst_tt

    def _ret_closes_outbound(
        self,
        outbound: Optional[dict],
        ret_ev: dict,
    ) -> bool:
        if not outbound or ret_ev.get("type") != "ret":
            return False
        if not self._is_external_to_target_ret(ret_ev):
            return False
        return self._same_module_offset(
            outbound.get("src_module", ""),
            outbound.get("src_offset", "0x0"),
            ret_ev.get("dst_module", ""),
            ret_ev.get("dst_offset", "0x0"),
        )

    @staticmethod
    def _normalize_targets(modules: list[str]) -> set[str]:
        out: set[str] = set()
        for mod in modules:
            name = Path(str(mod)).name.lower()
            if not name:
                continue
            out.add(name)
            out.add(name.rsplit(".", 1)[0])
        return out

    def _is_target_module(self, module: str) -> bool:
        if not module or module == "unknown":
            return False
        name = Path(str(module)).name.lower()
        stem = name.rsplit(".", 1)[0]
        return name in self._target_modules or stem in self._target_modules

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
            if parent_tid not in result or child_tid not in result:
                continue

            parent_nodes, parent_edges = result[parent_tid]
            child_nodes, _             = result[child_tid]

            creator_id = CallTreeBuilder._find_spawn_creator_node(
                parent_nodes, spawn_ev)
            if creator_id is None:
                creator_id = CallTreeBuilder._fallback_spawn_creator_node(
                    parent_nodes, spawn_ev)

            # 자식: 루트 노드 (is_entry인 것, 없으면 call_seq 최소)
            child_root_id: Optional[str] = None
            for nid, n in child_nodes.items():
                if n.is_entry:
                    child_root_id = nid
                    break
            if child_root_id is None and child_nodes:
                child_root_id = min(child_nodes, key=lambda k: child_nodes[k].call_seq)

            if creator_id and child_root_id:
                cn = parent_nodes[creator_id]
                cn.spawn_tid           = child_tid
                cn.spawn_child_node_id = child_root_id
                cn.spawn_child_tid     = child_tid
                cn.spawn_start_sym = CallTreeBuilder._spawn_start_label(
                    spawn_ev, child_nodes[child_root_id])

                child_root = child_nodes[child_root_id]
                child_root.spawned_by_id  = creator_id
                child_root.spawned_by_tid = parent_tid
                child_root.spawned_by_label = cn.label()
                child_root.spawn_start_label = cn.spawn_start_sym

                parent_edges.append(
                    CallEdge(creator_id, child_root_id, "spawn", parent_tid))

    @staticmethod
    def _find_spawn_creator_node(
        parent_nodes: dict[str, CallNode],
        spawn_ev: dict,
    ) -> Optional[str]:
        """스레드 생성자를 모듈+오프셋 기준으로 찾는다.

        Frida 에이전트는 Process.findModuleByAddress()로 creator_va를
        creator_module/creator_offset으로 변환해 보낸다. 여기서는 raw VA와
        module offset을 섞어 비교하지 않는다.

        우선순위:
          1. 노드의 src_module/src_offset이 생성 callsite와 정확히 일치
          2. 노드 자체 module/offset이 정확히 일치
          3. 같은 모듈에서 creator_offset 직전의 함수 entry로 추정
          4. 같은 모듈에서 가장 가까운 src_offset 또는 node offset
        """
        creator_module = str(spawn_ev.get("creator_module", "")).lower()
        creator_offset = CallTreeBuilder._hex(
            spawn_ev.get("creator_offset", "0x0"))
        if not creator_module or creator_module == "unknown":
            return None

        best: tuple[int, int, int, str] | None = None
        for idx, (nid, n) in enumerate(parent_nodes.items()):
            n_mod = (n.module or "").lower()
            src_mod = (n.src_module or "").lower()
            candidates: list[tuple[int, int]] = []

            if src_mod == creator_module:
                src_dist = abs(n.src_offset - creator_offset)
                candidates.append((0 if src_dist == 0 else 3, src_dist))
            if n_mod == creator_module:
                node_dist = abs(n.offset - creator_offset)
                if node_dist == 0:
                    candidates.append((1, 0))
                elif n.offset <= creator_offset:
                    candidates.append((2, creator_offset - n.offset))
                else:
                    candidates.append((4, node_dist))

            for rank, dist in candidates:
                score = (rank, dist, idx, nid)
                if best is None or score < best:
                    best = score

        return best[3] if best else None

    @staticmethod
    def _fallback_spawn_creator_node(
        parent_nodes: dict[str, CallNode],
        spawn_ev: dict,
    ) -> Optional[str]:
        """정확한 생성 callsite가 없을 때 탭 고립을 막는 보조 매칭."""
        if not parent_nodes:
            return None
        seq = int(spawn_ev.get("seq", 0))
        before = [
            n for n in parent_nodes.values()
            if int(getattr(n, "trace_seq", 0)) <= seq
        ]
        if before:
            return max(before, key=lambda n: n.trace_seq).node_id
        entries = [n for n in parent_nodes.values() if n.is_entry]
        if entries:
            return min(entries, key=lambda n: n.call_seq).node_id
        return min(parent_nodes.values(), key=lambda n: n.call_seq).node_id

    @staticmethod
    def _spawn_start_label(spawn_ev: dict, child_root: CallNode) -> str:
        symbol = spawn_ev.get("start_symbol", "") or ""
        module = spawn_ev.get("start_module", "") or ""
        offset = spawn_ev.get("start_offset", "") or ""
        if symbol:
            return symbol
        if module and module != "unknown" and offset:
            return "{}!{}".format(module, offset)
        return child_root.label()


class _SyntheticTraceSession:
    def __init__(self, events: list[dict]):
        self.events = events
        self.sync_events: list[dict] = []
        self.spawn_events: list[dict] = []
        self.exception_events: list[dict] = []


def _synthetic_call(seq: int, src_mod: str, src_off: str, src_sym: str,
                    dst_mod: str, dst_off: str, dst_sym: str,
                    tid: int = 1, source: str = "synthetic") -> dict:
    return {
        "type": "call",
        "thread_id": tid,
        "seq": seq,
        "src_module": src_mod,
        "src_offset": src_off,
        "src_symbol": src_sym,
        "dst_module": dst_mod,
        "dst_offset": dst_off,
        "dst_symbol": dst_sym,
        "source": source,
    }


def _synthetic_ret(seq: int, src_mod: str, src_off: str, src_sym: str,
                   dst_mod: str, dst_off: str, dst_sym: str,
                   tid: int = 1, source: str = "synthetic") -> dict:
    return {
        "type": "ret",
        "thread_id": tid,
        "seq": seq,
        "src_module": src_mod,
        "src_offset": src_off,
        "src_symbol": src_sym,
        "dst_module": dst_mod,
        "dst_offset": dst_off,
        "dst_symbol": dst_sym,
        "source": source,
    }


def _synthetic_jump(seq: int, src_mod: str, src_off: str, src_sym: str,
                    dst_mod: str, dst_off: str, dst_sym: str,
                    tid: int = 1, source: str = "synthetic") -> dict:
    ev = _synthetic_call(
        seq, src_mod, src_off, src_sym,
        dst_mod, dst_off, dst_sym,
        tid=tid, source=source)
    ev["type"] = "jump"
    ev["is_jump"] = True
    return ev


def _calltree_synthetic_snapshot(events: list[dict],
                                 target_modules: Optional[list[str]] = None,
                                 exception_events: Optional[list[dict]] = None,
                                 ) -> dict:
    session = _SyntheticTraceSession(events)
    session.exception_events = exception_events or []
    built = CallTreeBuilder(target_modules=target_modules or ["app.exe"]).build(
        session)
    nodes, edges = built.get(1, ({}, []))
    return {
        "nodes": [
            {
                "id": nid,
                "symbol": n.symbol,
                "parent": nodes[n.parent_id].symbol if n.parent_id in nodes else "",
                "depth": n.depth,
                "seq": n.trace_seq,
            }
            for nid, n in sorted(nodes.items(), key=lambda item: item[1].call_seq)
        ],
        "edges": [
            {
                "src": nodes[e.src_id].symbol if e.src_id in nodes else e.src_id,
                "dst": nodes[e.dst_id].symbol if e.dst_id in nodes else e.dst_id,
                "kind": e.kind,
            }
            for e in edges
        ],
    }


def _run_calltree_synthetic_checks() -> dict:
    """Manual diagnostic entrypoint for CallTreeBuilder parent false positives.

    Run with:
      .venv\\Scripts\\python.exe -c "import bridge_server as b; print(b._run_calltree_synthetic_checks())"
    """
    mismatch_events = [
        _synthetic_call(1, "unknown", "0x0", "", "app.exe", "0x100", "A"),
        _synthetic_call(2, "app.exe", "0x110", "A+0x10", "app.exe", "0x200", "B"),
        _synthetic_ret(3, "app.exe", "0x100", "A", "unknown", "0x0", ""),
        _synthetic_call(4, "unknown", "0x0", "", "app.exe", "0x300", "C"),
    ]
    mismatch_snapshot = _calltree_synthetic_snapshot(mismatch_events)
    c_nodes = [
        n for n in mismatch_snapshot["nodes"]
        if n["symbol"] == "C"
    ]
    c_parent = c_nodes[0]["parent"] if c_nodes else ""
    balanced_events = [
        _synthetic_call(1, "unknown", "0x0", "", "app.exe", "0x100", "A"),
        _synthetic_call(2, "app.exe", "0x110", "A+0x10", "app.exe", "0x200", "B"),
        _synthetic_ret(3, "app.exe", "0x200", "B", "app.exe", "0x118", "A+0x18"),
        _synthetic_call(4, "app.exe", "0x120", "A+0x20", "app.exe", "0x300", "C"),
    ]
    balanced_snapshot = _calltree_synthetic_snapshot(balanced_events)
    balanced_c_nodes = [
        n for n in balanced_snapshot["nodes"]
        if n["symbol"] == "C"
    ]
    balanced_c_parent = (
        balanced_c_nodes[0]["parent"] if balanced_c_nodes else ""
    )
    split_anchor_events = [
        _synthetic_call(
            1, "app.exe", "0x4a0d", "CHwpSDKSampleDlg::InsertText",
            "hwpsdk.dll", "0x1570", "HWPSDK::Document::CreateAction",
            source="target_export"),
        _synthetic_ret(
            2, "hwpsdk.dll", "0x1570", "HWPSDK::Document::CreateAction",
            "app.exe", "0x4a12", "CHwpSDKSampleDlg::InsertText+0x5"),
        _synthetic_call(
            3, "app.exe", "0x4a61", "CHwpSDKSampleDlg::InsertText",
            "hwpsdk.dll", "0x1070", "HWPSDK::Action::CreateParameterSet",
            source="target_export"),
    ]
    split_anchor_snapshot = _calltree_synthetic_snapshot(split_anchor_events)
    insert_text_nodes = [
        n for n in split_anchor_snapshot["nodes"]
        if n["symbol"] == "CHwpSDKSampleDlg::InsertText"
    ]
    tunnel_events = [
        _synthetic_call(1, "unknown", "0x0", "", "app.exe", "0x100", "A"),
        _synthetic_call(2, "app.exe", "0x110", "A+0x10",
                        "kernel32.dll", "0x500", "K32"),
        _synthetic_jump(3, "kernel32.dll", "0x500", "K32",
                        "app.exe", "0x200", "B"),
    ]
    tunnel_snapshot = _calltree_synthetic_snapshot(tunnel_events)
    tunnel_edges = tunnel_snapshot["edges"]
    ret_only_events = [
        _synthetic_call(1, "unknown", "0x0", "", "app.exe", "0x100", "A"),
        _synthetic_call(2, "app.exe", "0x110", "A+0x10",
                        "kernel32.dll", "0x500", "K32"),
        _synthetic_ret(3, "kernel32.dll", "0x500", "K32",
                       "app.exe", "0x118", "A+0x18"),
    ]
    ret_only_snapshot = _calltree_synthetic_snapshot(ret_only_events)
    exception_snapshot = _calltree_synthetic_snapshot(
        tunnel_events,
        exception_events=[{
            "seq": 2.5,
            "tid": 1,
            "address": "0xDEAD",
            "exception_type": "access-violation",
        }],
    )
    exception_tunnel_edges = exception_snapshot["edges"]
    return {
        "mismatched_ret_parent_pollution": {
            "current_c_parent": c_parent,
            "expected_after_fix": "",
            "reproduced": c_parent == "A",
            "passed": c_parent == "",
            "snapshot": mismatch_snapshot,
        },
        "balanced_nested_parent": {
            "current_c_parent": balanced_c_parent,
            "expected": "A",
            "passed": balanced_c_parent == "A",
            "snapshot": balanced_snapshot,
        },
        "target_export_anchor_merge": {
            "current_anchor_count": len(insert_text_nodes),
            "expected": 1,
            "passed": len(insert_text_nodes) == 1,
            "snapshot": split_anchor_snapshot,
        },
        "same_thread_tunnel": {
            "expected_edge": ("K32", "B", "jump"),
            "passed": any(
                e["src"] == "K32" and e["dst"] == "B"
                and e["kind"] == "jump"
                for e in tunnel_edges),
            "snapshot": tunnel_snapshot,
        },
        "ret_not_rendered": {
            "expected_node_count": 2,
            "passed": len(ret_only_snapshot["nodes"]) == 2,
            "snapshot": ret_only_snapshot,
        },
        "exception_suppresses_tunnel": {
            "expected_no_tunnel_edge": ("K32", "B"),
            "passed": not any(
                e["src"] == "K32" and e["dst"] == "B"
                for e in exception_tunnel_edges),
            "snapshot": exception_snapshot,
        },
    }


# ============================================================
# LayoutWorker
# ============================================================

def calc_node_height(n: "CallNode", all_nodes: dict[str, "CallNode"]) -> int:
    """NodeItem._calc_height()와 동일한 높이 계산 (레이아웃 공유)."""
    lines = 3  # 함수명 + 주소 + 구분선
    if n.is_external:
        lines += 1
    vis_ch = ordered_child_ids(n, all_nodes)
    if vis_ch:
        lines += len(vis_ch) + 1
    if n.spawn_tid is not None:
        lines += 1
    if n.spawned_by_id is not None:
        lines += 1
    return max(PAD * 2 + lines * LINE_H, PAD * 2 + LINE_H * 4)


def ordered_child_ids(n: "CallNode", all_nodes: dict[str, "CallNode"]) -> list[str]:
    """부모 내부 목록과 scene edge가 공유하는 하위 호출 순서."""
    child_ids = [cid for cid in n.children_ids if cid in all_nodes]
    return sorted(child_ids, key=lambda cid: all_nodes[cid].call_seq)


def child_row_anchor_y(n: "CallNode", all_nodes: dict[str, "CallNode"],
                       child_id: str) -> Optional[float]:
    """NodeItem.paint()의 하위 항목 줄 중앙 y와 같은 값을 반환."""
    children = ordered_child_ids(n, all_nodes)
    if child_id not in children:
        return None
    y = PAD
    if n.is_external:
        y += LINE_H
    y += LINE_H  # 함수명
    y += LINE_H  # 주소
    y += 6       # 구분선 여백
    y += LINE_H  # "하위/다음" 헤더
    return y + children.index(child_id) * LINE_H + LINE_H / 2.0


class LayoutWorker:
    def __init__(self, nodes: dict[str, CallNode],
                 edges: list[CallEdge], visible: set[str]):
        self._nodes   = nodes
        self._edges   = edges
        self._visible = visible

    def _compute(self) -> dict[str, tuple[float, float]]:
        # 현재 레이아웃 구현:
        #   - _visible_nodes()가 넘긴 실제 scene 노드를 배치한다.
        #   - parent_id/children_ids 트리를 기준으로 depth별 컬럼을 만들고,
        #     부모는 보이는 자식 서브트리의 수직 중앙에 둔다.
        #
        # 이 작업 이후 의도한 레이아웃:
        #   - 부모 카드 내부 하위 항목과 scene에 존재하는 child 노드의
        #     개념을 분리하지 않는다. 목록에 있는 child는 실제 scene 노드다.
        #   - edge는 부모 내부의 해당 하위 항목 줄에서 시작한다.
        #   - 하위 항목 줄 순서는 호출 순서(call_seq)이며, 이 순서가 edge
        #     anchor와 오른쪽 child 배치 순서를 함께 결정한다.
        #
        # 남은 차이:
        #   - child 노드의 y 좌표는 아직 서브트리 중심 정렬을 따른다.
        #     edge 시작점은 줄 anchor와 정확히 맞지만, 도착 노드 중심은
        #     전체 서브트리 충돌 회피를 위해 별도로 배치된다.
        vis = {nid: n for nid, n in self._nodes.items()
               if nid in self._visible}
        if not vis:
            return {}

        col_w = NODE_W + H_GAP
        positions: dict[str, tuple[float, float]] = {}

        # subtree_height: nid를 루트로 하는 서브트리 전체의 y 높이 (자식 포함)
        # 메모이제이션으로 중복 계산 방지
        _cache: dict[str, float] = {}

        def subtree_height(nid: str) -> float:
            if nid in _cache:
                return _cache[nid]
            n = vis.get(nid)
            if not n:
                _cache[nid] = 0.0
                return 0.0
            h = float(calc_node_height(n, self._nodes) + V_GAP)
            children = ordered_child_ids(n, vis)
            if children:
                ch_total = sum(subtree_height(c) for c in children)
                h = max(h, ch_total)
            _cache[nid] = h
            return h

        # place: 서브트리를 (depth, top_y) 기준으로 배치.
        # 부모 노드는 자식 서브트리 전체의 수직 중앙에 위치.
        def place(nid: str, depth: int, top_y: float):
            n = vis.get(nid)
            if not n:
                return
            children = ordered_child_ids(n, vis)

            node_h = calc_node_height(n, self._nodes)

            if not children:
                positions[nid] = (depth * col_w, top_y)
                return

            # 자식들을 depth+1 컬럼에 순서대로 배치
            child_y = top_y
            for cid in children:
                place(cid, depth + 1, child_y)
                child_y += subtree_height(cid)

            # 부모를 자식 블록의 수직 중앙에 배치
            total_children_h = child_y - top_y
            parent_y = top_y + (total_children_h - node_h) / 2.0
            positions[nid] = (depth * col_w, parent_y)

        # 최상위 루트들을 순서대로 배치
        roots = [n for n in vis.values()
                 if n.parent_id is None or n.parent_id not in vis]
        if not roots:
            # parent_id가 꼬이거나 cycle이 있으면 루트가 0개가 되어 탭이 빈
            # 화면처럼 보인다. 이 경우에도 모든 노드를 독립 root로 배치한다.
            roots = list(vis.values())
        roots.sort(key=lambda n: n.call_seq)

        cur_y = 0.0
        for root in roots:
            if root.node_id in positions:
                continue
            place(root.node_id, 0, cur_y)
            cur_y += subtree_height(root.node_id)

        # 그래도 배치되지 않은 노드는 독립 노드로 세로 배치한다.
        # partially broken trace라도 탭 내부에 내용은 반드시 보여야 한다.
        for n in sorted(vis.values(), key=lambda n: n.call_seq):
            if n.node_id in positions:
                continue
            positions[n.node_id] = (0, cur_y)
            cur_y += calc_node_height(n, self._nodes) + V_GAP

        return positions


# ============================================================
# NodeItem
# ============================================================

class NodeItem(QGraphicsItem):

    Type = QGraphicsItem.UserType + 1

    def __init__(self, node: CallNode, nodes_ref: dict[str, CallNode]):
        super().__init__()
        self._node     = node
        self._nodes    = nodes_ref
        self._searched = False
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        # 디버깅용: 레이아웃/edge anchor 문제를 눈으로 확인하기 위해
        # 노드를 직접 끌어 옮길 수 있게 한다. 이동하면 itemChange()에서
        # 연결선을 즉시 다시 계산한다.
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setAcceptHoverEvents(True)

    def type(self): return self.Type

    @property
    def node(self): return self._node

    def set_searched(self, v: bool):
        self._searched = v
        self.update()

    def _calc_height(self) -> int:
        return calc_node_height(self._node, self._nodes)

    def boundingRect(self) -> QRectF:
        return QRectF(0, 0, NODE_W, self._calc_height())

    def paint(self, painter: QPainter, option, widget=None):
        n = self._node
        h = self._calc_height()
        w = NODE_W
        sel = self.isSelected()

        # 배경색
        if n.is_entry:       bg = C_NODE_ENTRY
        elif n.is_exit:      bg = C_NODE_EXIT
        elif n.is_external:  bg = C_NODE_EXTERNAL
        else:                bg = C_NODE_BG

        # 테두리
        if sel:              border, bw = C_NODE_SEL,       2
        elif self._searched: border, bw = C_NODE_SEARCH,    2
        elif n.is_external:  border, bw = C_NODE_BORDER_EXT,1
        else:                border, bw = C_NODE_BORDER,    1

        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QBrush(bg))
        painter.setPen(QPen(border, bw))
        painter.drawRoundedRect(0, 0, w, h, 4, 4)

        y = PAD
        x = PAD

        # 외부 모듈 배지 (함수명 위)
        if n.is_external and n.module and not n.module.startswith("["):
            painter.setFont(FONT_SUB)
            painter.setPen(QPen(C_TEXT_EXT_MOD))
            mod_lbl = "[ {} ]".format(n.module)
            if len(mod_lbl) > 34:
                mod_lbl = mod_lbl[:31] + "…]"
            painter.drawText(x, y + LINE_H - 2, mod_lbl)
            y += LINE_H

        # 함수명
        painter.setFont(FONT_MAIN)
        painter.setPen(QPen(C_TEXT_FUNC))
        lbl = n.symbol if n.symbol else (
            "+{}".format(hex(n.offset)) if n.is_external else n.label())
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

        # 하위 호출 목록은 edge anchor 위치를 보여주기 위한 정적 표시다.
        # 클릭/더블클릭/펼침 동작은 노드 위치 이동 문제 때문에 제거했다.
        vis_ch = ordered_child_ids(n, self._nodes)
        if vis_ch:
            painter.setFont(FONT_SUB)
            painter.setPen(QPen(C_TEXT_SUB))
            painter.drawText(x, y + LINE_H - 2,
                             "하위/다음({})".format(len(vis_ch)))
            y += LINE_H
            painter.setFont(FONT_ADDR)
            for cid in vis_ch:
                cn = self._nodes.get(cid)
                if not cn: continue
                painter.setPen(QPen(C_TEXT_SUB))
                painter.drawText(x + 6, y + LINE_H - 2, ">")
                painter.setPen(QPen(C_TEXT_FUNC if cn.symbol else C_TEXT_ADDR))
                cl = cn.label()
                if len(cl) > 30: cl = cl[:27] + "…"
                painter.drawText(x + 20, y + LINE_H - 2, cl)
                y += LINE_H

        # spawn 링크 (스레드 생성) — 부모 노드에 표시
        footer_y = h - PAD
        if n.spawn_tid is not None:
            painter.setFont(FONT_SUB)
            painter.setPen(QPen(C_EDGE_SPAWN))
            sym = n.spawn_start_sym
            if sym and len(sym) > 22:
                sym = sym[:19] + "…"
            spawn_lbl = "⤷ Thread {} 생성".format(n.spawn_tid)
            if sym:
                spawn_lbl += "  {}".format(sym)
            painter.drawText(x, footer_y - 2, spawn_lbl)
            footer_y -= LINE_H

        # spawned by 링크 — 자식 스레드 루트 노드에 표시
        if n.spawned_by_id is not None and n.spawned_by_tid is not None:
            painter.setFont(FONT_SUB)
            painter.setPen(QPen(C_EDGE_SPAWN))
            parent_node = self._nodes.get(n.spawned_by_id)
            pname = parent_node.label() if parent_node else n.spawned_by_label
            if pname:
                if len(pname) > 20: pname = pname[:17] + "…"
                by_lbl = "⤴ Thread {} 에서 생성  {}".format(n.spawned_by_tid, pname)
            else:
                by_lbl = "⤴ Thread {} 에서 생성".format(n.spawned_by_tid)
            start_lbl = n.spawn_start_label
            if start_lbl and start_lbl != n.label():
                if len(start_lbl) > 18: start_lbl = start_lbl[:15] + "…"
                by_lbl += " -> {}".format(start_lbl)
            painter.drawText(x, footer_y - 2, by_lbl)

    def mouseDoubleClickEvent(self, event):
        scene = self.scene()
        if scene and hasattr(scene, "node_selected"):
            scene.node_selected.emit("__activate__:{}".format(self._node.node_id))
        event.accept()

    def mousePressEvent(self, event):
        super().mousePressEvent(event)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            scene = self.scene()
            if scene and hasattr(scene, "edges_update"):
                scene.edges_update()
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
        # 현재 구현:
        #   - 부모 내부 하위 항목 줄의 실제 y 좌표를 child_row_anchor_y()로
        #     계산하고, edge 시작점을 그 줄 중앙에 맞춘다.
        #
        # 원래 작동해야 하는 방식:
        #   - 하위 호출 순서가 곧 목록 줄 순서다.
        #   - 해당 순서의 줄에서 해당 child node로 선이 나가야 호출 순서를
        #     눈으로 따라갈 수 있다.
        sx = sp.x() + sr.width()
        sy = sp.y() + sr.height() / 2.0
        anchor_y = child_row_anchor_y(
            self._src.node, self._src._nodes, self._edge.dst_id)
        if anchor_y is not None:
            sy = sp.y() + anchor_y
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
            br = self.itemsBoundingRect()
            if not br.isEmpty():
                self.setSceneRect(br.adjusted(-80, -80, 80, 80))
            self.update()

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
        return item


# ============================================================
# GraphView
# ============================================================

class GraphView(QGraphicsView):

    def __init__(self, scene: GraphScene):
        super().__init__(scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self.setTransformationAnchor(
            QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(
            QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QBrush(C_BG))
        self._zoom = 1.0
        self._panning = False
        self._pan_start = QPointF()
        self._pan_h = 0
        self._pan_v = 0

    def _fit_zoom(self) -> float:
        br = self.scene().itemsBoundingRect()
        vp = self.viewport().rect()
        if br.isEmpty() or vp.isEmpty():
            return 1.0
        margin = 40.0
        w = max(br.width() + margin, 1.0)
        h = max(br.height() + margin, 1.0)
        return max(min(vp.width() / w, vp.height() / h), 0.01)

    def _min_zoom(self) -> float:
        return min(max(self._fit_zoom() / 1.5, 0.01), 8.0)

    def _set_zoom(self, zoom: float):
        zoom = max(self._min_zoom(), min(zoom, 8.0))
        self.resetTransform()
        self.scale(zoom, zoom)
        self._zoom = zoom

    def wheelEvent(self, event: QWheelEvent):
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self._set_zoom(self._zoom * factor)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.MiddleButton:
            self._panning = True
            self._pan_start = event.position()
            self._pan_h = self.horizontalScrollBar().value()
            self._pan_v = self.verticalScrollBar().value()
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._panning:
            delta = event.position() - self._pan_start
            self.horizontalScrollBar().setValue(self._pan_h - int(delta.x()))
            self.verticalScrollBar().setValue(self._pan_v - int(delta.y()))
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.MiddleButton and self._panning:
            self._panning = False
            self.unsetCursor()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def fit_all(self):
        br = self.scene().itemsBoundingRect()
        if not br.isEmpty():
            self.fitInView(br.adjusted(-20, -20, 20, 20),
                           Qt.AspectRatioMode.KeepAspectRatio)
            self._zoom = self.transform().m11()

    def focus_on(self, node_id: str, zoom: bool = False):
        item = self.scene().focus_node(node_id)
        if item:
            if zoom:
                self._set_zoom(1.6)
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
        self._edit.setMinimumWidth(80)
        self._edit.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._edit.setStyleSheet(
            "background:#FFFFFF;color:#1E293B;"
            "border:1px solid #C0C8D0;border-radius:3px;padding:2px 4px;")
        self._edit.returnPressed.connect(self._submit)
        ly.addWidget(self._edit, 1)

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
# ThreadListPanel
# ============================================================

class ThreadListPanel(QWidget):
    thread_activated = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        ly = QVBoxLayout(self)
        ly.setContentsMargins(4, 4, 4, 4)
        ly.setSpacing(4)

        lbl = QLabel("스레드")
        lbl.setStyleSheet("font-weight:bold;color:#1E293B;")
        ly.addWidget(lbl)

        self._list = QListWidget()
        self._list.setUniformItemSizes(True)
        self._list.itemDoubleClicked.connect(self._activate)
        self._list.setStyleSheet(
            "background:#FFFFFF;color:#1E293B;"
            "border:1px solid #D1D9E0;border-radius:3px;")
        ly.addWidget(self._list, 1)

    def set_threads(self, threads: list[dict], current_tid: Optional[int] = None):
        self._list.clear()
        for entry in threads:
            tid = int(entry.get("tid", 0))
            suffix = "  main" if entry.get("main") else ""
            node_count = int(entry.get("node_count", 0))
            item = QListWidgetItem(
                "TID {}{}  ({} nodes)".format(tid, suffix, node_count))
            item.setData(Qt.ItemDataRole.UserRole, tid)
            self._list.addItem(item)
        self.set_current_tid(current_tid)

    def set_current_tid(self, tid: Optional[int]):
        if tid is None:
            self._list.clearSelection()
            return
        for row in range(self._list.count()):
            item = self._list.item(row)
            if item.data(Qt.ItemDataRole.UserRole) == tid:
                self._list.setCurrentRow(row)
                self._list.scrollToItem(item)
                return

    def _activate(self, item: QListWidgetItem):
        tid = item.data(Qt.ItemDataRole.UserRole)
        if tid is None:
            return
        self.thread_activated.emit(int(tid))


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
    threads_changed = Signal(list, object)
    current_thread_changed = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._session_data: dict[int, tuple[dict, list]] = {}
        self._current_tid:  Optional[int] = None
        self._views:        dict[int, tuple[GraphScene, GraphView]] = {}
        self._symbol_resolver = None
        self._rendered_tids: set[int] = set()
        self._fit_pending_tids: set[int] = set()
        self._pending_focus: dict[int, str] = {}
        self._tab_tids: list[int] = []
        self._project_files: list[str] = []

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

        # 그래프 뷰 스택. 스레드 선택 UI는 오른쪽 ThreadListPanel에서 담당한다.
        self._tabs = QStackedWidget()
        self._tabs.setStyleSheet("""
            QStackedWidget{border:1px solid #D1D9E0;background:#F5F5F5;}
        """)
        self._tabs.currentChanged.connect(self._on_tab_changed)
        ly.addWidget(self._tabs, 1)

        # 플레이스홀더
        self._placeholder = QLabel(
            "트레이스 완료 후 그래프가 표시됩니다.\n"
            "가운데 버튼: 이동  |  마우스 휠: 확대/축소")
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._placeholder.setStyleSheet("color:#9CA3AF;font-size:13px;")
        ly.addWidget(self._placeholder)
        self._tabs.hide()

    # ── 공개 API ────────────────────────────────────────────

    def load_session(self, session):
        """TraceSession 수신 시 호출."""
        previous_tid = self._current_tid
        builder = CallTreeBuilder(self._symbol_resolver, self._project_files)
        try:
            self._session_data = builder.build(session)
        except Exception as e:
            dbg("graph build failed: {!r}".format(e))
            self._session_data = {}
        self._rendered_tids = set()
        self._fit_pending_tids = set()
        self._apply_initial_expansion()

        self._clear_graph_stack()
        self._views.clear()
        self._tab_tids = []

        if not self._session_data:
            self._current_tid = None
            self.threads_changed.emit([], None)
            self.current_thread_changed.emit(None)
            self._tabs.hide()
            self._placeholder.setText(
                "트레이스 데이터가 없습니다.\n"
                "사용자 입력 이후 실행되는 함수라면 해당 동작을 수행한 뒤 종료하세요.")
            self._placeholder.show()
            return

        self._placeholder.hide()
        self._tabs.show()

        for tid in sorted(self._session_data.keys()):
            self._add_tab(tid)

        if self._session_data:
            main_tid = self._main_tid()
            target_tid = (
                previous_tid
                if previous_tid in self._session_data
                else main_tid
            )
            self._current_tid = target_tid
            self.threads_changed.emit(self.thread_entries(), target_tid)
            self._relayout(target_tid)
            self._switch_to_tid(target_tid)

    def _clear_graph_stack(self):
        while self._tabs.count():
            widget = self._tabs.widget(0)
            self._tabs.removeWidget(widget)
            widget.setParent(None)

    def _apply_initial_expansion(self):
        """모든 노드 기본 접힘 상태. 클릭 시 오른쪽에 자식이 펼쳐짐."""
        for n_map, _ in self._session_data.values():
            for n in n_map.values():
                n.expanded = False

    def _terminal_node(self, nodes: dict[str, CallNode]) -> Optional[CallNode]:
        if not nodes:
            return None
        exits = [n for n in nodes.values() if n.is_exit]
        if exits:
            return max(exits, key=lambda n: n.call_seq)
        return max(nodes.values(), key=lambda n: n.call_seq)

    def _main_tid(self) -> int:
        # 현재 정책: 프로세스 생성 직후 가장 먼저 만들어진 스레드를 main으로 본다.
        # Windows에서는 일반적으로 메인 스레드가 가장 작은 TID를 가진다.
        #
        # 이전 구현은 "첫 trace_seq가 가장 작은 스레드"를 main으로 표시했다.
        # 그러나 Stalker attach/스케줄링 순서 때문에 실제 main보다 늦게 생성된
        # 스레드가 먼저 이벤트를 낼 수 있어, main 탭 표시가 흔들린다.
        return min(self._session_data.keys())

    def sync_from_ghidra(self, module: str, offset_hex: str, zoom: bool = False):
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
                        view.focus_on(nid, zoom=zoom)
                    return

    def goto_node_token(self, token: str, zoom: bool = False):
        self._on_goto(token, zoom=zoom)

    def select_thread(self, tid: int):
        if tid not in self._session_data:
            return
        self._switch_to_tid(tid)
        scene, _ = self._views.get(tid, (None, None))
        scene_empty = bool(scene is not None and not scene._node_items)
        if tid not in self._rendered_tids or scene_empty:
            self._relayout(tid)
        self.current_thread_changed.emit(tid)

    def thread_entries(self) -> list[dict]:
        if not self._session_data:
            return []
        main_tid = self._main_tid()
        entries: list[dict] = []
        for tid in sorted(self._session_data.keys()):
            nodes, _ = self._session_data[tid]
            entries.append({
                "tid": tid,
                "main": tid == main_tid,
                "node_count": len(nodes),
            })
        return entries

    def function_entries(self) -> list[dict]:
        counts: dict[tuple[str, str], int] = {}
        entries: list[dict] = []
        for tid, (nodes, _) in self._session_data.items():
            for nid, n in nodes.items():
                if n.module.startswith("[") or n.module == "unknown":
                    continue
                key = self._count_key(n)
                counts[key] = counts.get(key, 0) + 1
                entries.append({
                    "module": n.module,
                    "offset": hex(n.offset),
                    "src_module": n.src_module,
                    "src_offset": hex(n.src_offset),
                    "src_label": n.src_label(),
                    "tid": tid,
                    "node_id": nid,
                    "call_seq": n.call_seq,
                    "trace_seq": n.trace_seq,
                    "fallback": n.symbol,
                    "key": self._count_key(n),
                })
        for entry in entries:
            entry["count"] = counts.get(entry["key"], 1)
        entries.sort(key=lambda e: (e["trace_seq"], e["tid"], e["call_seq"]))
        return entries

    def _count_key(self, node: CallNode) -> tuple[str, str]:
        label = node.symbol or ""
        if "+" in label:
            base, delta = label.rsplit("+", 1)
            if delta.lower().startswith("0x"):
                label = base
        if not label:
            label = hex(node.offset)
        return (node.module.lower(), label.lower())

    def set_symbol_resolver(self, resolver):
        self._symbol_resolver = resolver

    def set_project_files(self, files: list[str]):
        self._project_files = list(files)

    # ── 탭 ──────────────────────────────────────────────────

    def _add_tab(self, tid: int):
        scene = GraphScene()
        view  = GraphView(scene)
        scene.node_selected.connect(
            lambda nid, t=tid: self._on_node_signal(t, nid))
        self._views[tid] = (scene, view)
        self._tab_tids.append(tid)
        self._tabs.addWidget(view)

    def _switch_to_tid(self, tid: int):
        if tid in self._tab_tids:
            self._tabs.setCurrentIndex(self._tab_tids.index(tid))
            self.current_thread_changed.emit(tid)

    # ── 레이아웃 ────────────────────────────────────────────

    def _relayout(self, tid: int, fit: bool = True):
        if tid not in self._session_data or tid not in self._views:
            return
        nodes, edges = self._session_data[tid]
        scene, view  = self._views[tid]

        visible = self._visible_nodes(nodes)

        # cross-thread spawn 자식 루트 노드를 이 탭의 씬에 포함
        extra_nodes = self._cross_thread_nodes(nodes, visible)
        if extra_nodes:
            combined_nodes = dict(nodes)
            combined_nodes.update(extra_nodes)
            combined_visible = set(visible) | set(extra_nodes.keys())
        else:
            combined_nodes  = nodes
            combined_visible = visible

        scene.rebuild(combined_nodes, edges, combined_visible)
        if fit:
            self._fit_pending_tids.add(tid)

        positions = LayoutWorker(combined_nodes, edges, combined_visible)._compute()
        self._apply_layout(tid, scene, view, positions)

    def _apply_layout(self, tid: int, scene: GraphScene, view: GraphView,
                      pos: dict[str, tuple[float, float]]):
        self._rendered_tids.add(tid)
        scene.apply_positions(pos)
        if tid in self._fit_pending_tids:
            view.fit_all()
            self._fit_pending_tids.discard(tid)
        if tid in self._pending_focus:
            view.focus_on(self._pending_focus.pop(tid))

    def _visible_nodes(self, nodes: dict[str, CallNode]) -> set[str]:
        # 현재 구현:
        #   - 이 스레드의 모든 CallNode를 실제 QGraphicsScene 노드로 만든다.
        #   - 따라서 부모 NodeItem 안의 하위 항목 목록과 scene에 존재하는
        #     child 노드의 개념이 같다.
        #   - expanded는 더 이상 "scene에 존재하는지"를 결정하지 않고,
        #     사용자가 어떤 노드를 열어 보려 했는지 표시/상호작용 상태에 가깝다.
        #
        # 원래 작동해야 하는 방식:
        #   - 모든 하위 호출은 expand/focus 가능한 실제 노드다.
        #   - 부모 내부 목록은 실제 노드의 요약 목록일 뿐, 별도의 텍스트 전용
        #     항목이어서는 안 된다.
        #   - edge는 부모 내부 목록 줄 위치에서 시작해 같은 child 노드로 향한다.
        #
        # 디버깅 효과:
        #   - root 판정이 잘못되어도 탭이 빈 scene으로 보이지 않는다.
        #   - 노드 드래그를 켜 두었으므로, 호출 순서/edge anchor 문제를 직접
        #     움직여 확인할 수 있다.
        return set(nodes.keys())

    def _cross_thread_nodes(self, nodes: dict[str, CallNode],
                            visible: set[str]) -> dict[str, CallNode]:
        """visible 노드 중 spawn_child를 가진 것의 자식 스레드 루트 노드 수집.
        반환: {child_node_id: CallNode} (다른 스레드 소속)
        """
        extra: dict[str, CallNode] = {}
        for nid in visible:
            n = nodes.get(nid)
            if not n or n.spawn_child_node_id is None or n.spawn_child_tid is None:
                continue
            child_nodes, _ = self._session_data.get(n.spawn_child_tid, ({}, []))
            child_nid = n.spawn_child_node_id
            if child_nid in child_nodes:
                extra[child_nid] = child_nodes[child_nid]
        return extra

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
        if idx < len(self._tab_tids):
            self._current_tid = self._tab_tids[idx]
            self.current_thread_changed.emit(self._current_tid)
            scene, _ = self._views.get(self._current_tid, (None, None))
            scene_empty = bool(scene is not None and not scene._node_items)
            if self._current_tid not in self._rendered_tids or scene_empty:
                self._relayout(self._current_tid)

    def _on_node_signal(self, tid: int, signal: str):
        """씬에서 오는 node_selected 시그널 처리."""
        if signal.startswith("__activate__:"):
            inner = signal[len("__activate__:"):]
            if inner.startswith("__spawn__:"):
                # spawn 링크 클릭 → 자식 스레드 탭으로 이동
                try:
                    child_tid = int(inner[len("__spawn__:"):])
                    self._switch_to_tid(child_tid)
                except ValueError:
                    pass
            elif inner.startswith("__spawned_by__:"):
                # spawned_by 링크 클릭 → 부모 스레드 탭으로 이동
                try:
                    parent_tid = int(inner[len("__spawned_by__:"):])
                    self._switch_to_tid(parent_tid)
                except ValueError:
                    pass
            else:
                node_id = inner
                # cross-thread 노드일 수도 있으므로 전체 탭에서 검색
                n = None
                found_tid = tid
                current_nodes, _ = self._session_data.get(tid, ({}, []))
                if node_id in current_nodes:
                    n = current_nodes[node_id]
                else:
                    for t, (ns, _) in self._session_data.items():
                        if node_id in ns:
                            n = ns[node_id]
                            found_tid = t
                            break
                if n and not n.module.startswith("["):
                    if found_tid != self._current_tid:
                        self._switch_to_tid(found_tid)
                    if found_tid in self._views:
                        _, view = self._views[found_tid]
                        view.focus_on(node_id)
                    self.sync_requested.emit(n.module, hex(n.offset))
        else:
            return

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

    def _on_goto(self, node_id: str, zoom: bool = False):
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
            view.focus_on(node_id, zoom=zoom)

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
    """Frida가 Process.findModuleByAddress()로 기록한 모듈명을 우선 사용한다."""
    out:  list[dict] = []
    for ev in raw_events:
        seq    = ev["seq"]
        src_va = int(ev["src"], 16)
        dst_va = int(ev["dst"], 16)
        raw_kind = ev["k"]
        kind   = "call" if raw_kind == 0 else "ret" if raw_kind == 1 else "jump"
        tid    = ev["tid"]

        sm = ev.get("src_module", "")
        if sm and sm != "unknown":
            sm = ev.get("src_module", sm)
            so = CallTreeBuilder._hex(ev.get("src_offset", "0x0"))
        else:
            sm, so = "unknown", src_va

        dm = ev.get("dst_module", "")
        if dm and dm != "unknown":
            dm = ev.get("dst_module", dm)
            do = CallTreeBuilder._hex(ev.get("dst_offset", "0x0"))
        else:
            dm, do = "unknown", dst_va

        out.append({"src_module": sm, "src_offset": hex(so),
                    "dst_module": dm, "dst_offset": hex(do),
                    "src_symbol": ev.get("src_symbol", ""),
                    "dst_symbol": ev.get("dst_symbol", ""),
                    "dst_is_external": bool(ev.get("dst_is_external", False)),
                    "src_tt": bool(ev.get("src_tt", False)),
                    "dst_tt": bool(ev.get("dst_tt", False)),
                    "is_jump": bool(ev.get("is_jump", False)),
                    "source": ev.get("source", ""),
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


def _normalized_path(path: str) -> str:
    try:
        return os.path.normcase(os.path.realpath(path))
    except Exception:
        return os.path.normcase(os.path.abspath(path))


def process_image_path(pid: int) -> str:
    if os.name != "nt":
        return ""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(
            handle, 0, buf, ctypes.byref(size)):
            return ""
        return buf.value
    finally:
        kernel32.CloseHandle(handle)


def terminate_process_if_image_matches(pid: int, expected_path: str) -> bool:
    if os.name != "nt" or not pid or not expected_path:
        return False
    actual_path = process_image_path(pid)
    if not actual_path:
        dbg("target kill skipped: pid={} image query failed".format(pid))
        return False
    if _normalized_path(actual_path) != _normalized_path(expected_path):
        dbg("target kill skipped: pid={} image mismatch actual={}".format(
            pid, actual_path))
        return False

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    PROCESS_TERMINATE = 0x0001
    handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not handle:
        dbg("target kill failed: pid={} open terminate failed".format(pid))
        return False
    try:
        ok = bool(kernel32.TerminateProcess(handle, 1))
        dbg("target kill {}: pid={}".format("ok" if ok else "failed", pid))
        return ok
    finally:
        kernel32.CloseHandle(handle)


# ============================================================
# Shared memory trace ABI (Task #9)
# ============================================================

SHM_MAGIC = 0x46445348  # FDSH
SHM_VERSION = 1
SHM_HEADER_SIZE = 0x100
SHM_MODULE_RECORD_SIZE = 48
SHM_EVENT_RECORD_SIZE = 64
SHM_DEFAULT_RECORD_CAPACITY = 65536
SHM_DEFAULT_CALLOUT_ARENA_SIZE = 4 * 1024 * 1024

SHM_STATE_CONFIG_READY = 1
SHM_STATE_STOP_REQUESTED = 5

SHM_COMMAND_NONE = 0
SHM_COMMAND_STOP = 1

SHM_FLAG_BLOCK_ON_FULL = 1 << 0
SHM_FLAG_DOUBLE_BUFFERING = 1 << 1
SHM_FLAG_WAKE_ON_HIGH_WATERMARK = 1 << 2

SHM_HEADER_OFFSETS = {
    "state": 0x08,
    "command": 0x0C,
    "config_flags": 0x10,
    "main_pid": 0x18,
    "main_tid": 0x1C,
    "write_index": 0x28,
    "read_index": 0x30,
    "dropped_count": 0x38,
    "record_size": 0x40,
    "record_capacity": 0x44,
    "module_table_offset": 0x48,
    "module_count": 0x4C,
    "module_record_size": 0x50,
    "function_bitmap_offset": 0x54,
    "function_bitmap_size": 0x58,
    "callout_arena_offset": 0x5C,
    "callout_arena_size": 0x60,
    "callout_arena_write_offset": 0x64,
    "event_ring0_offset": 0x68,
    "event_ring1_offset": 0x78,
    "active_write_buffer": 0x7C,
    "active_read_buffer": 0x80,
    "high_watermark_percent": 0x84,
    "wake_event_signal_count": 0x88,
    "blocking_wait_count": 0x90,
}


def _align(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _parse_hex_int(value: object) -> Optional[int]:
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return None


def _stable_name_hash(name: str) -> int:
    h = 2166136261
    normalized = str(name or "").lower().replace("\\", "/").split("/")[-1]
    for ch in normalized.encode("utf-8", "ignore"):
        h ^= ch
        h = (h * 16777619) & 0xFFFFFFFF
    return h


class _WindowsEvent:
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102

    def __init__(self, name: str):
        self.name = name
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.CreateEventW.argtypes = [
            wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        self._kernel32.CreateEventW.restype = wintypes.HANDLE
        self._kernel32.SetEvent.argtypes = [wintypes.HANDLE]
        self._kernel32.SetEvent.restype = wintypes.BOOL
        self._kernel32.WaitForSingleObject.argtypes = [
            wintypes.HANDLE, wintypes.DWORD]
        self._kernel32.WaitForSingleObject.restype = wintypes.DWORD
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._handle = self._kernel32.CreateEventW(
            None, False, False, self.name)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def signal(self) -> None:
        if not self._kernel32.SetEvent(self._handle):
            raise ctypes.WinError(ctypes.get_last_error())

    def wait(self, timeout_ms: int) -> bool:
        rv = self._kernel32.WaitForSingleObject(self._handle, timeout_ms)
        if rv == self.WAIT_OBJECT_0:
            return True
        if rv == self.WAIT_TIMEOUT:
            return False
        raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


class SharedTraceMemory:
    def __init__(
        self,
        main_pid: int,
        main_tid: int,
        target_configs: Optional[list[dict]] = None,
        *,
        record_capacity: int = SHM_DEFAULT_RECORD_CAPACITY,
        blocking: bool = False,
        double_buffering: bool = True,
        high_watermark_percent: int = 80,
    ):
        self.main_pid = int(main_pid)
        self.main_tid = int(main_tid)
        self.target_configs = target_configs or []
        self.record_capacity = int(record_capacity)
        self.high_watermark_percent = int(high_watermark_percent)
        self.config_flags = SHM_FLAG_WAKE_ON_HIGH_WATERMARK
        if blocking:
            self.config_flags |= SHM_FLAG_BLOCK_ON_FULL
        if double_buffering:
            self.config_flags |= SHM_FLAG_DOUBLE_BUFFERING
        nonce = uuid.uuid4().hex
        self.name = "Local\\frida_delta_{}_{}".format(self.main_pid, nonce)
        self.wake_event_name = self.name + "_wake"
        self._wake_event = _WindowsEvent(self.wake_event_name)
        self._layout = self._build_layout()
        self.size = self._layout["total_size"]
        self._map = mmap.mmap(-1, self.size, tagname=self.name)
        self._initialize()

    def close(self) -> None:
        try:
            self._map.close()
        finally:
            self._wake_event.close()

    def bootstrap_values(self) -> dict[str, object]:
        return {
            "FRIDA_DELTA_SHM_NAME": self.name,
            "FRIDA_DELTA_SHM_SIZE": self.size,
            "FRIDA_DELTA_WAKE_EVENT_NAME": self.wake_event_name,
            "FRIDA_DELTA_MAIN_PID": self.main_pid,
            "FRIDA_DELTA_MAIN_TID": self.main_tid,
        }

    def request_stop(self) -> None:
        self._write_u32("command", SHM_COMMAND_STOP)
        self._write_u32("state", SHM_STATE_STOP_REQUESTED)
        self._wake_event.signal()

    def wait_for_wakeup(self, timeout_ms: int = 100) -> bool:
        return self._wake_event.wait(timeout_ms)

    def write_synthetic_event(
        self, kind: int, tid: int, seq: int, src: int, dst: int,
        flags: int = 0, aux0: int = 0, aux1: int = 0, aux2: int = 0,
    ) -> None:
        read_index = self._read_u64("read_index")
        write_index = self._read_u64("write_index")
        if write_index - read_index >= self.record_capacity:
            self._write_u64("dropped_count", self._read_u64("dropped_count") + 1)
            if self.config_flags & SHM_FLAG_BLOCK_ON_FULL:
                self._write_u64(
                    "blocking_wait_count",
                    self._read_u64("blocking_wait_count") + 1)
            return

        slot = write_index % self.record_capacity
        base = self._event_ring_offset() + slot * SHM_EVENT_RECORD_SIZE
        struct.pack_into(
            "<HHIQQQQQQ", self._map, base,
            int(kind) & 0xFFFF,
            int(flags) & 0xFFFF,
            int(tid) & 0xFFFFFFFF,
            int(seq) & 0xFFFFFFFFFFFFFFFF,
            int(src) & 0xFFFFFFFFFFFFFFFF,
            int(dst) & 0xFFFFFFFFFFFFFFFF,
            int(aux0) & 0xFFFFFFFFFFFFFFFF,
            int(aux1) & 0xFFFFFFFFFFFFFFFF,
            int(aux2) & 0xFFFFFFFFFFFFFFFF,
        )
        struct.pack_into("<Q", self._map, base + 0x38, 0)
        self._write_u64("write_index", write_index + 1)
        if write_index + 1 - read_index >= self._high_watermark_count():
            self._write_u64(
                "wake_event_signal_count",
                self._read_u64("wake_event_signal_count") + 1)
            self._wake_event.signal()

    def drain_events(self) -> list[dict]:
        out: list[dict] = []
        read_index = self._read_u64("read_index")
        write_index = self._read_u64("write_index")
        while read_index < write_index:
            slot = read_index % self.record_capacity
            base = self._event_ring_offset() + slot * SHM_EVENT_RECORD_SIZE
            kind, flags, tid, seq, src, dst, aux0, aux1, aux2 = (
                struct.unpack_from("<HHIQQQQQQ", self._map, base))
            if kind <= 2:
                out.append({
                    "k": int(kind),
                    "src": "0x{:X}".format(src),
                    "dst": "0x{:X}".format(dst),
                    "tid": int(tid),
                    "seq": int(seq),
                    "src_tt": bool(flags & 0x1),
                    "dst_tt": bool(flags & 0x2),
                    "is_jump": bool(flags & 0x4),
                    "source": "shared_memory",
                })
            read_index += 1
        self._write_u64("read_index", read_index)
        return out

    def _build_layout(self) -> dict[str, int]:
        module_count = len(self.target_configs)
        module_table_offset = SHM_HEADER_SIZE
        module_table_size = module_count * SHM_MODULE_RECORD_SIZE
        function_bitmap_offset = _align(module_table_offset + module_table_size)
        function_bitmap_size = self._function_bitmap_size()
        callout_arena_offset = _align(function_bitmap_offset + function_bitmap_size)
        event_ring0_offset = _align(
            callout_arena_offset + SHM_DEFAULT_CALLOUT_ARENA_SIZE)
        ring_size = self.record_capacity * SHM_EVENT_RECORD_SIZE
        event_ring1_offset = _align(event_ring0_offset + ring_size)
        total_size = _align(event_ring1_offset + ring_size)
        return {
            "module_table_offset": module_table_offset,
            "module_count": module_count,
            "function_bitmap_offset": function_bitmap_offset,
            "function_bitmap_size": function_bitmap_size,
            "callout_arena_offset": callout_arena_offset,
            "event_ring0_offset": event_ring0_offset,
            "event_ring1_offset": event_ring1_offset,
            "total_size": total_size,
        }

    def _function_bitmap_size(self) -> int:
        total = 0
        for cfg in self.target_configs:
            max_offset = 0
            for off_text in cfg.get("function_starts", []) or []:
                offset = _parse_hex_int(off_text)
                if offset is not None:
                    max_offset = max(max_offset, offset)
            total += max(1, (max_offset + 8) // 8)
        return _align(total)

    def _initialize(self) -> None:
        self._map[:] = b"\x00" * self.size
        struct.pack_into("<IHH", self._map, 0, SHM_MAGIC, SHM_VERSION, SHM_HEADER_SIZE)
        self._write_u32("state", SHM_STATE_CONFIG_READY)
        self._write_u32("command", SHM_COMMAND_NONE)
        self._write_u32("config_flags", self.config_flags)
        self._write_u32("main_pid", self.main_pid)
        self._write_u32("main_tid", self.main_tid)
        self._write_u32("record_size", SHM_EVENT_RECORD_SIZE)
        self._write_u32("record_capacity", self.record_capacity)
        self._write_u32("module_table_offset", self._layout["module_table_offset"])
        self._write_u32("module_count", self._layout["module_count"])
        self._write_u32("module_record_size", SHM_MODULE_RECORD_SIZE)
        self._write_u32("function_bitmap_offset", self._layout["function_bitmap_offset"])
        self._write_u32("function_bitmap_size", self._layout["function_bitmap_size"])
        self._write_u32("callout_arena_offset", self._layout["callout_arena_offset"])
        self._write_u32("callout_arena_size", SHM_DEFAULT_CALLOUT_ARENA_SIZE)
        self._write_u32("event_ring0_offset", self._layout["event_ring0_offset"])
        self._write_u32("event_ring1_offset", self._layout["event_ring1_offset"])
        self._write_u32("active_write_buffer", 0)
        self._write_u32("active_read_buffer", 0)
        self._write_u32("high_watermark_percent", self.high_watermark_percent)
        self._write_module_table()

    def _write_module_table(self) -> None:
        table = self._layout["module_table_offset"]
        bitmap_cursor = self._layout["function_bitmap_offset"]
        for i, cfg in enumerate(self.target_configs):
            starts = cfg.get("function_starts", []) or []
            max_offset = 0
            parsed_offsets: list[int] = []
            for off_text in starts:
                offset = _parse_hex_int(off_text)
                if offset is None:
                    continue
                parsed_offsets.append(offset)
                max_offset = max(max_offset, offset)
            bit_count = max_offset + 1 if parsed_offsets else 0
            byte_count = max(1, (max_offset + 8) // 8)
            for offset in parsed_offsets:
                byte_index = bitmap_cursor + (offset >> 3)
                value = self._map[byte_index]
                self._map[byte_index] = value | (1 << (offset & 7))
            base = table + i * SHM_MODULE_RECORD_SIZE
            struct.pack_into(
                "<QQIIIIQQ", self._map, base,
                0, 0,
                _stable_name_hash(cfg.get("name", "")),
                1 if cfg.get("trace", True) else 0,
                bitmap_cursor,
                bit_count,
                0, 0,
            )
            bitmap_cursor += _align(byte_count)

    def _event_ring_offset(self) -> int:
        active = self._read_u32("active_read_buffer")
        if active == 1:
            return self._layout["event_ring1_offset"]
        return self._layout["event_ring0_offset"]

    def _high_watermark_count(self) -> int:
        return max(1, self.record_capacity * self.high_watermark_percent // 100)

    def _read_u32(self, field: str) -> int:
        return struct.unpack_from("<I", self._map, SHM_HEADER_OFFSETS[field])[0]

    def _read_u64(self, field: str) -> int:
        return struct.unpack_from("<Q", self._map, SHM_HEADER_OFFSETS[field])[0]

    def _write_u32(self, field: str, value: int) -> None:
        struct.pack_into("<I", self._map, SHM_HEADER_OFFSETS[field], int(value))

    def _write_u64(self, field: str, value: int) -> None:
        struct.pack_into("<Q", self._map, SHM_HEADER_OFFSETS[field], int(value))


def _run_shared_memory_synthetic_checks() -> str:
    shm = SharedTraceMemory(
        main_pid=os.getpid(),
        main_tid=1,
        target_configs=[{
            "name": "sample.exe",
            "trace": True,
            "function_starts": ["0x10", "0x20"],
        }],
        record_capacity=4,
    )
    try:
        shm.write_synthetic_event(0, 11, 0, 0x1000, 0x2000, flags=0x3)
        events = shm.drain_events()
        assert len(events) == 1
        assert events[0]["k"] == 0
        assert events[0]["src"] == "0x1000"
        assert events[0]["dst_tt"] is True
        shm.request_stop()
        assert shm.wait_for_wakeup(1000) is True
        return "OK shared memory synthetic checks"
    finally:
        shm.close()


# ============================================================
# TraceSession
# ============================================================

class TraceSession:
    def __init__(self):
        self.session_id    = str(uuid.uuid4())
        self.events:       list[dict] = []
        self.raw_events:   list[dict] = []
        self.mod_events:   list[dict] = []
        self.sync_events:  list[dict] = []
        self.spawn_events: list[dict] = []
        self.handle_events: list[dict] = []
        self.exception_events: list[dict] = []
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
            "mod_events":   self.mod_events,
            "sync_events":  self.sync_events,
            "spawn_events": self.spawn_events,
            "handle_events": self.handle_events,
            "exception_events": self.exception_events,
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
        s.mod_events   = d.get("mod_events", [])
        s.sync_events  = d.get("sync_events", [])
        s.spawn_events = d.get("spawn_events", [])
        s.handle_events = d.get("handle_events", [])
        s.exception_events = d.get("exception_events", [])
        s.modules      = d.get("modules", [])
        s.reason       = d.get("reason", "loaded")
        s.saved        = True
        s.build_graph()
        return s

    @staticmethod
    def _event_for_save(ev: dict) -> dict:
        return dict(ev)


# ============================================================
# Frida 워커
# ============================================================

class FridaWorker(QObject):
    status_changed = Signal(str)
    trace_complete = Signal(TraceSession)
    error_occurred = Signal(str)
    target_spawned = Signal(int, str)
    finished = Signal()

    def __init__(
        self,
        target_path: str,
        project_files: list[str],
        target_configs: Optional[list[dict]] = None,
    ):
        super().__init__()
        self._target        = target_path
        self._project_files = project_files
        self._target_configs = target_configs or []
        self._session       = None
        self._script        = None
        self._pid           = None
        self._done          = False
        self._stopping      = False
        self._finished      = False
        self._detached      = False
        self._resumed       = False
        self._trace_done_event = threading.Event()
        self._chunk_lock    = threading.Lock()
        self._chunk_events: list[dict] = []
        self._chunk_mod_events: list[dict] = []
        self._chunk_sync_events: list[dict] = []
        self._chunk_spawn_events: list[dict] = []
        self._chunk_handle_events: list[dict] = []
        self._chunk_exception_events: list[dict] = []
        self._session_id: Optional[str] = None
        self._shared_trace: Optional[SharedTraceMemory] = None

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
            self.target_spawned.emit(int(self._pid), self._target)
            initial_tids  = enumerate_process_threads(self._pid)
            main_tid = initial_tids[0] if initial_tids else 0
            self._shared_trace = SharedTraceMemory(
                int(self._pid), int(main_tid), self._target_configs)
            dbg("shared trace created: name={} wake={} size={}".format(
                self._shared_trace.name,
                self._shared_trace.wake_event_name,
                self._shared_trace.size))
            dbg("frida.attach begin: pid={}".format(self._pid))
            self._session = frida.attach(self._pid)
            self._session.on("detached", self._on_detached)
            dbg("frida.attach ok: pid={}".format(self._pid))
            self._script  = self._session.create_script(src)
            self._script.on("message", self._on_msg)
            dbg("script.load begin")
            self._script.load()
            dbg("script.load ok")
            if self._target_configs:
                dbg("set_target_config begin: count={}".format(
                    len(self._target_configs)))
                self._script.exports_sync.set_target_config(
                    self._target_configs)
                dbg("set_target_config ok")
            elif self._project_files:
                dbg("set_targets begin: count={}".format(len(self._project_files)))
                self._script.exports_sync.set_targets(self._project_files)
                dbg("set_targets ok")
            dbg("start_trace rpc begin before resume: tids={}".format(initial_tids))
            self._script.exports_sync.start_trace(initial_tids)
            dbg("start_trace rpc ok before resume")
            dbg("frida.resume begin: pid={}".format(self._pid))
            frida.resume(self._pid)
            resumed = True
            self._resumed = True
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
        if self._shared_trace:
            try:
                self._shared_trace.request_stop()
                dbg("shared trace stop requested")
            except Exception as e:
                dbg("shared trace stop request failed: {!r}".format(e))

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
                self.status_changed.emit("stop RPC 지연 - 계측만 분리")
            elif errors and not self._done:
                self.status_changed.emit("stop: {}".format(errors[0]))
            else:
                dbg("waiting trace_complete after stop rpc")
                if self._trace_done_event.wait(timeout=1.0):
                    dbg("trace_complete received after stop rpc")
                else:
                    dbg("trace_complete wait timeout after stop rpc")

        if not self._done:
            if self._has_cached_payload():
                dbg("finalize from cached chunks after stop fallback")
                self._done = True
                self._trace_done_event.set()
                self.trace_complete.emit(self._build_session("user_stop"))
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
                if self._resumed:
                    self.status_changed.emit(
                        "Frida 오류 - 대상 프로세스는 계속 실행 중")
                    self._pid = None
                else:
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
        if self._has_cached_payload():
            dbg("finalize from cached chunks after detach")
            self._done = True
            self._trace_done_event.set()
            self.trace_complete.emit(self._build_session("detached"))
        self._cleanup()
        self._finish()

    def _has_cached_payload(self) -> bool:
        with self._chunk_lock:
            return bool(
                self._chunk_events
                or self._chunk_mod_events
                or self._chunk_sync_events
                or self._chunk_spawn_events
                or self._chunk_handle_events
                or self._chunk_exception_events
            )

    def _append_trace_payload(self, pl: dict):
        with self._chunk_lock:
            self._session_id = pl.get("session_id", self._session_id)
            sent_at_ms = pl.get("sent_at_ms")
            if sent_at_ms is None:
                sent_at_ms = int(time.time() * 1000)
            for key in (
                "events", "mod_events", "sync_events",
                "spawn_events", "handle_events", "exception_events"):
                for ev in pl.get(key, []):
                    if isinstance(ev, dict) and "sent_at_ms" not in ev:
                        ev["sent_at_ms"] = sent_at_ms
            self._chunk_events.extend(pl.get("events", []))
            self._chunk_mod_events.extend(pl.get("mod_events", []))
            self._chunk_sync_events.extend(pl.get("sync_events", []))
            self._chunk_spawn_events.extend(pl.get("spawn_events", []))
            self._chunk_handle_events.extend(pl.get("handle_events", []))
            self._chunk_exception_events.extend(
                pl.get("exception_events", []))
            dbg("chunk cache totals raw:{} mod:{} sync:{} spawn:{} handle:{} exception:{}".format(
                len(self._chunk_events),
                len(self._chunk_mod_events),
                len(self._chunk_sync_events),
                len(self._chunk_spawn_events),
                len(self._chunk_handle_events),
                len(self._chunk_exception_events)))

    def _build_session(self, reason: str) -> TraceSession:
        with self._chunk_lock:
            raw = list(self._chunk_events)
            mods = list(self._chunk_mod_events)
            sync_events = list(self._chunk_sync_events)
            spawn_events = list(self._chunk_spawn_events)
            handle_events = list(self._chunk_handle_events)
            exception_events = list(self._chunk_exception_events)
            session_id = self._session_id

        evs = postprocess(raw, mods)
        names = sorted({e["name"] for e in mods if e["action"] == "load"})

        sess = TraceSession()
        if session_id:
            sess.session_id = session_id
        sess.raw_events = raw
        sess.events = evs
        sess.mod_events = mods
        sess.sync_events = sync_events
        sess.spawn_events = spawn_events
        sess.handle_events = handle_events
        sess.exception_events = exception_events
        sess.modules = names
        sess.reason = reason
        sess.build_graph()
        return sess

    def _cleanup(self):
        dbg("cleanup begin")
        if self._shared_trace:
            try:
                dbg("shared trace close begin")
                self._shared_trace.close()
                dbg("shared trace close ok")
            except Exception as e:
                dbg("shared trace close exception: {!r}".format(e))
            finally:
                self._shared_trace = None
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
# Ghidra Script TCP 클라이언트
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
        self._connect_enabled = True
        self._project_files: set[str] = set()
        self._symbol_cache: dict[str, list[dict]] = {}

        # RPC 요청-응답: req_id → (threading.Event, result_list)
        self._rpc: dict[str, tuple[threading.Event, list]] = {}
        self._rpc_lock = threading.Lock()

    def run_server(self):
        self._running = True
        self.status_changed.emit(
            "Ghidra 연결 대기: {}:{}".format(GHIDRA_SERVER_HOST, GHIDRA_SERVER_PORT))
        while self._running:
            if not self._connect_enabled:
                time.sleep(0.2)
                continue
            try:
                conn = socket.create_connection(
                    (GHIDRA_SERVER_HOST, GHIDRA_SERVER_PORT), timeout=2.0)
            except Exception:
                if self._running:
                    time.sleep(0.5)
                continue
            self._handle(conn, (GHIDRA_SERVER_HOST, GHIDRA_SERVER_PORT))
            if self._running:
                time.sleep(0.5)

    def _handle(self, conn: socket.socket, addr):
        buf = ""
        try:
            conn.settimeout(5.0)
            self._send(conn, {"type": "connect", "client": "frida",
                              "version": "1.0"})
            while "\n" not in buf:
                c = conn.recv(4096)
                if not c: return
                buf += c.decode("utf-8", errors="replace")
            line, buf = buf.split("\n", 1)
            msg = json.loads(line.strip())
            if not (msg.get("type") == "connect_ack"
                    and msg.get("status") == "ok"):
                return

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
            try: self._send(conn, {"type": "disconnect", "client": "frida"})
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

    def target_function_configs(self, modules: list[str]) -> list[dict]:
        configs: list[dict] = []
        for mod in modules:
            symbols = self._symbols_for_module_no_timeout(mod, refresh=True)
            configs.append({
                "name": mod,
                "trace": True,
                "function_starts": [
                    str(sym.get("offset", ""))
                    for sym in symbols
                    if sym.get("offset", "")
                ],
            })
        return configs

    def _symbols_for_module_no_timeout(
        self, mod: str, refresh: bool,
    ) -> list[dict]:
        key = self._module_key(mod)
        if not refresh and key in self._symbol_cache:
            return self._symbol_cache[key]
        rsp = self.ghidra_rpc("symbols", {"module": mod}, timeout=None)
        symbols: list[dict] = []
        if rsp and rsp.get("ok"):
            result = rsp.get("result", {})
            symbols = result.get("symbols", []) if isinstance(result, dict) else []
        symbols.sort(key=lambda s: self._safe_int(s.get("offset", "0x0")))
        self._symbol_cache[key] = symbols
        return symbols

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
                   timeout: Optional[float] = 30.0) -> Optional[dict]:
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
            try: self._send(conn, {"type": "disconnect", "client": "frida"})
            except: pass
            try: conn.close()
            except: pass

    def disconnect_ghidra(self, pause: bool = False):
        if pause:
            self._connect_enabled = False
        with self._lock: conn = self._conn
        if conn:
            try: self._send(conn, {"type": "disconnect", "client": "frida"})
            except: pass
            try: conn.close()
            except: pass
        if pause:
            self.status_changed.emit("Ghidra 연결 대기 해제")

    def resume_ghidra(self):
        self._connect_enabled = True
        self.status_changed.emit(
            "Ghidra 연결 대기: {}:{}".format(GHIDRA_SERVER_HOST, GHIDRA_SERVER_PORT))

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
        self._settings = QSettings("frida_delta", "frida_delta")
        ly = QVBoxLayout(self)
        ly.setContentsMargins(4, 4, 4, 4)

        split = QSplitter(Qt.Orientation.Vertical)
        split.setChildrenCollapsible(True)
        split.setStyleSheet("QSplitter::handle{background:#D1D9E0;height:2px;}")

        target_box = QWidget()
        target_ly = QVBoxLayout(target_box)
        target_ly.setContentsMargins(0, 0, 0, 0)
        target_ly.setSpacing(4)
        lbl = QLabel("타겟 모듈")
        lbl.setStyleSheet("font-weight:bold;color:#1E293B;")
        target_ly.addWidget(lbl)

        self._list = QTreeWidget()
        self._list.setHeaderLabels(["모듈", "trace"])
        self._list.setRootIsDecorated(False)
        self._list.setAlternatingRowColors(True)
        self._list.setStyleSheet(
            "background:#FFFFFF;color:#1E293B;"
            "border:1px solid #D1D9E0;border-radius:3px;"
            "QHeaderView::section{background:#EEF2F7;color:#1E293B;"
            "border:none;padding:3px;font-weight:bold;}")
        self._list.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self._list.customContextMenuRequested.connect(self._ctx)
        target_ly.addWidget(self._list)
        split.addWidget(target_box)

        loaded_box = QWidget()
        loaded_ly = QVBoxLayout(loaded_box)
        loaded_ly.setContentsMargins(0, 0, 0, 0)
        loaded_ly.setSpacing(4)
        sep = QLabel("로드된 모듈")
        sep.setStyleSheet("font-weight:bold;color:#1E293B;margin-top:6px;")
        loaded_ly.addWidget(sep)

        self._loaded = QListWidget()
        self._loaded.setStyleSheet(
            "background:#FAFAFA;color:#6B7280;"
            "border:1px solid #D1D9E0;border-radius:3px;")
        loaded_ly.addWidget(self._loaded)
        split.addWidget(loaded_box)
        split.setSizes([320, 240])
        ly.addWidget(split, 1)

        self._stop_btn = QPushButton("■  트레이스 강제 종료")
        self._stop_btn.setEnabled(False)
        self._stop_btn.setStyleSheet(
            "QPushButton{background:#DC2626;color:white;"
            "border:none;border-radius:3px;padding:5px;}"
            "QPushButton:disabled{background:#CBD5E1;color:#64748B;}")
        self._stop_btn.clicked.connect(self.stop_trace_requested)
        ly.addWidget(self._stop_btn)

    def set_project_files(self, files: list[str]):
        self._list.clear()
        for f in sorted(files):
            item = QTreeWidgetItem([f, ""])
            item.setData(0, Qt.ItemDataRole.UserRole, f)
            item.setCheckState(1, Qt.CheckState.Checked)
            item.setFlags(item.flags() 
                        | Qt.ItemFlag.ItemIsUserCheckable 
                        | Qt.ItemFlag.ItemIsEnabled 
                        | Qt.ItemFlag.ItemIsSelectable)
            if f.lower().endswith(".exe"):
                item.setForeground(0, Qt.GlobalColor.cyan)
            self._list.addTopLevelItem(item)
        self._list.resizeColumnToContents(0)
        self._list.resizeColumnToContents(1)

    def update_loaded_modules(self, modules: list[str]):
        existing = {self._loaded.item(i).text()
                    for i in range(self._loaded.count())}
        for m in sorted(modules):
            if m not in existing:
                self._loaded.addItem(QListWidgetItem(m))

    def set_tracing(self, active: bool):
        self._stop_btn.setEnabled(active)
        self._list.setEnabled(not active)

    def selected_project_files(self) -> list[str]:
        selected: list[str] = []
        for row in range(self._list.topLevelItemCount()):
            item = self._list.topLevelItem(row)
            if item.checkState(1) == Qt.CheckState.Checked:
                selected.append(item.data(0, Qt.ItemDataRole.UserRole) or item.text(0))
        return selected

    def _ctx(self, pos):
        item = self._list.itemAt(pos)
        if not item or not item.text(0).lower().endswith(".exe"):
            return
        fname = item.text(0)
        menu  = QMenu(self)
        act   = QAction("▶  트레이스 시작: {}".format(fname), self)
        act.triggered.connect(lambda: self._request(fname))
        menu.addAction(act)
        menu.exec(self._list.mapToGlobal(pos))

    def _request(self, fname: str):
        cached = self._cached_path(fname)
        if cached:
            path = self._select_target_path(fname, cached)
            if path:
                self._remember_path(fname, path)
                self.start_trace_requested.emit(path)
            return
        for d in [Path.cwd(), Path(__file__).parent]:
            p = d / fname
            if p.exists():
                self._remember_path(fname, str(p))
                self.start_trace_requested.emit(str(p))
                return
        path = self._select_target_path(fname, "")
        if path:
            self._remember_path(fname, path)
            self.start_trace_requested.emit(path)

    def _select_target_path(self, fname: str, initial: str) -> str:
        if initial and not Path(initial).exists():
            parent = Path(initial).parent
            initial = str(parent) if parent.exists() else ""
        path, _ = QFileDialog.getOpenFileName(
            self, "'{}' 위치 지정".format(fname), initial,
            "{} ({});;모든 파일 (*)".format(fname, fname))
        return path

    def _cached_path(self, fname: str) -> str:
        path = self._path_cache.get(fname)
        if path:
            return path
        value = self._settings.value(self._settings_key(fname), "")
        path = str(value) if value else ""
        if path:
            self._path_cache[fname] = path
        return path

    def _remember_path(self, fname: str, path: str):
        self._path_cache[fname] = path
        self._settings.setValue(self._settings_key(fname), path)
        self._settings.sync()

    @staticmethod
    def _settings_key(fname: str) -> str:
        return "target_paths/{}".format(
            fname.replace("\\", "_").replace("/", "_"))


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
        self._target_modules: set[str] = set()

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
        self._tree.setHeaderLabels(["함수", "출발지", "도착지"])
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

    def set_project_files(self, files: list[str]):
        self._target_modules = CallTreeBuilder._normalize_targets(files)
        self._rebuild_entries()

    def set_session(self, session):
        self._session = session
        self._rebuild_entries()

    def set_graph_entries(self, entries: list[dict]):
        merged = list(entries)
        seen = {
            (
                str(e.get("module", "")).lower(),
                str(e.get("offset", "")).lower(),
                int(e.get("tid", 0)),
                int(e.get("trace_seq", e.get("call_seq", 0))),
            )
            for e in merged
        }
        if self._session:
            for ev in self._session.events:
                if ev.get("type") != "call":
                    continue
                if not self._is_graph_event(ev):
                    continue
                mod = ev.get("dst_module", "")
                off = ev.get("dst_offset", "0x0")
                if not mod or mod == "unknown":
                    continue
                key = (
                    mod.lower(), off.lower(),
                    int(ev.get("thread_id", 0)),
                    int(ev.get("seq", 0)),
                )
                if key in seen:
                    continue
                seen.add(key)
                merged.append({
                    "module": mod,
                    "offset": off,
                    "src_module": ev.get("src_module", ""),
                    "src_offset": ev.get("src_offset", "0x0"),
                    "src_label": ev.get("src_symbol", ""),
                    "tid": ev.get("thread_id", 0),
                    "node_id": "",
                    "call_seq": ev.get("seq", 0),
                    "trace_seq": ev.get("seq", 0),
                    "fallback": ev.get("dst_symbol", ""),
                    "count": 1,
                })
        self._entries = sorted(
            merged, key=lambda e: (e.get("trace_seq", 0),
                                   e.get("tid", 0),
                                   e.get("call_seq", 0)))
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
            if not self._is_graph_event(ev):
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
            if not self._is_graph_event(ev):
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

    def _is_graph_event(self, ev: dict) -> bool:
        if not self._target_modules:
            return True
        return (
            self._is_target_module(ev.get("src_module", ""))
            or self._is_target_module(ev.get("dst_module", ""))
        )

    def _is_target_module(self, module: str) -> bool:
        if not module or module == "unknown":
            return False
        name = Path(str(module)).name.lower()
        stem = name.rsplit(".", 1)[0]
        return name in self._target_modules or stem in self._target_modules

    def _label_for(self, entry: dict) -> str:
        label = self._base_label_for(entry)
        if entry.get("count", 0) > 1:
            label = "{}  total:{}".format(label, entry["count"])
        label = "T{} #{}  {}".format(
            entry.get("tid", "?"), entry.get("trace_seq", "?"), label)
        return label

    def _base_label_for(self, entry: dict) -> str:
        label = entry.get("fallback", "")
        if not label:
            label = "{}+{}".format(entry["module"], entry["offset"])
        return label

    def _apply_filter(self):
        q = self._edit.text().strip().lower()
        self._tree.clear()
        for entry in self._entries:
            label = self._label_for(entry)
            src_label = entry.get("src_label", "") or "{}+{}".format(
                entry.get("src_module", ""), entry.get("src_offset", ""))
            src_addr = "{}+{}".format(
                entry.get("src_module", ""), entry.get("src_offset", ""))
            dst_addr = "{}+{}".format(entry["module"], entry["offset"])
            src_text = "{} ({})".format(src_label, src_addr) if src_label else src_addr
            dst_base = self._base_label_for(entry)
            dst_text = "{} ({})".format(dst_base, dst_addr)
            hay = "{} {} {} {} thread {} tid {}".format(
                label, src_text, src_addr, dst_text,
                entry.get("tid", ""), entry.get("tid", "")).lower()
            if q and q not in hay:
                continue
            item = QTreeWidgetItem([label, src_text, dst_text])
            graph_token = ""
            if entry.get("node_id"):
                graph_token = "{}|{}".format(entry.get("tid"), entry.get("node_id"))
            item.setData(0, Qt.ItemDataRole.UserRole,
                         "{}|{}|{}".format(entry["module"], entry["offset"], graph_token))
            self._tree.addTopLevelItem(item)
        self._tree.resizeColumnToContents(0)
        self._tree.resizeColumnToContents(1)

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
        self._trace_stopping = False
        self._ghidra_connected = False
        self._ghidra_connect_enabled = True
        self._frida_error_dialog_shown = False
        self._project_files: list[str] = []
        self._target_pid: Optional[int] = None
        self._target_path = ""

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
        h_split.setChildrenCollapsible(True)

        # 왼쪽
        self._left = LeftPanel()
        self._left.setMinimumWidth(120)
        self._left.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
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
        right = QWidget()
        right_ly = QVBoxLayout(right)
        right_ly.setContentsMargins(0, 0, 0, 0)
        right_ly.setSpacing(0)

        right_split = QSplitter(Qt.Orientation.Vertical)
        right_split.setStyleSheet(
            "QSplitter::handle{background:#D1D9E0;height:2px;}")
        right_split.setChildrenCollapsible(True)

        self._func_panel = FunctionSearchPanel()
        self._func_panel.set_symbol_resolver(self._resolve_ghidra_symbol)
        self._func_panel.function_selected.connect(self._on_function_selected)
        right_split.addWidget(self._func_panel)

        self._thread_panel = ThreadListPanel()
        self._thread_panel.setMinimumHeight(80)
        self._thread_panel.thread_activated.connect(self._graph.select_thread)
        self._graph.threads_changed.connect(self._thread_panel.set_threads)
        self._graph.current_thread_changed.connect(
            self._thread_panel.set_current_tid)
        right_split.addWidget(self._thread_panel)
        right_split.setSizes([520, 260])
        right_ly.addWidget(right_split)
        right.setMinimumWidth(160)
        right.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        h_split.addWidget(right)

        h_split.setSizes([240, 960, 280])
        h_split.setStretchFactor(0, 1)
        h_split.setStretchFactor(1, 4)
        h_split.setStretchFactor(2, 1)
        ly.addWidget(h_split)

        self._sb = QStatusBar()
        self._sb.setStyleSheet(
            "background:#0078D4;color:white;font-size:12px;padding:2px 6px;")
        self.setStatusBar(self._sb)
        self._ghidra_toggle_btn = QPushButton("Ghidra 대기 해제")
        self._ghidra_toggle_btn.setStyleSheet(
            "QPushButton{background:#FFFFFF;color:#1E293B;"
            "border:1px solid #CBD5E1;border-radius:3px;padding:2px 8px;}"
            "QPushButton:hover{background:#E2E8F0;}")
        self._ghidra_toggle_btn.clicked.connect(self._toggle_ghidra_connection)
        self._sb.addPermanentWidget(self._ghidra_toggle_btn)
        self._st("준비  |  Ghidra Script 연결 대기 중")

    # ── Ghidra 연결 ─────────────────────────────────────────

    def _setup_ghidra_server(self):
        self._ghidra_worker = GhidraServerWorker()
        self._ghidra_thread = QThread()
        self._ghidra_worker.moveToThread(self._ghidra_thread)
        self._ghidra_worker.status_changed.connect(self._st)
        self._ghidra_worker.ghidra_connected.connect(self._on_ghidra_connected)
        self._ghidra_worker.project_info_recv.connect(self._on_project_info)
        self._ghidra_worker.sync_recv.connect(self._on_ghidra_sync)
        self._ghidra_thread.started.connect(self._ghidra_worker.run_server)
        self._ghidra_thread.start()

    def _on_ghidra_connected(self, connected: bool):
        self._ghidra_connected = connected
        self._update_ghidra_toggle()
        self._st("Ghidra {}".format("연결됨" if connected else "연결 해제"))

    def _toggle_ghidra_connection(self):
        if not self._ghidra_worker:
            return
        if self._ghidra_connect_enabled:
            self._ghidra_connect_enabled = False
            self._ghidra_worker.disconnect_ghidra(pause=True)
        else:
            self._ghidra_connect_enabled = True
            self._ghidra_worker.resume_ghidra()
        self._update_ghidra_toggle()

    def _update_ghidra_toggle(self):
        if not hasattr(self, "_ghidra_toggle_btn"):
            return
        if not self._ghidra_connect_enabled:
            self._ghidra_toggle_btn.setText("Ghidra 연결 대기")
        elif self._ghidra_connected:
            self._ghidra_toggle_btn.setText("Ghidra 연결 해제")
        else:
            self._ghidra_toggle_btn.setText("Ghidra 대기 해제")

    def _on_project_info(self, files: list[str]):
        self._project_files = files
        self._left.set_project_files(files)
        self._graph.set_project_files(files)
        self._func_panel.set_project_files(files)
        self._st("프로젝트 파일 {}개 수신".format(len(files)))

    def _on_graph_sync(self, module: str, offset_hex: str):
        """그래프 노드 선택 → Ghidra sync."""
        if self._ghidra_worker:
            self._ghidra_worker.send_sync(module, offset_hex)

    def _on_function_selected(self, module: str, offset_hex: str, graph_token: str):
        if graph_token:
            self._graph.goto_node_token(graph_token, zoom=True)
        else:
            self._graph.sync_from_ghidra(module, offset_hex, zoom=True)
        self._on_graph_sync(module, offset_hex)

    def _on_ghidra_sync(self, module: str, offset_hex: str):
        if self._session and self._ghidra_worker:
            self._ghidra_worker.refresh_symbols_for_module(module)
            self._graph.load_session(self._session)
            self._func_panel.set_session(self._session)
            self._func_panel.set_graph_entries(self._graph.function_entries())
        self._graph.sync_from_ghidra(module, offset_hex)

    def _resolve_ghidra_symbol(self, module: str, offset_hex: str) -> str:
        if not self._ghidra_worker:
            return ""
        return self._ghidra_worker.resolve_symbol(module, offset_hex)

    # ── 트레이스 시작/종료 ────────────────────────────────────

    def _start_trace(self, target_path: str):
        if not self._check_unsaved(): return
        if self._is_tracing or self._trace_stopping or self._frida_worker:
            self._st("트레이스 실행/종료 처리 중입니다.")
            return
        selected_targets = self._left.selected_project_files()
        if not selected_targets:
            self._st("트레이스 대상 모듈을 하나 이상 체크하세요.")
            QMessageBox.warning(
                self, "트레이스 대상 없음",
                "트레이스할 Ghidra 프로젝트 모듈을 하나 이상 체크하세요.")
            return
        target_configs = self._prepare_target_configs(selected_targets)
        if target_configs is None:
            return
        self._session    = TraceSession()
        self._target_pid = None
        self._target_path = str(Path(target_path).resolve())
        self._is_tracing = True
        self._trace_stopping = False
        self._frida_error_dialog_shown = False
        self._left.set_tracing(True)
        self._graph.set_project_files(selected_targets)
        self._func_panel.set_project_files(selected_targets)

        self._frida_worker = FridaWorker(
            target_path, selected_targets, target_configs)
        self._frida_thread = QThread()
        worker = self._frida_worker
        thread = self._frida_thread
        self._frida_live_workers.append(worker)
        self._frida_live_threads.append(thread)
        self._frida_worker.moveToThread(self._frida_thread)
        self._frida_worker.status_changed.connect(self._st)
        self._frida_worker.trace_complete.connect(self._on_trace_complete)
        self._frida_worker.error_occurred.connect(self._on_frida_error)
        self._frida_worker.target_spawned.connect(self._on_target_spawned)
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

    def _prepare_target_configs(
        self, selected_targets: list[str],
    ) -> Optional[list[dict]]:
        if not self._ghidra_worker or not self._ghidra_worker.is_connected():
            self._st("함수 시작점 준비: Ghidra 미연결")
            QMessageBox.warning(
                self, "Ghidra 미연결",
                "함수 시작점 bitmap 준비를 위해 Ghidra 연결이 필요합니다.")
            return None
        self._st("함수 시작점 준비 중: {}개 모듈".format(len(selected_targets)))
        configs = self._ghidra_worker.target_function_configs(selected_targets)
        missing = [
            cfg.get("name", "")
            for cfg in configs
            if not cfg.get("function_starts")
        ]
        if missing:
            self._st("함수 시작점 없음: {}".format(", ".join(missing)))
            QMessageBox.warning(
                self, "함수 시작점 없음",
                "다음 모듈에서 Ghidra 함수 시작점을 받지 못했습니다:\n{}".format(
                    "\n".join(missing)))
            return None
        total = sum(len(cfg.get("function_starts", [])) for cfg in configs)
        self._st("함수 시작점 준비 완료: {}개".format(total))
        return configs

    def _on_target_spawned(self, pid: int, target_path: str):
        self._target_pid = int(pid)
        self._target_path = str(Path(target_path).resolve())
        dbg("target recorded: pid={} path={}".format(
            self._target_pid, self._target_path))

    def _stop_trace(self):
        if self._trace_stopping:
            self._st("트레이스 종료 처리 중입니다.")
            return
        if self._frida_worker:
            self._trace_stopping = True
            self._st("트레이스 종료 요청")
            self._stop_frida_requested.emit()
        self._left.set_tracing(False)

    def _on_trace_complete(self, session: TraceSession):
        self._session    = session
        self._is_tracing = False
        self._trace_stopping = False
        self._left.set_tracing(False)
        self._left.update_loaded_modules(session.modules)
        self._graph.load_session(session)
        self._func_panel.set_session(session)
        self._func_panel.set_graph_entries(self._graph.function_entries())
        self._st("트레이스 완료  이벤트:{}  모듈:{}".format(
            len(session.events), len(session.modules)))

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
            self._func_panel.set_session(self._session)
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
            self._func_panel.set_session(self._session)
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
        self._trace_stopping = False
        self._left.set_tracing(False)

    def _on_frida_finished(self, worker: FridaWorker):
        self._is_tracing = False
        self._trace_stopping = False
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
            self._func_panel.set_session(sess)
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
        if self._target_pid and self._target_path:
            if terminate_process_if_image_matches(
                self._target_pid, self._target_path):
                self._st("대상 프로세스 강제 종료: pid={}".format(
                    self._target_pid))
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
