# GhidraFridaBridge.py
# @author  FridaBridge
# @category FridaIntegration
# @keybinding
# @menupath Tools.Frida Bridge.Connect
# @toolbar
#
# ============================================================
# Ghidra 내부 스크립트 (PyGhidra / Jython / GraalPy)
#
# 프로토콜:
#   Frida → Ghidra: connect, annotate, xref, rpc_request, sync, disconnect
#   Ghidra → Frida: connect_ack, project_info, annotate_result, xref_result,
#                   rpc_response, sync, disconnect
#
# rpc_request 처리:
#   수신 후 SwingUtilities.invokeLater()로 Ghidra EDT에 제출.
#   Jython: java.lang.Runnable 상속 방식 사용.
#   GraalPy: invokeLater 실패 시 run_loop 내 동기 처리로 fallback.
#
# 구현된 RPC 메서드:
#   module_list, decompile, disassemble, xref, import, export, change_name
#
# sync 프로토콜:
#   Ghidra 커서 이동 시 → { type:"sync", module:"...", offset:"0x..." }
#   Server에서 sync 수신 시 → { type:"sync", module:"...", offset:"0x..." }
#   → Ghidra GoTo 이동
# ============================================================

from __future__ import annotations

import json
import socket
import traceback
import threading
import time

# ── Ghidra Java API ─────────────────────────────────────────
from ghidra.app.decompiler        import DecompInterface          # type: ignore
from ghidra.framework.model       import DomainFolder             # type: ignore
from ghidra.program.model.listing import CodeUnit, Instruction    # type: ignore
from ghidra.program.model.symbol  import (                        # type: ignore
    FlowType, RefType, SourceType
)
from ghidra.program.util          import ProgramLocation           # type: ignore
from javax.swing                  import SwingUtilities           # type: ignore
from ghidra.app.nav               import NavigationUtils          # type: ignore
from ghidra.app.services          import GoToService, ProgramManager  # type: ignore
from ghidra.util.task             import TaskMonitor              # type: ignore
from java.lang                    import Object as JavaObject     # type: ignore

# ── 설정 ────────────────────────────────────────────────────
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8763

_INDIRECT = frozenset([
    FlowType.COMPUTED_CALL, FlowType.COMPUTED_CALL_TERMINATOR,
    FlowType.COMPUTED_JUMP, FlowType.INDIRECTION,
])
_CALL_F = frozenset([
    FlowType.COMPUTED_CALL, FlowType.COMPUTED_CALL_TERMINATOR,
])


# ============================================================
# 유틸
# ============================================================

def _hex(v) -> int:
    if isinstance(v, int): return v
    return int(str(v).strip(), 16)

def _find_file(files: list, name: str):
    nl = name.lower(); st = nl.rsplit(".", 1)[0]
    for f in files:
        fn = f.getName().lower()
        if fn == nl or fn.rsplit(".", 1)[0] == st: return f
    return None

def _walk(folder: DomainFolder, out: list):
    for f in folder.getFiles(): out.append(f)
    for s in folder.getFolders(): _walk(s, out)

def _all_files(project) -> list:
    out = []
    _walk(project.getProjectData().getRootFolder(), out)
    return out

def _consumer():
    return JavaObject()

def _monitor():
    return TaskMonitor.DUMMY

def _get_program(project, module: str):
    """module 이름에 해당하는 (program, consumer) 반환. 없으면 (None, None)."""
    files = _all_files(project)
    df = _find_file(files, module)
    if df is None: return None, None
    consumer = _consumer()
    program  = df.getDomainObject(consumer, True, False,
                                   _monitor())
    return program, consumer

def _addr(program, offset: int):
    base  = program.getImageBase().getOffset()
    space = program.getAddressFactory().getDefaultAddressSpace()
    return space.getAddress(base + offset)


# ============================================================
# RPC 핸들러
# ============================================================

_HANDLERS: dict[str, callable] = {}

def _rpc(name: str):
    def dec(fn): _HANDLERS[name] = fn; return fn
    return dec


@_rpc("module_list")
def _rpc_module_list(project, _params) -> dict:
    return {"files": [f.getName() for f in _all_files(project)]}


@_rpc("decompile")
def _rpc_decompile(project, params) -> dict:
    module = params.get("module", "")
    offset = _hex(params.get("offset", "0x0"))
    program, consumer = _get_program(project, module)
    if program is None: return {"error": "module not found: " + module}
    try:
        addr = _addr(program, offset)
        fn   = program.getFunctionManager().getFunctionContaining(addr)
        if fn is None: return {"error": "no function at " + hex(offset)}
        decomp = DecompInterface()
        decomp.openProgram(program)
        res = decomp.decompileFunction(fn, 30, _monitor())
        if not res.decompileCompleted():
            return {"error": "decompile failed"}
        return {
            "function":   fn.getName(),
            "entry":      hex(fn.getEntryPoint().getOffset()),
            "pseudocode": res.getDecompiledFunction().getC(),
        }
    finally:
        program.release(consumer)


@_rpc("disassemble")
def _rpc_disassemble(project, params) -> dict:
    module  = params.get("module", "")
    offset  = _hex(params.get("offset", "0x0"))
    n_lines = int(params.get("n_lines", 20))
    program, consumer = _get_program(project, module)
    if program is None: return {"error": "module not found"}
    try:
        listing = program.getListing()
        base    = program.getImageBase().getOffset()
        cur     = _addr(program, offset)
        lines   = []
        for _ in range(n_lines):
            cu = listing.getCodeUnitAt(cur)
            if cu is None: break
            lines.append({
                "offset":   hex(cur.getOffset() - base),
                "bytes":    " ".join("{:02x}".format(b)
                                     for b in bytes(cu.getBytes())),
                "mnemonic": str(cu),
                "comment":  cu.getComment(CodeUnit.EOL_COMMENT) or "",
            })
            cur = cur.add(cu.getLength())
        return {"lines": lines}
    finally:
        program.release(consumer)


@_rpc("xref")
def _rpc_xref(project, params) -> dict:
    module    = params.get("module", "")
    offset    = _hex(params.get("offset", "0x0"))
    direction = params.get("direction", "to")
    program, consumer = _get_program(project, module)
    if program is None: return {"error": "module not found"}
    try:
        addr    = _addr(program, offset)
        ref_mgr = program.getReferenceManager()
        base    = program.getImageBase().getOffset()
        refs    = list(ref_mgr.getReferencesTo(addr)
                       if direction == "to"
                       else ref_mgr.getReferencesFrom(addr))
        out = []
        for r in refs[:200]:
            out.append({
                "from": hex(r.getFromAddress().getOffset() - base),
                "to":   hex(r.getToAddress().getOffset()   - base),
                "type": str(r.getReferenceType()),
                "ext":  r.isExternalReference(),
            })
        return {"refs": out, "total": len(refs)}
    finally:
        program.release(consumer)


@_rpc("import")
def _rpc_import(project, params) -> dict:
    module = params.get("module", "")
    program, consumer = _get_program(project, module)
    if program is None: return {"error": "module not found"}
    try:
        ext_mgr = program.getExternalManager()
        out = []
        for lib in ext_mgr.getExternalLibraryNames():
            for loc in ext_mgr.getExternalLocations(lib):
                out.append({
                    "library": lib,
                    "name":    loc.getLabel() or "",
                    "address": hex(loc.getAddress().getOffset())
                               if loc.getAddress() else None,
                })
        return {"imports": out}
    finally:
        program.release(consumer)


@_rpc("export")
def _rpc_export(project, params) -> dict:
    module = params.get("module", "")
    program, consumer = _get_program(project, module)
    if program is None: return {"error": "module not found"}
    try:
        base    = program.getImageBase().getOffset()
        sym_tbl = program.getSymbolTable()
        out = []
        for addr in sym_tbl.getExternalEntryPointIterator():
            syms = list(sym_tbl.getSymbols(addr))
            name = syms[0].getName() if syms else str(addr)
            out.append({
                "name":   name,
                "offset": hex(addr.getOffset() - base),
            })
        return {"exports": out}
    finally:
        program.release(consumer)


@_rpc("symbols")
def _rpc_symbols(project, params) -> dict:
    module = params.get("module", "")
    program, consumer = _get_program(project, module)
    if program is None: return {"error": "module not found"}
    try:
        base = program.getImageBase().getOffset()
        out = []
        funcs = program.getFunctionManager().getFunctions(True)
        for fn in funcs:
            body = fn.getBody()
            start = fn.getEntryPoint().getOffset() - base
            end = None
            try:
                end = body.getMaxAddress().getOffset() - base + 1
            except Exception:
                pass
            out.append({
                "name": fn.getName(),
                "offset": hex(start),
                "end": hex(end) if end is not None else None,
            })
        return {"symbols": out}
    finally:
        program.release(consumer)


@_rpc("change_name")
def _rpc_change_name(project, params) -> dict:
    module   = params.get("module", "")
    offset   = _hex(params.get("offset", "0x0"))
    new_name = params.get("name", "")
    if not new_name: return {"error": "name required"}
    program, consumer = _get_program(project, module)
    if program is None: return {"error": "module not found"}
    try:
        addr = _addr(program, offset)
        fn   = program.getFunctionManager().getFunctionContaining(addr)
        txn  = program.startTransaction("Rename via FridaBridge")
        ok   = False
        try:
            if fn:
                fn.setName(new_name, SourceType.USER_DEFINED)
            else:
                syms = list(program.getSymbolTable().getSymbols(addr))
                if syms:
                    syms[0].setName(new_name, SourceType.USER_DEFINED)
                else:
                    program.getSymbolTable().createLabel(
                        addr, new_name, SourceType.USER_DEFINED)
            ok = True
        finally:
            program.endTransaction(txn, ok)
        return {"ok": True, "name": new_name}
    finally:
        program.release(consumer)


# ============================================================
# GhidraAnnotator
# ============================================================

class GhidraAnnotator:
    def __init__(self, project):
        self._project = project

    def apply_events(self, events: list[dict]) -> tuple[int, int]:
        applied = skipped = 0
        files   = _all_files(self._project)
        for ev in events:
            a, s = self._apply_one(files, ev)
            applied += a; skipped += s
        print("[FridaBridge] 완료 적용:{} 스킵:{}".format(applied, skipped))
        return applied, skipped

    def apply_xrefs(self, events: list[dict]) -> tuple[int, int]:
        applied = skipped = 0
        files = _all_files(self._project)
        for ev in events:
            a, s = self._apply_xref_one(files, ev)
            applied += a; skipped += s
        print("[FridaBridge] XRef 완료 적용:{} 스킵:{}".format(applied, skipped))
        return applied, skipped

    def _apply_one(self, files, ev):
        sm = ev.get("src_module",""); so = _hex(ev.get("src_offset","0x0"))
        dm = ev.get("dst_module",""); do = _hex(ev.get("dst_offset","0x0"))
        ds = ev.get("dst_symbol","")
        df = _find_file(files, sm)
        if df is None: return 0, 0
        consumer = _consumer(); program = None
        try:
            program = df.getDomainObject(consumer, True, False, _monitor())
            return self._annotate(program, df.getName(), so, dm, do, ds, sm)
        except Exception as e:
            print("[FridaBridge] 오류({}): {}".format(df.getName(), e))
            return 0, 0
        finally:
            if program: program.release(consumer)

    def _apply_xref_one(self, files, ev):
        sm = ev.get("src_module",""); so = _hex(ev.get("src_offset","0x0"))
        dm = ev.get("dst_module",""); do = _hex(ev.get("dst_offset","0x0"))
        ds = ev.get("dst_symbol","")
        df = _find_file(files, sm)
        if df is None: return 0, 0
        consumer = _consumer(); program = None
        try:
            program = df.getDomainObject(consumer, True, False, _monitor())
            return self._add_xref_for_event(program, so, dm, do, ds, sm)
        except Exception as e:
            print("[FridaBridge] XRef 오류({}): {}".format(df.getName(), e))
            return 0, 0
        finally:
            if program: program.release(consumer)

    def _annotate(self, program, fname, src_off, dst_mod, dst_off, dst_sym, src_mod):
        base  = program.getImageBase().getOffset()
        space = program.getAddressFactory().getDefaultAddressSpace()
        try: src_addr = space.getAddress(base + src_off)
        except: return 0, 0
        cu = program.getListing().getCodeUnitAt(src_addr)
        if cu is None: return 0, 0

        if not isinstance(cu, Instruction):
            return self._txn_comment(program, cu, dst_mod, dst_off, dst_sym)

        instr = cu
        if instr.getFlowType() not in _INDIRECT: return 0, 1
        flows = instr.getFlows()
        if flows and len(flows) > 0: return 0, 1

        target  = self._target_text(dst_mod, dst_off, dst_sym)
        line    = "-> {}".format(target)

        txn = program.startTransaction("Frida Annotation")
        ok = applied = False
        try:
            applied = self._add_comment(cu, line)
            ok = True
        except Exception as e:
            print("[FridaBridge] 트랜잭션 오류: {}".format(e))
            traceback.print_exc()
        finally:
            program.endTransaction(txn, ok)

        if ok and applied:
            print("[FridaBridge] ✓ {} @ {} → {}".format(fname, hex(base+src_off), target))
            return 1, 0
        return (0, 1) if ok else (0, 0)

    @staticmethod
    def _txn_comment(program, cu, dst_mod, dst_off, dst_sym):
        target = GhidraAnnotator._target_text(dst_mod, dst_off, dst_sym)
        line   = "-> {}".format(target)
        txn = program.startTransaction("Frida Annotation (data)")
        ok = applied = False
        try: applied = GhidraAnnotator._add_comment(cu, line); ok = True
        finally: program.endTransaction(txn, ok)
        return (1, 0) if (ok and applied) else (0, 1)

    @staticmethod
    def _add_comment(cu, line: str) -> bool:
        eol = cu.getComment(CodeUnit.EOL_COMMENT) or ""
        if line.strip() in [l.strip() for l in eol.splitlines()]:
            return False
        cu.setComment(CodeUnit.EOL_COMMENT, (eol + "\n" + line) if eol else line)
        pre = cu.getComment(CodeUnit.PRE_COMMENT) or ""
        if line.strip() not in [l.strip() for l in pre.splitlines()]:
            cu.setComment(CodeUnit.PRE_COMMENT, (pre + "\n" + line) if pre else line)
        return True

    def _add_xref_for_event(self, program, src_off, dst_mod, dst_off, dst_sym, src_mod):
        base  = program.getImageBase().getOffset()
        space = program.getAddressFactory().getDefaultAddressSpace()
        try: src_addr = space.getAddress(base + src_off)
        except: return 0, 0
        cu = program.getListing().getCodeUnitAt(src_addr)
        if cu is None or not isinstance(cu, Instruction):
            return 0, 1

        instr = cu
        if instr.getFlowType() not in _CALL_F:
            return 0, 1
        flows = instr.getFlows()
        if flows and len(flows) > 0:
            return 0, 1

        same = src_mod.lower() == dst_mod.lower()
        txn = program.startTransaction("Frida XRef")
        ok = applied = False
        try:
            if same:
                applied = self._xref_internal(program, src_addr, dst_off, True)
            else:
                applied = self._xref_external(
                    program, src_addr, dst_mod, dst_sym, dst_off, True)
            ok = True
        except Exception as e:
            print("[FridaBridge] XRef 트랜잭션 오류: {}".format(e))
            traceback.print_exc()
        finally:
            program.endTransaction(txn, ok)
        return (1, 0) if (ok and applied) else (0, 1)

    @staticmethod
    def _xref_internal(program, src_addr, dst_off, is_call):
        ref_mgr  = program.getReferenceManager()
        base     = program.getImageBase().getOffset()
        space    = program.getAddressFactory().getDefaultAddressSpace()
        ref_type = RefType.COMPUTED_CALL if is_call else RefType.COMPUTED_JUMP
        try: dst_addr = space.getAddress(base + dst_off)
        except: return
        for r in ref_mgr.getReferencesFrom(src_addr):
            if r.getToAddress() == dst_addr and r.getReferenceType() == ref_type:
                return False
        ref_mgr.addMemoryReference(src_addr, dst_addr, ref_type,
                                   SourceType.USER_DEFINED, 0)
        return True

    @staticmethod
    def _xref_external(program, src_addr, dst_mod, dst_sym, dst_off, is_call):
        ref_mgr  = program.getReferenceManager()
        ext_mgr  = program.getExternalManager()
        ref_type = RefType.COMPUTED_CALL if is_call else RefType.COMPUTED_JUMP
        label    = GhidraAnnotator._xref_label(dst_mod, dst_off)
        for r in ref_mgr.getReferencesFrom(src_addr):
            if not r.isExternalReference(): continue
            loc = r.getExternalLocation()
            if loc and loc.getLibraryName().lower() == dst_mod.lower():
                if loc.getLabel() == label: return False
        try:
            ext_loc = ext_mgr.addExtFunction(dst_mod, label, None,
                                             SourceType.USER_DEFINED)
            ref_mgr.addExternalReference(src_addr, 0, ext_loc,
                                         SourceType.USER_DEFINED, ref_type)
            return True
        except Exception as e:
            print("[FridaBridge] External XRef 실패: {}".format(e))
            return False

    @staticmethod
    def _target_text(dst_mod, dst_off, dst_sym):
        loc = "{}+{}".format(dst_mod, hex(dst_off))
        if dst_sym:
            return "{}!{} ; goto {}".format(dst_mod, dst_sym, loc)
        return loc

    @staticmethod
    def _xref_label(dst_mod, dst_off):
        stem = dst_mod.rsplit(".", 1)[0].replace("-", "_").replace(" ", "_")
        return "frida_ref_{}_{}".format(stem, hex(dst_off).replace("0x", ""))


# ============================================================
# BridgeClient
# ============================================================

class BridgeClient:
    def __init__(self, host: str, port: int):
        self.host = host; self.port = port
        self._sock      = None
        self._server    = None
        self._running   = False
        self._conn_running = False
        self._project   = state.getProject()        # type: ignore[name-defined]
        self._annotator = GhidraAnnotator(self._project)

    # ── 서버 ────────────────────────────────────────────────
    def serve(self):
        self._running = True
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(1)
        self._server.settimeout(1.0)
        print("[FridaBridge] Ghidra 서버 대기: {}:{}".format(
            self.host, self.port))
        try:
            while self._running:
                try:
                    sock, addr = self._server.accept()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        print("[FridaBridge] accept 오류: {}".format(e))
                    break
                self._handle_client(sock, addr)
        finally:
            try:
                if self._server:
                    self._server.close()
            except Exception:
                pass
            self._server = None

    def _handle_client(self, sock, addr):
        self._sock = sock
        self._sock.settimeout(5.0)
        hello = self._recv_one()
        if not (hello and hello.get("type") == "connect"):
            print("[FridaBridge] 잘못된 첫 메시지: {}".format(hello))
            self._close()
            return
        self._send({"type":"connect_ack","status":"ok",
                    "message":"Registered."})
        self._sock.settimeout(None)
        print("[FridaBridge] 연결 완료: {}".format(addr))
        # project_info 즉시 전송
        files = [f.getName() for f in _all_files(self._project)]
        self._send({"type":"project_info","files":files})
        print("[FridaBridge] project_info 전송: {}".format(files))
        self.run_loop()

    # ── 수신 루프 ────────────────────────────────────────────
    def run_loop(self):
        self._conn_running = True
        buf = ""
        try:
            while self._running and self._conn_running:
                self._sock.settimeout(0.05)
                try:
                    chunk = self._sock.recv(65536)
                except socket.timeout:
                    continue
                except Exception:
                    break
                if not chunk:
                    print("[FridaBridge] 연결 끊김."); break
                buf += chunk.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line: continue
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self._dispatch(msg)
        except Exception as e:
            print("[FridaBridge] 루프 오류: {}".format(e))
            traceback.print_exc()
        finally:
            self._conn_running = False
            self._send({"type":"disconnect","client":"ghidra"})
            self._close()

    def stop(self):
        self._conn_running = False
        self._running = False
        try:
            if self._server:
                self._server.close()
        except Exception:
            pass

    # ── 메시지 처리 ──────────────────────────────────────────
    def _dispatch(self, msg: dict):
        t = msg.get("type","")

        if t == "trace":
            # trace는 정보 전달용으로만 취급한다. 주석 적용은 annotate 명령에서만 수행한다.
            self._send({"type":"trace_result","ok":True,
                        "count":len(msg.get("events",[]))})

        elif t == "annotate":
            evs = msg.get("events",[])
            sid = msg.get("session_id","?")
            rsn = msg.get("reason","?")
            print("[FridaBridge] annotate sid={} reason={} count={}".format(
                sid, rsn, len(evs)))
            a, s = self._annotator.apply_events(evs)
            self._send({"type":"annotate_result","applied":a,"skipped":s})

        elif t == "xref":
            evs = msg.get("events",[])
            sid = msg.get("session_id","?")
            rsn = msg.get("reason","?")
            print("[FridaBridge] xref sid={} reason={} count={}".format(
                sid, rsn, len(evs)))
            a, s = self._annotator.apply_xrefs(evs)
            self._send({"type":"xref_result","applied":a,"skipped":s})

        elif t == "rpc_request":
            req_id = msg.get("req_id","")
            method = msg.get("method","")
            params = msg.get("params",{})
            self._schedule_rpc(req_id, method, params)

        elif t == "sync":
            # Server → Ghidra: 해당 주소로 GoTo
            module     = msg.get("module","")
            offset_hex = msg.get("offset","0x0")
            self._ghidra_goto(module, offset_hex)

        elif t == "disconnect":
            print("[FridaBridge] Frida disconnect.")
            self._conn_running = False

        else:
            print("[FridaBridge] 알 수 없는 타입: {}".format(t))

    def _schedule_rpc(self, req_id: str, method: str, params: dict):
        self._exec_rpc(req_id, method, params)

    def _exec_rpc(self, req_id: str, method: str, params: dict):
        handler = _HANDLERS.get(method)
        if handler is None:
            self._send({"type":"rpc_response","req_id":req_id,
                        "ok":False,"error":"unknown method: "+method})
            return
        client_ref = self
        try:
            from java.lang import Runnable  # type: ignore

            class _Task(Runnable):
                def run(self_inner):
                    try:
                        result = handler(client_ref._project, params)
                        client_ref._send({"type":"rpc_response","req_id":req_id,
                                          "ok":True,"result":result})
                    except Exception as e:
                        client_ref._send({"type":"rpc_response","req_id":req_id,
                                          "ok":False,"error":str(e)})
            SwingUtilities.invokeLater(_Task())
        except Exception:
            # GraalPy fallback — no Runnable subclassing support
            try:
                result = handler(self._project, params)
                self._send({"type":"rpc_response","req_id":req_id,
                            "ok":True,"result":result})
            except Exception as e:
                self._send({"type":"rpc_response","req_id":req_id,
                            "ok":False,"error":str(e)})

    def _ghidra_goto(self, module: str, offset_hex: str):
        """Ghidra GoTo 서비스를 통해 해당 주소로 이동."""
        try:
            offset  = _hex(offset_hex)
            files   = _all_files(self._project)
            df      = _find_file(files, module)
            if df is None: return
            consumer = _consumer(); program = None
            try:
                program = df.getDomainObject(consumer, True, False, _monitor())
                addr    = _addr(program, offset)
                tool = state.getTool()  # type: ignore[name-defined]
                if tool:
                    try:
                        pm = tool.getService(ProgramManager)
                        if pm:
                            pm.openProgram(program)
                    except Exception:
                        pass
                    gs = tool.getService(GoToService)
                    if gs:
                        ok = False
                        try:
                            ok = bool(gs.goTo(ProgramLocation(program, addr)))
                        except Exception:
                            ok = False
                        if not ok:
                            try:
                                NavigationUtils.goTo(tool, program, addr)
                            except Exception:
                                pass
            finally:
                if program: program.release(consumer)
        except Exception:
            pass

    # ── 소켓 유틸 ────────────────────────────────────────────
    def _send(self, obj: dict):
        if not self._sock: return
        try:
            self._sock.sendall(
                (json.dumps(obj, ensure_ascii=False)+"\n").encode("utf-8"))
        except Exception as e:
            print("[FridaBridge] 송신 실패: {}".format(e))

    def _recv_one(self):
        buf = b""
        try:
            while b"\n" not in buf:
                c = self._sock.recv(4096)
                if not c: return None
                buf += c
            return json.loads(buf.split(b"\n")[0].decode("utf-8").strip())
        except: return None

    def _close(self):
        if self._sock:
            try: self._sock.close()
            except: pass
            self._sock = None


# ============================================================
# Ghidra Script 진입점
# ============================================================

def run():
    print("=" * 55)
    print(" Ghidra Frida Bridge  {}:{}".format(SERVER_HOST, SERVER_PORT))
    print("=" * 55)
    client = BridgeClient(SERVER_HOST, SERVER_PORT)
    t = threading.Thread(target=client.serve, name="FridaBridge-Server", daemon=True)
    t.start()
    print("[FridaBridge] 서버 스레드 시작 (분석 작업 계속 가능).")


run()
