📦
25788 /agent.js
✄
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

// frida-builtins:/node-globals.js
var init_node_globals = __esm({
  "frida-builtins:/node-globals.js"() {
    "use strict";
  }
});

// agent.ts
var require_agent = __commonJS({
  "agent.ts"() {
    init_node_globals();
    var g_events = [];
    var g_snapshots = [];
    var g_mod_events = [];
    var g_sync_events = [];
    var g_spawn_events = [];
    var g_stalked = /* @__PURE__ */ new Set();
    var g_attach_failed = /* @__PURE__ */ new Set();
    var g_last_external_call_by_tid = /* @__PURE__ */ new Map();
    var g_seq = 0;
    var g_flushed = false;
    var g_started = false;
    var g_status_timer = null;
    var g_thread_api = null;
    var g_sent_events = 0;
    var g_sent_snapshots = 0;
    var g_sent_mod_events = 0;
    var g_sent_sync_events = 0;
    var g_sent_spawn_events = 0;
    var g_targets = /* @__PURE__ */ new Set();
    var SESSION_ID = generateUUID();
    var MAX_BT = 24;
    var LAST_EXTERNAL_CALL_TTL_MS = 1e3;
    var ENABLE_ARG_SNAPSHOTS = false;
    var FAILURE_SCAN_DELAY_MS = 50;
    function generateUUID() {
      return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
        const r = Math.random() * 16 | 0;
        return (c === "x" ? r : r & 3 | 8).toString(16);
      });
    }
    function ph(p) {
      return "0x" + p.toString(16).toUpperCase();
    }
    function nextSeq() {
      return g_seq++;
    }
    function isTarget(mod) {
      if (!mod)
        return false;
      return g_targets.has(mod.name.toLowerCase());
    }
    function moduleOffset(addr, mod) {
      if (!mod)
        return "0x0";
      return "0x" + addr.sub(mod.base).toString(16).toUpperCase();
    }
    function symbolName(addr) {
      try {
        const sym = DebugSymbol.fromAddress(addr);
        return sym && sym.name ? sym.name : "";
      } catch (_) {
        return "";
      }
    }
    function findTargetCaller(ctx) {
      const arch = Process.arch;
      const x64 = ctx;
      const ia32 = ctx;
      let rsp = arch === "ia32" ? ia32.esp : x64.rsp;
      for (let i = 0; i < MAX_BT; i++) {
        let ra;
        try {
          ra = rsp.readPointer();
        } catch (_) {
          break;
        }
        if (ra.isNull())
          break;
        const mod = Process.findModuleByAddress(ra);
        if (mod && g_targets.has(mod.name.toLowerCase()))
          return ph(ra);
        rsp = rsp.add(Process.pointerSize);
      }
      return "unknown";
    }
    function noteExternalCall(caller, target) {
      const targetMod = Process.findModuleByAddress(target);
      g_last_external_call_by_tid.set(Process.getCurrentThreadId(), {
        caller_va: ph(caller),
        target_va: ph(target),
        target_module: targetMod ? targetMod.name.toLowerCase() : "unknown",
        at_ms: Date.now()
      });
    }
    function consumeRecentExternalCaller(ctx) {
      const tid = Process.getCurrentThreadId();
      const last = g_last_external_call_by_tid.get(tid);
      if (last && Date.now() - last.at_ms <= LAST_EXTERNAL_CALL_TTL_MS) {
        return last.caller_va;
      }
      return findTargetCaller(ctx);
    }
    function directCallTarget(instr) {
      const i = instr;
      const operands = i.operands || [];
      if (operands.length > 0) {
        const op = operands[0];
        const value = op.value;
        if ((op.type === "imm" || op.type === "immediate") && value !== void 0) {
          if (typeof value === "number")
            return ptr(value);
          if (typeof value === "string") {
            try {
              return ptr(value);
            } catch (_) {
              return null;
            }
          }
          try {
            return value;
          } catch (_) {
            return null;
          }
        }
      }
      const opStr = String(i.opStr || "");
      const m = opStr.match(/0x[0-9a-fA-F]+/);
      if (!m)
        return null;
      try {
        return ptr(m[0]);
      } catch (_) {
        return null;
      }
    }
    function shouldTrackExternalCallsite(instr) {
      const src = instr.address;
      const srcMod = Process.findModuleByAddress(src);
      if (!isTarget(srcMod))
        return null;
      const target = directCallTarget(instr);
      if (!target)
        return null;
      const dstMod = Process.findModuleByAddress(target);
      if (!dstMod || isTarget(dstMod))
        return null;
      return target;
    }
    function captureArgs(ctx, seq, tid) {
      if (Process.arch === "ia32") {
        const x2 = ctx;
        const arg0 = x2.esp;
        const arg1 = x2.esp.add(4);
        const arg2 = x2.esp.add(8);
        const arg3 = x2.esp.add(12);
        const readArg = (p) => {
          try {
            return p.readPointer().toString();
          } catch (_) {
            return "";
          }
        };
        return {
          seq,
          kind: 0,
          tid,
          arch: "ia32",
          rcx: readArg(arg0),
          rdx: readArg(arg1),
          r8: readArg(arg2),
          r9: readArg(arg3),
          rsp: x2.esp.toString()
        };
      }
      const x = ctx;
      return {
        seq,
        kind: 0,
        tid,
        arch: "x64",
        rcx: x.rcx.toString(),
        rdx: x.rdx.toString(),
        r8: x.r8.toString(),
        r9: x.r9.toString(),
        rsp: x.rsp.toString()
      };
    }
    var THREAD_SUSPEND_RESUME = 2;
    function getThreadApi() {
      if (g_thread_api)
        return g_thread_api;
      try {
        const k32 = Process.getModuleByName("kernel32.dll");
        const getThreadIdAddr = k32.findExportByName("GetThreadId");
        const getThreadId = getThreadIdAddr ? new NativeFunction(getThreadIdAddr, "uint32", ["pointer"]) : null;
        g_thread_api = {
          getThreadId,
          suspendThread: new NativeFunction(k32.getExportByName("SuspendThread"), "int32", ["pointer"]),
          resumeThread: new NativeFunction(k32.getExportByName("ResumeThread"), "int32", ["pointer"]),
          openThread: new NativeFunction(k32.getExportByName("OpenThread"), "pointer", ["uint32", "bool", "uint32"]),
          closeHandle: new NativeFunction(k32.getExportByName("CloseHandle"), "bool", ["pointer"])
        };
        return g_thread_api;
      } catch (e) {
        send({ type: "status", text: "thread_api_failed " + e });
        return null;
      }
    }
    function withThreadSuspended(tid, reason, fn) {
      const api = getThreadApi();
      if (!api) {
        send({ type: "status", text: "thread_attach_no_api:tid=" + tid + " reason=" + reason });
        return fn();
      }
      const currentTid = Process.getCurrentThreadId();
      if (tid === currentTid) {
        send({ type: "status", text: "thread_attach_current_skip_suspend:tid=" + tid + " reason=" + reason });
        return fn();
      }
      const h = api.openThread(THREAD_SUSPEND_RESUME, 0, tid);
      if (h.isNull()) {
        send({ type: "status", text: "thread_suspend_open_failed:tid=" + tid + " reason=" + reason });
        return fn();
      }
      let suspended = false;
      try {
        const suspendCount = api.suspendThread(h);
        suspended = suspendCount >= 0;
        if (!suspended) {
          send({ type: "status", text: "thread_suspend_failed:tid=" + tid + " reason=" + reason });
        }
        return fn();
      } finally {
        if (suspended) {
          const resumeCount = api.resumeThread(h);
          if (resumeCount < 0) {
            send({ type: "status", text: "thread_resume_failed:tid=" + tid + " reason=" + reason });
          }
        }
        api.closeHandle(h);
      }
    }
    function recordLoad(name, base, size) {
      g_mod_events.push({
        seq: nextSeq(),
        action: "load",
        name,
        base: ph(base),
        size
      });
    }
    function recordUnload(name, base, size) {
      g_mod_events.push({
        seq: nextSeq(),
        action: "unload",
        name,
        base: ph(base),
        size
      });
    }
    function hookModules() {
      for (const mod of Process.enumerateModules())
        recordLoad(mod.name, mod.base, mod.size);
      const ntdll = Process.getModuleByName("ntdll.dll");
      const ldrLoad = ntdll.findExportByName("LdrLoadDll");
      if (ldrLoad) {
        Interceptor.attach(ldrLoad, {
          onEnter(_) {
            this._before = new Set(Process.enumerateModules().map((m) => m.name.toLowerCase()));
          },
          onLeave(rv) {
            if (rv.toInt32() !== 0)
              return;
            for (const mod of Process.enumerateModules()) {
              if (!this._before.has(mod.name.toLowerCase()))
                recordLoad(mod.name, mod.base, mod.size);
            }
          }
        });
      }
      const ldrUnload = ntdll.findExportByName("LdrUnloadDll");
      if (ldrUnload) {
        Interceptor.attach(ldrUnload, {
          onEnter(args) {
            const mod = Process.findModuleByAddress(args[0]);
            if (mod)
              recordUnload(mod.name, mod.base, mod.size);
          }
        });
      }
    }
    function attachStalker(tid, reason = "unknown") {
      if (g_stalked.has(tid)) {
        send({ type: "status", text: "stalker_skip:tid=" + tid + " reason=" + reason + " already=1" });
        return true;
      }
      if (tid === Process.getCurrentThreadId()) {
        send({ type: "status", text: "stalker_skip:tid=" + tid + " reason=" + reason + " current=1" });
        return false;
      }
      let ok = false;
      try {
        ok = withThreadSuspended(tid, reason, () => {
          Stalker.follow(tid, {
            events: { call: true, ret: true },
            onReceive(evbuf) {
              const parsed = Stalker.parse(evbuf, {
                annotate: true,
                stringify: false
              });
              for (const ev of parsed) {
                const ks = ev[0];
                if (ks !== "call" && ks !== "ret")
                  continue;
                const loc = ev[1];
                const target = ev[2];
                const srcMod = Process.findModuleByAddress(loc);
                const dstMod = Process.findModuleByAddress(target);
                if (g_targets.size > 0) {
                  if (!isTarget(srcMod) && !isTarget(dstMod))
                    continue;
                }
                const seq = nextSeq();
                g_events.push({
                  k: ks === "call" ? 0 : 1,
                  src: ph(loc),
                  dst: ph(target),
                  tid,
                  seq,
                  src_module: srcMod ? srcMod.name : "unknown",
                  src_offset: moduleOffset(loc, srcMod),
                  src_symbol: symbolName(loc),
                  dst_module: dstMod ? dstMod.name : "unknown",
                  dst_offset: moduleOffset(target, dstMod),
                  dst_symbol: symbolName(target)
                });
              }
            },
            transform(iterator) {
              let instr;
              while ((instr = iterator.next()) !== null) {
                const mn = instr.mnemonic.toLowerCase();
                if (mn === "call") {
                  const caller = instr.address;
                  const externalTarget = shouldTrackExternalCallsite(instr);
                  if (externalTarget) {
                    iterator.putCallout(() => {
                      noteExternalCall(caller, externalTarget);
                    });
                  }
                  if (ENABLE_ARG_SNAPSHOTS) {
                    const _tid = tid;
                    iterator.putCallout((ctx) => {
                      g_snapshots.push(captureArgs(ctx, g_events.length, _tid));
                    });
                  }
                }
                iterator.keep();
              }
            }
          });
          return true;
        });
      } catch (e) {
        if (!g_attach_failed.has(tid)) {
          g_attach_failed.add(tid);
          send({ type: "status", text: "stalker_failed:tid=" + tid + " reason=" + reason + " " + e });
        }
        return false;
      }
      if (!ok) {
        if (!g_attach_failed.has(tid)) {
          g_attach_failed.add(tid);
          send({ type: "status", text: "stalker_failed:tid=" + tid + " reason=" + reason + " attach=0" });
        }
        return false;
      }
      g_attach_failed.delete(tid);
      g_stalked.add(tid);
      send({ type: "status", text: "stalker:tid=" + tid + " reason=" + reason });
      return true;
    }
    function scanThreads(reason) {
      const currentTid = Process.getCurrentThreadId();
      const tids = Process.enumerateThreads().map((t) => t.id).filter((tid) => tid !== currentTid);
      let attempted = 0;
      for (const tid of tids) {
        if (g_stalked.has(tid))
          continue;
        attempted++;
        attachStalker(tid, reason);
      }
      send({
        type: "status",
        text: "thread_scan reason=" + reason + " seen=" + tids.length + " stalked=" + g_stalked.size + " failed=" + g_attach_failed.size + " attempted=" + attempted
      });
    }
    function scheduleFailureScan(reason) {
      setTimeout(() => scanThreads(reason), FAILURE_SCAN_DELAY_MS);
    }
    function beginTrace(initialTids = []) {
      if (g_started)
        return;
      g_started = true;
      scanThreads("start_before_initial");
      for (const tid of initialTids)
        attachStalker(tid, "initial");
      scanThreads("start_after_initial");
      send({ type: "status", text: "trace_threads=" + Array.from(g_stalked).join(",") });
      g_status_timer = setInterval(() => {
        sendTraceChunk("periodic");
        send({
          type: "status",
          text: "trace_stats events=" + g_events.length + " snapshots=" + g_snapshots.length + " modules=" + g_mod_events.length + " sync=" + g_sync_events.length
        });
      }, 1e3);
    }
    function hookThreadCreation() {
      const ntdll = Process.getModuleByName("ntdll.dll");
      const onNewThread = (handlePtr, startVa, callerVa, parentTid) => {
        if (handlePtr.isNull()) {
          send({ type: "status", text: "thread_create_no_handle_ptr parent_tid=" + parentTid });
          scheduleFailureScan("thread_create_no_handle_ptr");
          return;
        }
        const handle = handlePtr.readPointer();
        if (handle.isNull()) {
          send({ type: "status", text: "thread_create_null_handle parent_tid=" + parentTid });
          scheduleFailureScan("thread_create_null_handle");
          return;
        }
        const api = getThreadApi();
        const tid = api && api.getThreadId ? api.getThreadId(handle) : 0;
        if (!tid) {
          send({ type: "status", text: "thread_create_no_tid parent_tid=" + parentTid + " start=" + startVa });
          scheduleFailureScan("thread_create_no_tid");
          return;
        }
        g_spawn_events.push({
          seq: nextSeq(),
          parent_tid: parentTid,
          child_tid: tid,
          creator_va: callerVa,
          start_va: startVa
        });
        send({
          type: "status",
          text: "thread_create tid=" + tid + " parent_tid=" + parentTid + " start=" + startVa + " caller=" + callerVa
        });
        if (!attachStalker(tid, "thread_create")) {
          scheduleFailureScan("thread_create_attach_failed");
        }
      };
      const ntCreateThreadEx = ntdll.findExportByName("NtCreateThreadEx");
      if (ntCreateThreadEx) {
        Interceptor.attach(ntCreateThreadEx, {
          onEnter(args) {
            this._hp = args[0];
            this._sv = ph(args[4]);
            this._cv = consumeRecentExternalCaller(this.context);
            this._pt = Process.getCurrentThreadId();
          },
          onLeave(rv) {
            if (rv.toInt32() === 0)
              onNewThread(this._hp, this._sv, this._cv, this._pt);
          }
        });
      }
      const ntCreateThread = ntdll.findExportByName("NtCreateThread");
      if (ntCreateThread) {
        Interceptor.attach(ntCreateThread, {
          onEnter(args) {
            this._hp = args[0];
            this._sv = "unknown";
            this._cv = consumeRecentExternalCaller(this.context);
            this._pt = Process.getCurrentThreadId();
          },
          onLeave(rv) {
            if (rv.toInt32() === 0)
              onNewThread(this._hp, this._sv, this._cv, this._pt);
          }
        });
      }
    }
    function hookSync() {
      const ntdll = Process.getModuleByName("ntdll.dll");
      const defs = [
        { fn: "NtSetEvent", kind: "set_event", handle: (a) => ph(a[0]) },
        { fn: "NtPulseEvent", kind: "pulse_event", handle: (a) => ph(a[0]) },
        { fn: "NtReleaseMutant", kind: "release_mutex", handle: (a) => ph(a[0]) },
        {
          fn: "NtWaitForSingleObject",
          kind: "wait_single",
          handle: (a) => ph(a[0]),
          extra: (a, ev) => {
            if (!a[2].isNull()) {
              try {
                const v = a[2].readS64();
                ev.timeout = v.compare(0) < 0 ? Math.round(Number(v.toNumber() * -1) / 1e4) : -2;
              } catch (_) {
                ev.timeout = -1;
              }
            } else {
              ev.timeout = -1;
            }
          }
        },
        {
          fn: "NtWaitForMultipleObjects",
          kind: "wait_multiple",
          handle: (a) => ph(a[1]),
          extra: (a, ev) => {
            if (!a[3].isNull()) {
              try {
                const v = a[3].readS64();
                ev.timeout = v.compare(0) < 0 ? Math.round(Number(v.toNumber() * -1) / 1e4) : -2;
              } catch (_) {
                ev.timeout = -1;
              }
            } else {
              ev.timeout = -1;
            }
          }
        },
        { fn: "NtQueueApcThread", kind: "queue_apc", handle: (a) => ph(a[0]) },
        { fn: "NtAlpcSendWaitReceivePort", kind: "alpc", handle: (a) => ph(a[0]) }
      ];
      for (const d of defs) {
        const addr = ntdll.findExportByName(d.fn);
        if (!addr)
          continue;
        Interceptor.attach(addr, {
          onEnter(args) {
            const ev = {
              seq: nextSeq(),
              tid: Process.getCurrentThreadId(),
              kind: d.kind,
              handle: d.handle(args),
              caller_va: consumeRecentExternalCaller(this.context)
            };
            if (d.extra)
              d.extra(args, ev);
            g_sync_events.push(ev);
          }
        });
      }
    }
    function hookUserInput() {
      const u32 = Process.findModuleByName("user32.dll");
      if (!u32)
        return;
      const readMsg = (lpMsg) => {
        try {
          const ps = Process.pointerSize;
          const msgOff = ps;
          const wparamOff = ps === 4 ? 8 : 16;
          const lparamOff = wparamOff + ps;
          return {
            hwnd: ph(lpMsg.readPointer()),
            msg_id: lpMsg.add(msgOff).readU32(),
            wparam: ph(lpMsg.add(wparamOff).readPointer()),
            lparam: ph(lpMsg.add(lparamOff).readPointer())
          };
        } catch (_) {
          return null;
        }
      };
      const getMsgAddr = u32.findExportByName("GetMessageW");
      if (getMsgAddr) {
        Interceptor.attach(getMsgAddr, {
          onEnter(args) {
            this._lp = args[0];
            this._cv = consumeRecentExternalCaller(this.context);
          },
          onLeave(rv) {
            if (rv.toInt32() <= 0)
              return;
            const m = readMsg(this._lp);
            if (!m)
              return;
            g_sync_events.push({
              seq: nextSeq(),
              tid: Process.getCurrentThreadId(),
              kind: "get_message",
              handle: m.hwnd,
              caller_va: this._cv,
              msg_id: m.msg_id,
              wparam: m.wparam,
              lparam: m.lparam
            });
          }
        });
      }
      const peekMsgAddr = u32.findExportByName("PeekMessageW");
      if (peekMsgAddr) {
        Interceptor.attach(peekMsgAddr, {
          onEnter(args) {
            this._lp = args[0];
            this._cv = consumeRecentExternalCaller(this.context);
          },
          onLeave(rv) {
            if (rv.toInt32() === 0)
              return;
            const m = readMsg(this._lp);
            if (!m)
              return;
            g_sync_events.push({
              seq: nextSeq(),
              tid: Process.getCurrentThreadId(),
              kind: "peek_message",
              handle: m.hwnd,
              caller_va: this._cv,
              msg_id: m.msg_id,
              wparam: m.wparam,
              lparam: m.lparam
            });
          }
        });
      }
      const postMsg = u32.findExportByName("PostMessageW");
      if (postMsg) {
        Interceptor.attach(postMsg, {
          onEnter(args) {
            g_sync_events.push({
              seq: nextSeq(),
              tid: Process.getCurrentThreadId(),
              kind: "post_message",
              handle: ph(args[0]),
              caller_va: consumeRecentExternalCaller(this.context),
              msg_id: args[1].toInt32(),
              wparam: ph(args[2]),
              lparam: ph(args[3])
            });
          }
        });
      }
      const sendMsg = u32.findExportByName("SendMessageW");
      if (sendMsg) {
        Interceptor.attach(sendMsg, {
          onEnter(args) {
            g_sync_events.push({
              seq: nextSeq(),
              tid: Process.getCurrentThreadId(),
              kind: "send_message",
              handle: ph(args[0]),
              caller_va: consumeRecentExternalCaller(this.context),
              msg_id: args[1].toInt32(),
              wparam: ph(args[2]),
              lparam: ph(args[3])
            });
          }
        });
      }
    }
    function hookExit() {
      const ntdll = Process.getModuleByName("ntdll.dll");
      for (const fn of ["RtlExitUserProcess", "NtTerminateProcess"]) {
        const addr = ntdll.findExportByName(fn);
        if (addr) {
          Interceptor.attach(addr, {
            onEnter(_) {
              flushAndSend("exit");
            }
          });
        }
      }
      const k32 = Process.findModuleByName("kernel32.dll");
      if (!k32)
        return;
      for (const fn of ["ExitProcess", "TerminateProcess"]) {
        const addr = k32.findExportByName(fn);
        if (addr) {
          Interceptor.attach(addr, {
            onEnter(_) {
              flushAndSend("exit");
            }
          });
        }
      }
    }
    function sendTraceChunk(reason) {
      const events = g_events.slice(g_sent_events);
      const snapshots = g_snapshots.slice(g_sent_snapshots);
      const modEvents = g_mod_events.slice(g_sent_mod_events);
      const syncEvents = g_sync_events.slice(g_sent_sync_events);
      const spawnEvents = g_spawn_events.slice(g_sent_spawn_events);
      if (events.length === 0 && snapshots.length === 0 && modEvents.length === 0 && syncEvents.length === 0 && spawnEvents.length === 0) {
        return;
      }
      send({
        type: "trace_chunk",
        session_id: SESSION_ID,
        reason,
        events,
        snapshots,
        mod_events: modEvents,
        sync_events: syncEvents,
        spawn_events: spawnEvents
      });
      g_sent_events = g_events.length;
      g_sent_snapshots = g_snapshots.length;
      g_sent_mod_events = g_mod_events.length;
      g_sent_sync_events = g_sync_events.length;
      g_sent_spawn_events = g_spawn_events.length;
    }
    function flushAndSend(reason) {
      if (g_flushed)
        return;
      g_flushed = true;
      if (g_status_timer !== null) {
        clearInterval(g_status_timer);
        g_status_timer = null;
      }
      send({
        type: "status",
        text: "flush_send reason=" + reason + " events=" + g_events.length + " snapshots=" + g_snapshots.length + " modules=" + g_mod_events.length
      });
      sendTraceChunk(reason);
      send({
        type: "trace_complete",
        session_id: SESSION_ID,
        reason,
        events: [],
        snapshots: [],
        mod_events: [],
        sync_events: [],
        spawn_events: []
      });
    }
    rpc.exports = {
      stopTrace() {
        flushAndSend("user_stop");
      },
      startTrace(initialTids) {
        beginTrace(initialTids ?? []);
      },
      /**
       * 타겟 모듈 목록 주입. frida_bridge_server.py가 세션 시작 후 호출.
       * project_info에서 받은 파일명 목록 (소문자).
       */
      setTargets(targets) {
        g_targets = new Set(targets.map((t) => t.toLowerCase()));
        const mainMod = Process.enumerateModules()[0];
        if (mainMod)
          g_targets.add(mainMod.name.toLowerCase());
        send({ type: "status", text: "targets=" + Array.from(g_targets).join(",") });
      }
    };
    (function main() {
      if (Process.arch !== "x64" && Process.arch !== "ia32") {
        throw new Error("unsupported architecture: " + Process.arch + " (x64/ia32 required)");
      }
      Stalker.queueDrainInterval = 50;
      send({ type: "status", text: "agent:start session=" + SESSION_ID + " arch=" + Process.arch });
      const mainMod = Process.enumerateModules()[0];
      if (mainMod)
        g_targets.add(mainMod.name.toLowerCase());
      hookModules();
      hookThreadCreation();
      hookSync();
      hookUserInput();
      hookExit();
    })();
  }
});
export default require_agent();
