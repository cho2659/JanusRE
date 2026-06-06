📦
26281 /agent.js
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
    var g_mod_events = [];
    var g_sync_events = [];
    var g_spawn_events = [];
    var g_handle_events = [];
    var g_stalked = /* @__PURE__ */ new Set();
    var g_attach_failed = /* @__PURE__ */ new Set();
    var g_seq = 0;
    var g_flushed = false;
    var g_started = false;
    var g_status_timer = null;
    var g_thread_api = null;
    var g_sent_events = 0;
    var g_sent_mod_events = 0;
    var g_sent_sync_events = 0;
    var g_sent_spawn_events = 0;
    var g_sent_handle_events = 0;
    var g_handle_gen_by_key = /* @__PURE__ */ new Map();
    var g_next_handle_gen = 1;
    var g_symbol_name_by_va = /* @__PURE__ */ new Map();
    var g_hooked_target_exports = /* @__PURE__ */ new Set();
    var g_last_external_call_by_tid = /* @__PURE__ */ new Map();
    var g_export_symbols_by_module = /* @__PURE__ */ new Map();
    var g_targets = /* @__PURE__ */ new Set();
    var g_function_starts_by_module = /* @__PURE__ */ new Map();
    var SESSION_ID = generateUUID();
    var MAX_BT = 24;
    var FAILURE_SCAN_DELAY_MS = 50;
    var LAST_EXTERNAL_CALL_TTL_MS = 1500;
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
    function ntStatus(rv) {
      return ph(rv);
    }
    function handleKey(handle) {
      if (typeof handle === "string")
        return handle.toLowerCase();
      return ph(handle).toLowerCase();
    }
    function recordHandleCreate(api, handle, status, kind) {
      const key = handleKey(handle);
      const gen = g_next_handle_gen++;
      g_handle_gen_by_key.set(key, gen);
      const ev = {
        seq: nextSeq(),
        tid: Process.getCurrentThreadId(),
        action: "create",
        api,
        handle: ph(handle),
        handle_gen: gen,
        status,
        kind
      };
      g_handle_events.push(ev);
      return gen;
    }
    function normalizedTargetName(name) {
      const raw = (name || "").toLowerCase().replace(/\\/g, "/");
      const parts = raw.split("/");
      return parts[parts.length - 1] || raw;
    }
    function isTarget(mod) {
      if (!mod)
        return false;
      return g_targets.has(normalizedTargetName(mod.name));
    }
    function moduleOffset(addr, mod) {
      if (!mod)
        return "0x0";
      return "0x" + addr.sub(mod.base).toString(16).toUpperCase();
    }
    function symbolName(addr) {
      const key = ph(addr);
      const cached = g_symbol_name_by_va.get(key);
      if (cached !== void 0)
        return cached;
      let name = "";
      try {
        const sym = DebugSymbol.fromAddress(addr);
        if (sym && sym.name)
          name = sym.name;
      } catch (_) {
      }
      if (!name)
        name = exportSymbolName(addr);
      g_symbol_name_by_va.set(key, name);
      return name;
    }
    function exportSymbolName(addr) {
      const mod = findModuleSafe(addr);
      if (!mod)
        return "";
      const key = mod.name.toLowerCase();
      let symbols = g_export_symbols_by_module.get(key);
      if (!symbols) {
        symbols = [];
        try {
          for (const ex of mod.enumerateExports()) {
            if (ex.type === "function") {
              symbols.push({ name: ex.name, address: ex.address });
            }
          }
        } catch (_) {
        }
        symbols.sort((a, b) => a.address.compare(b.address));
        g_export_symbols_by_module.set(key, symbols);
      }
      let best = null;
      for (const sym of symbols) {
        if (sym.address.compare(addr) > 0)
          break;
        best = sym;
      }
      if (!best)
        return "";
      const delta = addr.sub(best.address).toInt32();
      if (delta === 0)
        return best.name;
      if (delta > 0 && delta < 8192) {
        return best.name + "+0x" + delta.toString(16).toUpperCase();
      }
      return "";
    }
    function findModuleSafe(addr) {
      if (!addr)
        return null;
      try {
        return Process.findModuleByAddress(addr);
      } catch (_) {
        return null;
      }
    }
    function pointerDetails(va) {
      if (!va || va === "unknown") {
        return { module: "unknown", offset: "0x0", symbol: "" };
      }
      try {
        const p = ptr(va);
        const mod = findModuleSafe(p);
        return {
          module: mod ? mod.name : "unknown",
          offset: moduleOffset(p, mod),
          symbol: symbolName(p)
        };
      } catch (_) {
        return { module: "unknown", offset: "0x0", symbol: "" };
      }
    }
    function noteExternalBoundaryCall(tid, loc, target, dstMod) {
      if (!dstMod)
        return;
      g_last_external_call_by_tid.set(tid, {
        caller_va: ph(loc),
        target_va: ph(target),
        target_module: dstMod.name,
        at_ms: Date.now()
      });
    }
    function recordTraceEvent(kind, loc, target, tid, source) {
      const srcMod = findModuleSafe(loc);
      const dstMod = findModuleSafe(target);
      const isCall = kind === "call";
      const dstIsExternal = isCall && isTarget(srcMod) && dstMod !== null && !isTarget(dstMod);
      const out = {
        k: isCall ? 0 : 1,
        src: ph(loc),
        dst: ph(target),
        tid,
        seq: nextSeq(),
        src_module: srcMod ? srcMod.name : "unknown",
        src_offset: moduleOffset(loc, srcMod),
        dst_module: dstMod ? dstMod.name : "unknown",
        dst_offset: moduleOffset(target, dstMod),
        dst_is_external: dstIsExternal,
        source
      };
      if (isCall || isTarget(srcMod) || isTarget(dstMod)) {
        out.src_symbol = symbolName(loc);
        out.dst_symbol = symbolName(target);
      }
      g_events.push(out);
      if (dstIsExternal) {
        noteExternalBoundaryCall(tid, loc, target, dstMod);
      }
    }
    function hookTargetExports(mod) {
      if (!isTarget(mod))
        return;
      let hooked = 0;
      let failed = 0;
      let exports2 = [];
      try {
        exports2 = mod.enumerateExports();
      } catch (_) {
        return;
      }
      for (const ex of exports2) {
        if (ex.type !== "function")
          continue;
        const key = normalizedTargetName(mod.name) + "!" + ex.name + "@" + ph(ex.address);
        if (g_hooked_target_exports.has(key))
          continue;
        g_hooked_target_exports.add(key);
        try {
          Interceptor.attach(ex.address, {
            onEnter(_) {
              const tid = Process.getCurrentThreadId();
              const ra = this.returnAddress;
              const tailTarget = detectVtableTailJump(ex.address, this.context);
              this._fd_tid = tid;
              this._fd_ra = ra;
              this._fd_tail_target = tailTarget;
              this._fd_tail_site = tailTarget ? tailJumpSite(ex.address) : null;
              recordTraceEvent("call", ra, ex.address, tid, "target_export");
              if (tailTarget) {
                recordTraceEvent("call", tailJumpSite(ex.address), tailTarget, tid, "target_export_tail_jump");
              }
            },
            onLeave(_) {
              const tid = this._fd_tid || Process.getCurrentThreadId();
              const ra = this._fd_ra;
              const tailTarget = this._fd_tail_target;
              const tailSite = this._fd_tail_site;
              if (tailTarget && tailSite) {
                recordTraceEvent("ret", tailTarget, tailSite, tid, "target_export_tail_jump");
              }
              if (ra)
                recordTraceEvent("ret", ex.address, ra, tid, "target_export");
            }
          });
          hooked++;
        } catch (_) {
          failed++;
        }
      }
      if (hooked > 0 || failed > 0) {
        send({
          type: "status",
          text: "target_export_hooks module=" + mod.name + " hooked=" + hooked + " failed=" + failed
        });
      }
    }
    function tailJumpSite(entry) {
      return entry.add(6);
    }
    function detectVtableTailJump(entry, ctx) {
      if (Process.arch !== "x64")
        return null;
      let disp = -1;
      try {
        if (entry.readU8() !== 72)
          return null;
        if (entry.add(1).readU8() !== 139)
          return null;
        if (entry.add(2).readU8() !== 9)
          return null;
        if (entry.add(3).readU8() !== 72)
          return null;
        if (entry.add(4).readU8() !== 139)
          return null;
        if (entry.add(5).readU8() !== 1)
          return null;
        if (entry.add(6).readU8() !== 72)
          return null;
        if (entry.add(7).readU8() !== 255)
          return null;
        if (entry.add(8).readU8() !== 96)
          return null;
        disp = entry.add(9).readU8();
      } catch (_) {
        return null;
      }
      try {
        const x64 = ctx;
        const thisPtr = x64.rcx;
        if (!thisPtr || thisPtr.isNull())
          return null;
        const implThis = thisPtr.readPointer();
        if (implThis.isNull())
          return null;
        const vtable = implThis.readPointer();
        if (vtable.isNull())
          return null;
        const target = vtable.add(disp).readPointer();
        if (target.isNull())
          return null;
        if (!findModuleSafe(target))
          return null;
        return target;
      } catch (_) {
        return null;
      }
    }
    function hookLoadedTargetExports() {
      for (const mod of Process.enumerateModules()) {
        hookTargetExports(mod);
      }
    }
    function findTargetCaller(ctx, immediateReturn) {
      const immediateMod = findModuleSafe(immediateReturn || null);
      if (immediateMod && g_targets.has(immediateMod.name.toLowerCase())) {
        return ph(immediateReturn);
      }
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
        const mod = findModuleSafe(ra);
        if (mod && g_targets.has(mod.name.toLowerCase()))
          return ph(ra);
        rsp = rsp.add(Process.pointerSize);
      }
      return "unknown";
    }
    function findThreadCreator(ctx, immediateReturn) {
      const tid = Process.getCurrentThreadId();
      const last = g_last_external_call_by_tid.get(tid);
      const lastMod = last ? last.target_module.toLowerCase() : "";
      const looksLikeThreadApi = lastMod === "ntdll.dll" || lastMod === "kernel32.dll" || lastMod === "kernelbase.dll";
      if (last && looksLikeThreadApi && Date.now() - last.at_ms <= LAST_EXTERNAL_CALL_TTL_MS) {
        return last.caller_va;
      }
      return findTargetCaller(ctx, immediateReturn);
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
              if (!this._before.has(mod.name.toLowerCase())) {
                recordLoad(mod.name, mod.base, mod.size);
                hookTargetExports(mod);
              }
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
                recordTraceEvent(ks, loc, target, tid, "stalker");
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
          text: "trace_stats events=" + g_events.length + " modules=" + g_mod_events.length + " sync=" + g_sync_events.length + " handles=" + g_handle_events.length
        });
      }, 1e3);
    }
    function hookThreadCreation() {
      const ntdll = Process.getModuleByName("ntdll.dll");
      const onNewThread = (apiName, status, handlePtr, startVa, callerVa, parentTid) => {
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
        const gen = recordHandleCreate(apiName, handle, status, "thread");
        if (!tid) {
          send({ type: "status", text: "thread_create_no_tid parent_tid=" + parentTid + " start=" + startVa });
          scheduleFailureScan("thread_create_no_tid");
          return;
        }
        const creator = pointerDetails(callerVa);
        const start = pointerDetails(startVa);
        g_spawn_events.push({
          seq: nextSeq(),
          api: apiName,
          parent_tid: parentTid,
          child_tid: tid,
          thread_handle: ph(handle),
          handle_gen: gen,
          creator_va: callerVa,
          start_va: startVa,
          creator_module: creator.module,
          creator_offset: creator.offset,
          creator_symbol: creator.symbol,
          start_module: start.module,
          start_offset: start.offset,
          start_symbol: start.symbol,
          status
        });
        send({
          type: "status",
          text: "thread_create tid=" + tid + " parent_tid=" + parentTid + " start=" + startVa + " caller=" + callerVa + " caller_mod=" + creator.module + "!" + creator.offset + " start_mod=" + start.module + "!" + start.offset
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
            this._cv = findThreadCreator(this.context, this.returnAddress);
            this._pt = Process.getCurrentThreadId();
          },
          onLeave(rv) {
            if (rv.toInt32() === 0)
              onNewThread("NtCreateThreadEx", ntStatus(rv), this._hp, this._sv, this._cv, this._pt);
          }
        });
      }
      const ntCreateThread = ntdll.findExportByName("NtCreateThread");
      if (ntCreateThread) {
        Interceptor.attach(ntCreateThread, {
          onEnter(args) {
            this._hp = args[0];
            this._sv = "unknown";
            this._cv = findThreadCreator(this.context, this.returnAddress);
            this._pt = Process.getCurrentThreadId();
          },
          onLeave(rv) {
            if (rv.toInt32() === 0)
              onNewThread("NtCreateThread", ntStatus(rv), this._hp, this._sv, this._cv, this._pt);
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
              flushAndSend("exit", fn);
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
              flushAndSend("exit", fn);
            }
          });
        }
      }
    }
    function sendTraceChunk(reason) {
      const events = g_events.slice(g_sent_events);
      const modEvents = g_mod_events.slice(g_sent_mod_events);
      const syncEvents = g_sync_events.slice(g_sent_sync_events);
      const spawnEvents = g_spawn_events.slice(g_sent_spawn_events);
      const handleEvents = g_handle_events.slice(g_sent_handle_events);
      if (events.length === 0 && modEvents.length === 0 && syncEvents.length === 0 && spawnEvents.length === 0 && handleEvents.length === 0) {
        return;
      }
      send({
        type: "trace_chunk",
        session_id: SESSION_ID,
        reason,
        sent_at_ms: Date.now(),
        events,
        mod_events: modEvents,
        sync_events: syncEvents,
        spawn_events: spawnEvents,
        handle_events: handleEvents
      });
      g_sent_events = g_events.length;
      g_sent_mod_events = g_mod_events.length;
      g_sent_sync_events = g_sync_events.length;
      g_sent_spawn_events = g_spawn_events.length;
      g_sent_handle_events = g_handle_events.length;
    }
    function flushAndSend(reason, hookName) {
      if (g_flushed)
        return;
      g_flushed = true;
      if (g_status_timer !== null) {
        clearInterval(g_status_timer);
        g_status_timer = null;
      }
      send({
        type: "status",
        text: "flush_send hook=" + (hookName || "unknown") + " reason=" + reason + " events=" + g_events.length + " modules=" + g_mod_events.length
      });
      sendTraceChunk(reason);
      send({
        type: "trace_complete",
        session_id: SESSION_ID,
        reason,
        sent_at_ms: Date.now(),
        events: [],
        mod_events: [],
        sync_events: [],
        spawn_events: [],
        handle_events: []
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
        g_targets = new Set(targets.map((t) => normalizedTargetName(t)));
        const mainMod = Process.enumerateModules()[0];
        if (mainMod)
          g_targets.add(normalizedTargetName(mainMod.name));
        hookLoadedTargetExports();
        send({ type: "status", text: "targets=" + Array.from(g_targets).join(",") });
      },
      setTargetConfig(configs) {
        g_targets = /* @__PURE__ */ new Set();
        g_function_starts_by_module.clear();
        for (const cfg of configs) {
          if (!cfg.trace)
            continue;
          const name = normalizedTargetName(cfg.name);
          g_targets.add(name);
          g_function_starts_by_module.set(name, (cfg.function_starts || []).map((v) => String(v)));
        }
        hookLoadedTargetExports();
        let starts = 0;
        for (const offsets of g_function_starts_by_module.values()) {
          starts += offsets.length;
        }
        send({
          type: "status",
          text: "target_config modules=" + Array.from(g_targets).join(",") + " function_starts=" + starts
        });
      }
    };
    (function main() {
      if (Process.arch !== "x64" && Process.arch !== "ia32") {
        throw new Error("unsupported architecture: " + Process.arch + " (x64/ia32 required)");
      }
      Stalker.queueDrainInterval = 0;
      Stalker.trustThreshold = -1;
      send({ type: "status", text: "agent:start session=" + SESSION_ID + " arch=" + Process.arch });
      const mainMod = Process.enumerateModules()[0];
      if (mainMod)
        g_targets.add(normalizedTargetName(mainMod.name));
      hookModules();
      hookThreadCreation();
      hookExit();
    })();
  }
});
export default require_agent();
