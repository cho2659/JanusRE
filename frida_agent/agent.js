📦
25157 /agent.js
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
    var g_exception_events = [];
    var g_stalked = /* @__PURE__ */ new Set();
    var g_attach_failed = /* @__PURE__ */ new Set();
    var g_seq = 0;
    var g_flushed = false;
    var g_started = false;
    var g_status_timer = null;
    var g_thread_api = null;
    var g_thread_observer = null;
    var g_module_observer = null;
    var g_sent_events = 0;
    var g_sent_mod_events = 0;
    var g_sent_sync_events = 0;
    var g_sent_spawn_events = 0;
    var g_sent_handle_events = 0;
    var g_sent_exception_events = 0;
    var g_exception_handler_installed = false;
    var g_symbol_name_by_va = /* @__PURE__ */ new Map();
    var g_last_external_call_by_tid = /* @__PURE__ */ new Map();
    var g_last_block_by_tid = /* @__PURE__ */ new Map();
    var g_export_symbols_by_module = /* @__PURE__ */ new Map();
    var g_targets = /* @__PURE__ */ new Set();
    var g_function_starts_by_module = /* @__PURE__ */ new Map();
    var g_target_module_records = [];
    var g_classifier_module = null;
    var g_bitmap_test = null;
    var SESSION_ID = generateUUID();
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
    function normalizedTargetName(name) {
      const raw = (name || "").toLowerCase().replace(/\\/g, "/");
      const parts = raw.split("/");
      return parts[parts.length - 1] || raw;
    }
    function ensureClassifier() {
      if (g_bitmap_test)
        return;
      g_classifier_module = new CModule(`
    int bitmap_test(const unsigned char *bits,
                    unsigned long long bit_count,
                    unsigned long long offset) {
      if (bits == 0 || offset >= bit_count) return 0;
      return (bits[offset >> 3] >> (offset & 7)) & 1;
    }
  `);
      g_bitmap_test = new NativeFunction(g_classifier_module.bitmap_test, "int", ["pointer", "uint64", "uint64"]);
    }
    function pointerOffset(addr, base) {
      return parseInt(addr.sub(base).toString(16), 16);
    }
    function allocBitmap(bitCount, fill, offsets = []) {
      ensureClassifier();
      const byteCount = Math.max(1, Math.ceil(Math.max(0, bitCount) / 8));
      const bytes = new Uint8Array(byteCount);
      if (fill) {
        bytes.fill(255);
      } else {
        for (const offText of offsets) {
          const offset = parseInt(String(offText), 16);
          if (!Number.isFinite(offset) || offset < 0 || offset >= bitCount)
            continue;
          const byteIndex = offset >> 3;
          bytes[byteIndex] = (bytes[byteIndex] || 0) | 1 << (offset & 7);
        }
      }
      const mem = Memory.alloc(byteCount);
      mem.writeByteArray(bytes.buffer);
      return mem;
    }
    function removeTargetModuleRecord(mod) {
      for (let i = g_target_module_records.length - 1; i >= 0; i--) {
        const rec = g_target_module_records[i];
        if (rec.name === normalizedTargetName(mod.name) && rec.base.equals(mod.base)) {
          g_target_module_records.splice(i, 1);
        }
      }
    }
    function refreshTargetModuleRecord(mod) {
      const name = normalizedTargetName(mod.name);
      removeTargetModuleRecord(mod);
      if (!g_targets.has(name))
        return;
      const starts = g_function_starts_by_module.get(name) || [];
      g_target_module_records.push({
        name,
        base: mod.base,
        size: mod.size,
        targetBits: allocBitmap(mod.size, true),
        functionBits: allocBitmap(mod.size, false, starts)
      });
    }
    function rebuildTargetModuleRecords() {
      g_target_module_records.length = 0;
      for (const mod of Process.enumerateModules()) {
        refreshTargetModuleRecord(mod);
      }
    }
    function targetRecordForAddress(addr) {
      if (!addr)
        return null;
      for (const rec of g_target_module_records) {
        if (addr.compare(rec.base) >= 0 && addr.compare(rec.base.add(rec.size)) < 0) {
          return rec;
        }
      }
      return null;
    }
    function classifyAddress(addr) {
      ensureClassifier();
      const rec = targetRecordForAddress(addr);
      if (!addr || !rec || !g_bitmap_test) {
        return { tt: false, functionStart: false };
      }
      const offset = pointerOffset(addr, rec.base);
      const tt = g_bitmap_test(rec.targetBits, rec.size, offset) !== 0;
      const functionStart = g_bitmap_test(rec.functionBits, rec.size, offset) !== 0;
      return { tt, functionStart };
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
      const srcClass = classifyAddress(loc);
      const dstClass = classifyAddress(target);
      if (!srcClass.tt && !dstClass.tt)
        return;
      const srcMod = findModuleSafe(loc);
      const dstMod = findModuleSafe(target);
      const isCall = kind === "call";
      const dstIsExternal = isCall && srcClass.tt && dstMod !== null && !dstClass.tt;
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
        src_tt: srcClass.tt,
        dst_tt: dstClass.tt,
        source
      };
      if (isCall || srcClass.tt || dstClass.tt) {
        out.src_symbol = symbolName(loc);
        out.dst_symbol = symbolName(target);
      }
      g_events.push(out);
      if (dstIsExternal) {
        noteExternalBoundaryCall(tid, loc, target, dstMod);
      }
    }
    function recordJumpEvent(loc, target, tid, source) {
      const srcClass = classifyAddress(loc);
      const dstClass = classifyAddress(target);
      if (!srcClass.tt && !dstClass.tt)
        return;
      if (dstClass.tt && !dstClass.functionStart)
        return;
      const srcMod = findModuleSafe(loc);
      const dstMod = findModuleSafe(target);
      const out = {
        k: 2,
        src: ph(loc),
        dst: ph(target),
        tid,
        seq: nextSeq(),
        src_module: srcMod ? srcMod.name : "unknown",
        src_offset: moduleOffset(loc, srcMod),
        dst_module: dstMod ? dstMod.name : "unknown",
        dst_offset: moduleOffset(target, dstMod),
        dst_is_external: srcClass.tt && dstMod !== null && !dstClass.tt,
        src_tt: srcClass.tt,
        dst_tt: dstClass.tt,
        is_jump: true,
        source
      };
      out.src_symbol = symbolName(loc);
      out.dst_symbol = symbolName(target);
      g_events.push(out);
      if (out.dst_is_external && dstMod) {
        noteExternalBoundaryCall(tid, loc, target, dstMod);
      }
    }
    function isJumpMnemonic(mnemonic) {
      const m = mnemonic.toLowerCase();
      return m === "jmp" || /^j[a-z0-9]+$/.test(m);
    }
    function recordBlockTransition(tid, blockStart, blockLast, blockEndsWithJump) {
      const prev = g_last_block_by_tid.get(tid);
      if (prev && prev.isJump) {
        recordJumpEvent(prev.last, blockStart, tid, "stalker_jump");
      }
      g_last_block_by_tid.set(tid, {
        last: blockLast,
        isJump: blockEndsWithJump
      });
    }
    function hookTargetExports(mod) {
      void mod;
    }
    function hookLoadedTargetExports() {
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
      if (g_module_observer)
        return;
      if (typeof Process.attachModuleObserver !== "function") {
        throw new Error("Process.attachModuleObserver is not available");
      }
      g_module_observer = Process.attachModuleObserver({
        onAdded(mod) {
          recordLoad(mod.name, mod.base, mod.size);
          refreshTargetModuleRecord(mod);
          if (g_targets.size > 0)
            hookTargetExports(mod);
          send({
            type: "status",
            text: "module_observer:add " + mod.name + " base=" + ph(mod.base)
          });
        },
        onRemoved(mod) {
          recordUnload(mod.name, mod.base, mod.size);
          removeTargetModuleRecord(mod);
          send({
            type: "status",
            text: "module_observer:remove " + mod.name + " base=" + ph(mod.base)
          });
        }
      });
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
            transform(iterator) {
              let instruction = iterator.next();
              if (instruction === null)
                return;
              const blockStart = instruction.address;
              let blockLast = instruction;
              do {
                blockLast = instruction;
                iterator.keep();
                instruction = iterator.next();
              } while (instruction !== null);
              const blockEndsWithJump = isJumpMnemonic(blockLast.mnemonic);
              iterator.putCallout(() => {
                recordBlockTransition(tid, blockStart, blockLast.address, blockEndsWithJump);
              });
            },
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
      if (g_thread_observer)
        return;
      if (typeof Process.attachThreadObserver !== "function") {
        throw new Error("Process.attachThreadObserver is not available");
      }
      g_thread_observer = Process.attachThreadObserver({
        onAdded(thread) {
          const tid = thread.id;
          send({ type: "status", text: "thread_observer:add tid=" + tid });
          if (!g_started)
            return;
          g_spawn_events.push({
            seq: nextSeq(),
            api: "thread_observer",
            parent_tid: 0,
            child_tid: tid,
            thread_handle: "unknown",
            creator_va: "unknown",
            start_va: "unknown",
            creator_module: "unknown",
            creator_offset: "0x0",
            creator_symbol: "",
            start_module: "unknown",
            start_offset: "0x0",
            start_symbol: "",
            status: "observed"
          });
          if (!attachStalker(tid, "thread_observer")) {
            scheduleFailureScan("thread_observer_attach_failed");
          }
        },
        onRemoved(thread) {
          const tid = thread.id;
          g_stalked.delete(tid);
          g_attach_failed.delete(tid);
          send({ type: "status", text: "thread_observer:remove tid=" + tid });
        },
        onRenamed(thread, previousName) {
          send({
            type: "status",
            text: "thread_observer:rename tid=" + thread.id + " previous=" + (previousName || "")
          });
        }
      });
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
    function hookExceptions() {
      if (g_exception_handler_installed)
        return;
      g_exception_handler_installed = true;
      Process.setExceptionHandler((details) => {
        try {
          const address = details.address;
          const mod = address ? findModuleSafe(address) : null;
          if (g_started) {
            g_exception_events.push({
              seq: nextSeq(),
              tid: Process.getCurrentThreadId(),
              address: address ? ph(address) : "unknown",
              exception_type: String(details.type || "unknown"),
              module: mod ? mod.name : "unknown",
              offset: address ? moduleOffset(address, mod) : "0x0"
            });
          }
          send({
            type: "status",
            text: "exception_marker type=" + String(details.type || "unknown") + " address=" + (address ? ph(address) : "unknown")
          });
        } catch (_) {
        }
        return false;
      });
    }
    function sendTraceChunk(reason) {
      const events = g_events.slice(g_sent_events);
      const modEvents = g_mod_events.slice(g_sent_mod_events);
      const syncEvents = g_sync_events.slice(g_sent_sync_events);
      const spawnEvents = g_spawn_events.slice(g_sent_spawn_events);
      const handleEvents = g_handle_events.slice(g_sent_handle_events);
      const exceptionEvents = g_exception_events.slice(g_sent_exception_events);
      if (events.length === 0 && modEvents.length === 0 && syncEvents.length === 0 && spawnEvents.length === 0 && handleEvents.length === 0 && exceptionEvents.length === 0) {
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
        handle_events: handleEvents,
        exception_events: exceptionEvents
      });
      g_sent_events = g_events.length;
      g_sent_mod_events = g_mod_events.length;
      g_sent_sync_events = g_sync_events.length;
      g_sent_spawn_events = g_spawn_events.length;
      g_sent_handle_events = g_handle_events.length;
      g_sent_exception_events = g_exception_events.length;
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
        handle_events: [],
        exception_events: []
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
        rebuildTargetModuleRecords();
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
        rebuildTargetModuleRecords();
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
      hookExceptions();
      hookExit();
    })();
  }
});
export default require_agent();
