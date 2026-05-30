📦
31855 /agent.js
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
    var g_target_ranges = [];
    var g_targets = /* @__PURE__ */ new Set();
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
    function targetNameKeys(name) {
      const normalized = normalizedTargetName(name);
      if (!normalized)
        return [];
      const keys = [normalized];
      const dot = normalized.lastIndexOf(".");
      if (dot > 0)
        keys.push(normalized.substring(0, dot));
      return keys;
    }
    function addTargetName(name) {
      for (const key of targetNameKeys(name))
        g_targets.add(key);
    }
    function isTargetModuleName(name) {
      for (const key of targetNameKeys(name)) {
        if (g_targets.has(key))
          return true;
      }
      return false;
    }
    function isTarget(mod) {
      if (!mod)
        return false;
      return isTargetModuleName(mod.name);
    }
    function refreshTargetRanges() {
      const ranges = [];
      for (const mod of Process.enumerateModules()) {
        if (!isTarget(mod))
          continue;
        ranges.push({
          base: mod.base,
          end: mod.base.add(mod.size),
          name: mod.name
        });
      }
      g_target_ranges = ranges;
    }
    function isTargetAddress(addr) {
      for (const range of g_target_ranges) {
        if (addr.compare(range.base) >= 0 && addr.compare(range.end) < 0) {
          return true;
        }
      }
      return false;
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
              this._fd_tid = tid;
              this._fd_ra = ra;
              recordTraceEvent("call", ra, ex.address, tid, "target_export");
            },
            onLeave(_) {
              const tid = this._fd_tid || Process.getCurrentThreadId();
              const ra = this._fd_ra;
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
    function hookLoadedTargetExports() {
      for (const mod of Process.enumerateModules()) {
        hookTargetExports(mod);
      }
    }
    function parseSignedInteger(text) {
      const s = text.trim().toLowerCase();
      if (!s)
        return null;
      const sign = s.startsWith("-") ? -1 : 1;
      const body = s.replace(/^[+-]/, "");
      const value = body.startsWith("0x") ? parseInt(body.slice(2), 16) : parseInt(body, 10);
      if (!Number.isFinite(value))
        return null;
      return sign * value;
    }
    function contextRegister(ctx, name) {
      const c = ctx;
      const key = name.toLowerCase();
      const aliases = {
        eax: "eax",
        ebx: "ebx",
        ecx: "ecx",
        edx: "edx",
        esi: "esi",
        edi: "edi",
        esp: "esp",
        ebp: "ebp",
        eip: "eip",
        rax: "rax",
        rbx: "rbx",
        rcx: "rcx",
        rdx: "rdx",
        rsi: "rsi",
        rdi: "rdi",
        rsp: "rsp",
        rbp: "rbp",
        rip: "rip",
        r8: "r8",
        r9: "r9",
        r10: "r10",
        r11: "r11",
        r12: "r12",
        r13: "r13",
        r14: "r14",
        r15: "r15"
      };
      const prop = aliases[key];
      if (!prop || c[prop] === void 0 || c[prop] === null)
        return null;
      try {
        return ptr(c[prop].toString());
      } catch (_) {
        return null;
      }
    }
    function isIndirectJumpOperand(opStr) {
      const op = opStr.trim().toLowerCase();
      if (!op)
        return false;
      if (op.includes("["))
        return true;
      if (op.startsWith("0x"))
        return false;
      return /^[a-z][a-z0-9]*$/.test(op);
    }
    function resolveJumpTarget(opStr, ctx, instrAddress, instrSize, instruction) {
      const operandTarget = resolveJumpTargetFromOperands(instruction, ctx, instrAddress, instrSize);
      if (operandTarget)
        return operandTarget;
      const op = opStr.trim().toLowerCase();
      if (!op)
        return null;
      if (!op.includes("[") && /^[a-z][a-z0-9]*$/.test(op)) {
        return contextRegister(ctx, op);
      }
      const m = op.match(/\[([^\]]+)\]/);
      if (!m)
        return null;
      const inner = m[1];
      if (!inner)
        return null;
      const expr = inner.replace(/\s+/g, "");
      const terms = expr.match(/[+-]?[^+-]+/g) || [];
      let base = null;
      let disp = 0;
      for (const term of terms) {
        const clean = term.replace(/^\+/, "");
        const reg = clean.replace(/^-/, "");
        if (/^[a-z][a-z0-9]*$/.test(reg)) {
          if (reg === "rip" || reg === "eip") {
            base = instrAddress.add(instrSize);
          } else {
            const rv = contextRegister(ctx, reg);
            if (rv)
              base = rv;
          }
          continue;
        }
        const n = parseSignedInteger(clean);
        if (n !== null)
          disp += n;
      }
      if (!base) {
        const absolute = parseSignedInteger(expr);
        if (absolute === null)
          return null;
        base = ptr(absolute);
      }
      try {
        return base.add(disp).readPointer();
      } catch (_) {
        return null;
      }
    }
    function resolveJumpTargetFromOperands(instruction, ctx, instrAddress, instrSize) {
      const operands = instruction && instruction.operands;
      if (!operands || operands.length < 1)
        return null;
      const op = operands[0];
      if (!op || !op.type)
        return null;
      if (op.type === "reg") {
        return contextRegister(ctx, String(op.value || ""));
      }
      if (op.type !== "mem" || !op.value)
        return null;
      const mem = op.value;
      let base = null;
      if (mem.base) {
        const baseName = String(mem.base).toLowerCase();
        base = baseName === "rip" || baseName === "eip" ? instrAddress.add(instrSize) : contextRegister(ctx, baseName);
      }
      let address = base || ptr(0);
      if (mem.index) {
        const index = contextRegister(ctx, String(mem.index));
        const scale = Number(mem.scale || 1);
        if (index) {
          if (scale === 1)
            address = address.add(index);
          else if (scale === 2)
            address = address.add(index.shl(1));
          else if (scale === 4)
            address = address.add(index.shl(2));
          else if (scale === 8)
            address = address.add(index.shl(3));
          else
            address = address.add(index.toInt32() * scale);
        }
      }
      const disp = Number(mem.disp || 0);
      address = address.add(disp);
      try {
        return address.readPointer();
      } catch (_) {
        return null;
      }
    }
    function symbolBase(name) {
      return (name || "").replace(/\+0x[0-9a-f]+$/i, "").toLowerCase();
    }
    function isFunctionBoundaryJump(src, dst) {
      const srcMod = findModuleSafe(src);
      const dstMod = findModuleSafe(dst);
      if (!srcMod || !dstMod)
        return false;
      if (!isTarget(srcMod))
        return false;
      if (srcMod.name.toLowerCase() !== dstMod.name.toLowerCase())
        return true;
      const srcSym = symbolBase(symbolName(src));
      const dstSym = symbolBase(symbolName(dst));
      if (srcSym && dstSym)
        return srcSym !== dstSym;
      if (srcSym || dstSym)
        return src.compare(dst) !== 0;
      return false;
    }
    function isExecutableAddress(addr) {
      try {
        return Memory.queryProtection(addr).includes("x");
      } catch (_) {
        return false;
      }
    }
    function recordJumpFromCallout(tid, instrAddress, instrSize, opStr, ctx, instruction) {
      const target = resolveJumpTarget(opStr, ctx, instrAddress, instrSize, instruction);
      if (!target || target.isNull())
        return;
      if (!isFunctionBoundaryJump(instrAddress, target) && !isExecutableAddress(target))
        return;
      recordTraceEvent("call", instrAddress, target, tid, "stalker_jmp");
    }
    function findTargetCaller(ctx, immediateReturn) {
      const immediateMod = findModuleSafe(immediateReturn || null);
      if (immediateMod && isTargetModuleName(immediateMod.name)) {
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
        if (mod && isTargetModuleName(mod.name))
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
                refreshTargetRanges();
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
            transform(iterator) {
              let instruction;
              while ((instruction = iterator.next()) !== null) {
                const mnemonic = String(instruction.mnemonic || "").toLowerCase();
                if (mnemonic === "jmp") {
                  const address = instruction.address;
                  const opStr = String(instruction.opStr || "");
                  if (isTargetAddress(address) && isIndirectJumpOperand(opStr)) {
                    const size = Number(instruction.size || 0);
                    iterator.putCallout((ctx) => {
                      recordJumpFromCallout(tid, address, size, opStr, ctx, instruction);
                    });
                  }
                }
                iterator.keep();
              }
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
      const rawEvents = g_events.slice(g_sent_events);
      const events = filterTraceEventsForSend(rawEvents);
      const modEvents = g_mod_events.slice(g_sent_mod_events);
      const syncEvents = g_sync_events.slice(g_sent_sync_events);
      const spawnEvents = g_spawn_events.slice(g_sent_spawn_events);
      const handleEvents = g_handle_events.slice(g_sent_handle_events);
      if (events.length === 0 && modEvents.length === 0 && syncEvents.length === 0 && spawnEvents.length === 0 && handleEvents.length === 0) {
        g_sent_events = g_events.length;
        g_sent_mod_events = g_mod_events.length;
        g_sent_sync_events = g_sync_events.length;
        g_sent_spawn_events = g_spawn_events.length;
        g_sent_handle_events = g_handle_events.length;
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
    function filterTraceEventsForSend(events) {
      if (g_targets.size === 0)
        return events;
      return events.filter((ev) => isTargetModuleName(ev.src_module || "") || isTargetModuleName(ev.dst_module || ""));
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
        text: "flush_send hook=" + (hookName || "unknown") + " reason=" + reason + " events=" + g_events.length + " send_events=" + filterTraceEventsForSend(g_events.slice(g_sent_events)).length + " modules=" + g_mod_events.length
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
        g_targets = /* @__PURE__ */ new Set();
        for (const target of targets)
          addTargetName(target);
        const mainMod = Process.enumerateModules()[0];
        if (mainMod)
          addTargetName(mainMod.name);
        refreshTargetRanges();
        hookLoadedTargetExports();
        send({ type: "status", text: "targets=" + Array.from(g_targets).join(",") });
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
        addTargetName(mainMod.name);
      refreshTargetRanges();
      hookModules();
      hookThreadCreation();
      hookExit();
    })();
  }
});
export default require_agent();
