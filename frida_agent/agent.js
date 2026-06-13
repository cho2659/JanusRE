"use strict";
(() => {
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
      var g_oep_hooked = false;
      var g_oep_reached = false;
      var g_stalker_cleanup_done = false;
      var g_sent_events = 0;
      var g_sent_mod_events = 0;
      var g_sent_sync_events = 0;
      var g_sent_spawn_events = 0;
      var g_sent_handle_events = 0;
      var g_sent_exception_events = 0;
      var g_exception_handler_installed = false;
      var g_symbol_name_by_va = /* @__PURE__ */ new Map();
      var g_last_external_call_by_tid = /* @__PURE__ */ new Map();
      var g_export_symbols_by_module = /* @__PURE__ */ new Map();
      var g_targets = /* @__PURE__ */ new Set();
      var g_function_starts_by_module = /* @__PURE__ */ new Map();
      var g_target_module_records = [];
      var g_classifier_module = null;
      var g_bitmap_test = null;
      var g_on_block_start_callout = null;
      var g_on_branch_execute_callout = null;
      var g_drain_transitions = null;
      var g_transition_drain_buffer = null;
      var g_native_last_src = null;
      var g_native_last_is_jump = null;
      var g_native_transitions = null;
      var g_native_transition_read_index = null;
      var g_native_transition_write_index = null;
      var g_native_module_records = null;
      var g_native_module_count = null;
      var g_callout_arena_current = null;
      var g_callout_arena_offset = 0;
      var g_callout_arena_size = 0;
      var g_callout_arena_chunks = [];
      var SESSION_ID = generateUUID();
      var BOOTSTRAP_SHM_NAME = "__FRIDA_DELTA_SHM_NAME__";
      var BOOTSTRAP_WAKE_EVENT_NAME = "__FRIDA_DELTA_WAKE_EVENT_NAME__";
      var BOOTSTRAP_SHM_SIZE_TEXT = "__FRIDA_DELTA_SHM_SIZE__";
      var BOOTSTRAP_MAIN_PID_TEXT = "__FRIDA_DELTA_MAIN_PID__";
      var BOOTSTRAP_MAIN_TID_TEXT = "__FRIDA_DELTA_MAIN_TID__";
      var FAILURE_SCAN_DELAY_MS = 50;
      var NATIVE_SLOT_COUNT = 4096;
      var NATIVE_QUEUE_CAPACITY = 65536;
      var NATIVE_TRANSITION_SIZE = 24;
      var NATIVE_TRANSITION_BATCH = 4096;
      var NATIVE_MODULE_CAPACITY = 1024;
      var NATIVE_MODULE_RECORD_SIZE = 32;
      var CALLOUT_ARENA_CHUNK_SIZE = 4 * 1024 * 1024;
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
      function allocZeroed(size) {
        const mem = Memory.alloc(size);
        mem.writeByteArray(new Uint8Array(size).buffer);
        return mem;
      }
      function ensureClassifier() {
        if (g_bitmap_test)
          return;
        g_native_last_src = allocZeroed(NATIVE_SLOT_COUNT * 8);
        g_native_last_is_jump = allocZeroed(NATIVE_SLOT_COUNT * 4);
        g_native_transitions = allocZeroed(NATIVE_QUEUE_CAPACITY * NATIVE_TRANSITION_SIZE);
        g_native_transition_read_index = allocZeroed(4);
        g_native_transition_write_index = allocZeroed(4);
        g_native_module_records = allocZeroed(NATIVE_MODULE_CAPACITY * NATIVE_MODULE_RECORD_SIZE);
        g_native_module_count = allocZeroed(4);
        g_classifier_module = new CModule(`
    typedef unsigned int u32;
    typedef unsigned long long u64;
    typedef void * gpointer;
    typedef struct _GumCpuContext GumCpuContext;

    typedef struct {
      u32 tid;
      u32 reserved;
      u64 start;
    } BlockStartData;

    typedef struct {
      u32 tid;
      u32 is_jump;
      u64 address;
    } BranchData;

    typedef struct {
      u32 tid;
      u32 reserved;
      u64 src;
      u64 dst;
    } TransitionRecord;

    typedef struct {
      u64 base;
      u64 size;
      const unsigned char *target_bits;
      const unsigned char *function_bits;
    } NativeTargetModuleRecord;

    #define SLOT_COUNT 4096
    #define QUEUE_CAPACITY 65536

    extern u64 native_last_src[];
    extern u32 native_last_is_jump[];
    extern TransitionRecord native_transitions[];
    extern volatile u32 native_transition_read_index;
    extern volatile u32 native_transition_write_index;
    extern NativeTargetModuleRecord native_module_records[];
    extern volatile u32 native_module_count;

    int bitmap_test(const unsigned char *bits,
                    unsigned long long bit_count,
                    unsigned long long offset) {
      if (bits == 0 || offset >= bit_count) return 0;
      return (bits[offset >> 3] >> (offset & 7)) & 1;
    }

    static u32 slot_for_tid(u32 tid) {
      return tid & (SLOT_COUNT - 1);
    }

    static int native_bitmap_test(const unsigned char *bits, u64 bit_count, u64 offset) {
      if (bits == 0 || offset >= bit_count) return 0;
      return (bits[offset >> 3] >> (offset & 7)) & 1;
    }

    static void classify_address(u64 address, u32 *is_target, u32 *is_function_start) {
      u32 i;
      *is_target = 0;
      *is_function_start = 0;
      for (i = 0; i < native_module_count; i++) {
        NativeTargetModuleRecord *rec = &native_module_records[i];
        u64 end = rec->base + rec->size;
        if (address >= rec->base && address < end) {
          u64 offset = address - rec->base;
          *is_target = native_bitmap_test(rec->target_bits, rec->size, offset) != 0;
          *is_function_start = native_bitmap_test(rec->function_bits, rec->size, offset) != 0;
          return;
        }
      }
    }

    static void enqueue_transition(u32 tid, u64 src, u64 dst) {
      u32 src_target;
      u32 src_function_start;
      u32 dst_target;
      u32 dst_function_start;
      u32 index;
      TransitionRecord *rec;

      classify_address(src, &src_target, &src_function_start);
      classify_address(dst, &dst_target, &dst_function_start);
      if (src_target == 0 && dst_target == 0) return;
      if (dst_target != 0 && dst_function_start == 0) return;

      index = native_transition_write_index++;
      rec = &native_transitions[index & (QUEUE_CAPACITY - 1)];
      rec->tid = tid;
      rec->reserved = 0;
      rec->src = src;
      rec->dst = dst;

      if (index - native_transition_read_index >= QUEUE_CAPACITY) {
        native_transition_read_index = index - QUEUE_CAPACITY + 1;
      }
    }

    void on_block_start(GumCpuContext *cpu_context, gpointer user_data) {
      BlockStartData *data = (BlockStartData *) user_data;
      u32 slot;
      (void) cpu_context;
      if (data == 0) return;

      slot = slot_for_tid(data->tid);
      if (native_last_is_jump[slot] != 0) {
        enqueue_transition(data->tid, native_last_src[slot], data->start);
        native_last_is_jump[slot] = 0;
      }
    }

    void on_branch_execute(GumCpuContext *cpu_context, gpointer user_data) {
      BranchData *data = (BranchData *) user_data;
      u32 slot;
      (void) cpu_context;
      if (data == 0) return;

      slot = slot_for_tid(data->tid);
      if (data->is_jump != 0) {
        native_last_src[slot] = data->address;
        native_last_is_jump[slot] = 1;
      } else {
        native_last_is_jump[slot] = 0;
      }
    }

    u32 drain_transitions(TransitionRecord *out, u32 max_count) {
      u32 read_index = native_transition_read_index;
      u32 write_index = native_transition_write_index;
      u32 available = write_index - read_index;
      u32 count = available < max_count ? available : max_count;
      u32 i;

      for (i = 0; i < count; i++) {
        out[i] = native_transitions[(read_index + i) & (QUEUE_CAPACITY - 1)];
      }
      native_transition_read_index = read_index + count;
      return count;
    }
  `, {
          native_last_src: g_native_last_src,
          native_last_is_jump: g_native_last_is_jump,
          native_transitions: g_native_transitions,
          native_transition_read_index: g_native_transition_read_index,
          native_transition_write_index: g_native_transition_write_index,
          native_module_records: g_native_module_records,
          native_module_count: g_native_module_count
        });
        g_bitmap_test = new NativeFunction(g_classifier_module.bitmap_test, "int", ["pointer", "uint64", "uint64"]);
        g_on_block_start_callout = g_classifier_module.on_block_start;
        g_on_branch_execute_callout = g_classifier_module.on_branch_execute;
        g_drain_transitions = new NativeFunction(g_classifier_module.drain_transitions, "uint32", ["pointer", "uint32"]);
        g_transition_drain_buffer = Memory.alloc(NATIVE_TRANSITION_SIZE * NATIVE_TRANSITION_BATCH);
      }
      function pointerOffset(addr, base) {
        return parseInt(addr.sub(base).toString(16), 16);
      }
      function writeU64Number(dst, value) {
        dst.writeU64(uint64(value));
      }
      function writeU64Pointer(dst, value) {
        dst.writeU64(0);
        dst.writePointer(value);
      }
      function arenaAlloc(size, align = 8) {
        const alignedOffset = g_callout_arena_offset + align - 1 & ~(align - 1);
        if (!g_callout_arena_current || alignedOffset + size > g_callout_arena_size) {
          const chunkSize = Math.max(CALLOUT_ARENA_CHUNK_SIZE, size + align);
          g_callout_arena_current = Memory.alloc(chunkSize);
          g_callout_arena_chunks.push(g_callout_arena_current);
          g_callout_arena_offset = 0;
          g_callout_arena_size = chunkSize;
        } else {
          g_callout_arena_offset = alignedOffset;
        }
        const out = g_callout_arena_current.add(g_callout_arena_offset);
        g_callout_arena_offset += size;
        return out;
      }
      function allocBlockStartData(tid, start) {
        const data = arenaAlloc(16);
        data.writeU32(tid);
        data.add(4).writeU32(0);
        writeU64Pointer(data.add(8), start);
        return data;
      }
      function allocBranchData(tid, address, isJump) {
        const data = arenaAlloc(16);
        data.writeU32(tid);
        data.add(4).writeU32(isJump ? 1 : 0);
        writeU64Pointer(data.add(8), address);
        return data;
      }
      function updateNativeTargetModuleMap() {
        ensureClassifier();
        if (!g_native_module_records || !g_native_module_count)
          return;
        const count = Math.min(g_target_module_records.length, NATIVE_MODULE_CAPACITY);
        g_native_module_count.writeU32(0);
        for (let i = 0; i < count; i++) {
          const rec = g_target_module_records[i];
          const out = g_native_module_records.add(i * NATIVE_MODULE_RECORD_SIZE);
          writeU64Pointer(out, rec.base);
          writeU64Number(out.add(8), rec.size);
          out.add(16).writePointer(rec.targetBits);
          out.add(24).writePointer(rec.functionBits);
        }
        g_native_module_count.writeU32(count);
      }
      function drainNativeTransitions() {
        ensureClassifier();
        if (!g_drain_transitions || !g_transition_drain_buffer)
          return;
        while (true) {
          const count = g_drain_transitions(g_transition_drain_buffer, NATIVE_TRANSITION_BATCH);
          if (count <= 0)
            return;
          for (let i = 0; i < count; i++) {
            const rec = g_transition_drain_buffer.add(i * NATIVE_TRANSITION_SIZE);
            const tid = rec.readU32();
            const src = rec.add(8).readPointer();
            const dst = rec.add(16).readPointer();
            recordJumpEvent(src, dst, tid, "stalker_jump");
          }
          if (count < NATIVE_TRANSITION_BATCH)
            return;
        }
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
        updateNativeTargetModuleMap();
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
        if (mnemonic.length < 2)
          return false;
        const first = mnemonic.charCodeAt(0);
        if (first !== 106 && first !== 74)
          return false;
        if (mnemonic === "jmp" || mnemonic === "JMP")
          return true;
        for (let i = 1; i < mnemonic.length; i++) {
          const c = mnemonic.charCodeAt(i);
          const lower = c | 32;
          if (!(lower >= 97 && lower <= 122 || c >= 48 && c <= 57)) {
            return false;
          }
        }
        return true;
      }
      function isCallOrRetMnemonic(mnemonic) {
        return mnemonic === "call" || mnemonic === "ret" || mnemonic === "retf";
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
            updateNativeTargetModuleMap();
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
            updateNativeTargetModuleMap();
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
            ensureClassifier();
            const onBlockStart = g_on_block_start_callout;
            const onBranchExecute = g_on_branch_execute_callout;
            Stalker.follow(tid, {
              events: { call: true, ret: true },
              transform(iterator) {
                let instruction = iterator.next();
                if (instruction === null)
                  return;
                iterator.putCallout(onBlockStart, allocBlockStartData(tid, instruction.address));
                do {
                  const mnemonic = instruction.mnemonic;
                  const isJump = isJumpMnemonic(mnemonic);
                  if (isJump || isCallOrRetMnemonic(mnemonic)) {
                    iterator.putCallout(onBranchExecute, allocBranchData(tid, instruction.address, isJump));
                  }
                  iterator.keep();
                  instruction = iterator.next();
                } while (instruction !== null);
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
                drainNativeTransitions();
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
        if (!g_oep_reached) {
          send({ type: "status", text: "thread_scan_deferred reason=" + reason + " before_oep=1" });
          return;
        }
        setTimeout(() => scanThreads(reason), FAILURE_SCAN_DELAY_MS);
      }
      function findMainOep() {
        const mainMod = Process.enumerateModules()[0];
        if (!mainMod)
          return null;
        try {
          const base = mainMod.base;
          if (base.readU16() !== 23117)
            return null;
          const pe = base.add(base.add(60).readU32());
          if (pe.readU32() !== 17744)
            return null;
          const optional = pe.add(24);
          const magic = optional.readU16();
          if (magic !== 267 && magic !== 523)
            return null;
          const entryRva = optional.add(16).readU32();
          if (entryRva === 0)
            return null;
          return base.add(entryRva);
        } catch (_) {
          return null;
        }
      }
      function markOepReached(source) {
        if (g_oep_reached)
          return;
        g_oep_reached = true;
        send({ type: "status", text: "oep_reached source=" + source });
        scanThreads("after_oep");
      }
      function hookMainOep() {
        if (g_oep_hooked)
          return;
        g_oep_hooked = true;
        const oep = findMainOep();
        if (!oep) {
          send({ type: "status", text: "oep_probe_oep_not_found" });
        } else {
          send({ type: "status", text: "oep_probe address=" + ph(oep) });
        }
        let hooks = 0;
        for (const moduleName of ["kernel32.dll", "kernelbase.dll"]) {
          const mod = Process.findModuleByName(moduleName);
          if (!mod)
            continue;
          const addr = mod.findExportByName("SetUnhandledExceptionFilter");
          if (!addr)
            continue;
          try {
            Interceptor.attach(addr, {
              onLeave(_) {
                markOepReached("SetUnhandledExceptionFilter_onleave");
              }
            });
            hooks++;
            send({
              type: "status",
              text: "oep_suef_hook module=" + moduleName + " address=" + ph(addr)
            });
          } catch (e) {
            send({
              type: "status",
              text: "oep_suef_hook_failed module=" + moduleName + " " + e
            });
          }
        }
        if (hooks === 0) {
          send({ type: "status", text: "oep_suef_hook_failed no_export=1" });
        }
      }
      function beginTrace(initialTids = []) {
        if (g_started)
          return;
        g_started = true;
        hookMainOep();
        for (const tid of initialTids)
          attachStalker(tid, "initial");
        send({ type: "status", text: "trace_threads=" + Array.from(g_stalked).join(",") });
        g_status_timer = setInterval(() => {
          sendTraceChunk("periodic");
          send({
            type: "status",
            text: "trace_stats events=" + g_events.length + " modules=" + g_mod_events.length + " sync=" + g_sync_events.length + " handles=" + g_handle_events.length
          });
        }, 1e3);
      }
      function enumerateInitialThreadIds() {
        try {
          return Process.enumerateThreads().map((t) => t.id);
        } catch (_) {
          return [];
        }
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
            if (!g_oep_reached) {
              send({ type: "status", text: "thread_observer:defer_attach tid=" + tid + " reason=before_oep" });
              return;
            }
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
        drainNativeTransitions();
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
        cleanupStalkers(reason);
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
      function cleanupStalkers(reason) {
        if (g_stalker_cleanup_done)
          return;
        g_stalker_cleanup_done = true;
        let unfollowed = 0;
        let failed = 0;
        for (const tid of Array.from(g_stalked)) {
          try {
            Stalker.unfollow(tid);
            unfollowed++;
          } catch (e) {
            failed++;
            send({
              type: "status",
              text: "stalker_unfollow_failed:tid=" + tid + " reason=" + reason + " " + e
            });
          }
        }
        g_stalked.clear();
        g_attach_failed.clear();
        try {
          Stalker.garbageCollect();
          send({
            type: "status",
            text: "stalker_cleanup reason=" + reason + " unfollowed=" + unfollowed + " failed=" + failed
          });
        } catch (e) {
          send({
            type: "status",
            text: "stalker_garbage_collect_failed reason=" + reason + " " + e
          });
        }
      }
      (function main() {
        if (Process.arch !== "x64" && Process.arch !== "ia32") {
          throw new Error("unsupported architecture: " + Process.arch + " (x64/ia32 required)");
        }
        Stalker.queueDrainInterval = 0;
        Stalker.trustThreshold = -1;
        send({ type: "status", text: "agent:start session=" + SESSION_ID + " arch=" + Process.arch });
        send({
          type: "status",
          text: "bootstrap shm=" + BOOTSTRAP_SHM_NAME + " wake=" + BOOTSTRAP_WAKE_EVENT_NAME + " size=" + BOOTSTRAP_SHM_SIZE_TEXT + " main_pid=" + BOOTSTRAP_MAIN_PID_TEXT + " main_tid=" + BOOTSTRAP_MAIN_TID_TEXT
        });
        const mainMod = Process.enumerateModules()[0];
        if (mainMod)
          g_targets.add(normalizedTargetName(mainMod.name));
        hookModules();
        hookThreadCreation();
        hookExceptions();
        hookExit();
        rebuildTargetModuleRecords();
        hookLoadedTargetExports();
        setImmediate(() => beginTrace(enumerateInitialThreadIds()));
      })();
    }
  });
  require_agent();
})();
