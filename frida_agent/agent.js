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
      var g_exception_handler_installed = false;
      var g_targets = /* @__PURE__ */ new Set();
      var g_function_starts_by_module = /* @__PURE__ */ new Map();
      var g_target_module_records = [];
      var g_classifier_module = null;
      var g_bitmap_test = null;
      var g_on_block_start_callout = null;
      var g_on_branch_execute_callout = null;
      var g_shared_init = null;
      var g_shared_alloc_callout = null;
      var g_shared_write_event = null;
      var SESSION_ID = generateUUID();
      var BOOTSTRAP_SHM_NAME = "__FRIDA_DELTA_SHM_NAME__";
      var BOOTSTRAP_WAKE_EVENT_NAME = "__FRIDA_DELTA_WAKE_EVENT_NAME__";
      var BOOTSTRAP_SHM_SIZE_TEXT = "__FRIDA_DELTA_SHM_SIZE__";
      var BOOTSTRAP_MAIN_PID_TEXT = "__FRIDA_DELTA_MAIN_PID__";
      var BOOTSTRAP_MAIN_TID_TEXT = "__FRIDA_DELTA_MAIN_TID__";
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
      function wcharArrayLiteral(value) {
        const out = [];
        for (let i = 0; i < value.length; i++) {
          out.push(value.charCodeAt(i));
        }
        out.push(0);
        return out.join(", ");
      }
      function ensureClassifier() {
        if (g_shared_init)
          return;
        const k32 = Process.getModuleByName("kernel32.dll");
        const shmName = BOOTSTRAP_SHM_NAME;
        const wakeName = BOOTSTRAP_WAKE_EVENT_NAME;
        g_classifier_module = new CModule(`
    typedef unsigned short u16;
    typedef unsigned int u32;
    typedef unsigned long long u64;
    typedef void * gpointer;
    typedef void * HANDLE;
    typedef const unsigned short * LPCWSTR;
    typedef struct _GumCpuContext GumCpuContext;

    typedef struct {
      u32 tid;
      u32 reserved;
      u64 start;
    } BlockStartData;

    typedef struct {
      u32 tid;
      u32 kind;
      u64 address;
    } BranchData;

    #define SLOT_COUNT 4096
    #define FILE_MAP_ALL_ACCESS 0x000F001F
    #define EVENT_MODIFY_STATE 0x0002
    #define SYNCHRONIZE 0x00100000
    #define SHM_FLAG_BLOCK_ON_FULL 1
    #define SHM_FLAG_WAKE_ON_HIGH_WATERMARK 4

    #define OFF_STATE 0x08
    #define OFF_CONFIG_FLAGS 0x10
    #define OFF_WRITE_INDEX 0x28
    #define OFF_READ_INDEX 0x30
    #define OFF_DROPPED_COUNT 0x38
    #define OFF_RECORD_SIZE 0x40
    #define OFF_RECORD_CAPACITY 0x44
    #define OFF_CALLOUT_ARENA_OFFSET 0x5C
    #define OFF_CALLOUT_ARENA_SIZE 0x60
    #define OFF_CALLOUT_ARENA_WRITE_OFFSET 0x64
    #define OFF_EVENT_RING0_OFFSET 0x68
    #define OFF_EVENT_RING1_OFFSET 0x78
    #define OFF_ACTIVE_WRITE_BUFFER 0x7C
    #define OFF_HIGH_WATERMARK_PERCENT 0x84
    #define OFF_WAKE_EVENT_SIGNAL_COUNT 0x88
    #define OFF_BLOCKING_WAIT_COUNT 0x90

    extern void * p_open_file_mapping_w;
    extern void * p_map_view_of_file;
    extern void * p_open_event_w;
    extern void * p_set_event;
    extern void * p_sleep;

    static const unsigned short shm_name[] = { ${wcharArrayLiteral(shmName)} };
    static const unsigned short wake_event_name[] = { ${wcharArrayLiteral(wakeName)} };

    static unsigned char *shm_base = 0;
    static HANDLE wake_event = 0;
    static u64 native_last_src[SLOT_COUNT];
    static u32 native_last_is_jump[SLOT_COUNT];

    int bitmap_test(const unsigned char *bits,
                    unsigned long long bit_count,
                    unsigned long long offset) {
      if (bits == 0 || offset >= bit_count) return 0;
      return (bits[offset >> 3] >> (offset & 7)) & 1;
    }

    static u32 slot_for_tid(u32 tid) {
      return tid & (SLOT_COUNT - 1);
    }

    static u32 read_u32(u32 off) {
      return *(volatile u32 *) (shm_base + off);
    }

    static u64 read_u64(u32 off) {
      return *(volatile u64 *) (shm_base + off);
    }

    static void atomic_add_u64(u32 off, u64 value) {
      __sync_fetch_and_add((volatile u64 *) (shm_base + off), value);
    }

    static u64 atomic_fetch_add_u64(u32 off, u64 value) {
      return __sync_fetch_and_add((volatile u64 *) (shm_base + off), value);
    }

    static u32 atomic_fetch_add_u32(u32 off, u32 value) {
      return __sync_fetch_and_add((volatile u32 *) (shm_base + off), value);
    }

    int init_shared_memory(void) {
      typedef HANDLE (*OpenFileMappingWFunc)(u32, int, LPCWSTR);
      typedef void * (*MapViewOfFileFunc)(HANDLE, u32, u32, u32, u64);
      typedef HANDLE (*OpenEventWFunc)(u32, int, LPCWSTR);

      HANDLE mapping;
      if (shm_base != 0) return 1;
      mapping = ((OpenFileMappingWFunc) p_open_file_mapping_w)(
        FILE_MAP_ALL_ACCESS, 0, shm_name);
      if (mapping == 0) return 0;
      shm_base = (unsigned char *) ((MapViewOfFileFunc) p_map_view_of_file)(
        mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
      if (shm_base == 0) return 0;
      wake_event = ((OpenEventWFunc) p_open_event_w)(
        EVENT_MODIFY_STATE | SYNCHRONIZE, 0, wake_event_name);
      return 1;
    }

    gpointer alloc_callout_data(u32 size) {
      u32 arena_offset;
      u32 arena_size;
      u32 old_offset;
      if (init_shared_memory() == 0) return 0;
      arena_offset = read_u32(OFF_CALLOUT_ARENA_OFFSET);
      arena_size = read_u32(OFF_CALLOUT_ARENA_SIZE);
      old_offset = atomic_fetch_add_u32(OFF_CALLOUT_ARENA_WRITE_OFFSET, (size + 7) & ~7);
      if (old_offset + size > arena_size) return 0;
      return shm_base + arena_offset + old_offset;
    }

    static void signal_high_watermark_if_needed(u64 used, u32 capacity) {
      u32 percent;
      u32 flags;
      typedef int (*SetEventFunc)(HANDLE);
      if (wake_event == 0) return;
      flags = read_u32(OFF_CONFIG_FLAGS);
      if ((flags & SHM_FLAG_WAKE_ON_HIGH_WATERMARK) == 0) return;
      percent = read_u32(OFF_HIGH_WATERMARK_PERCENT);
      if (percent == 0) percent = 80;
      if (used * 100 < ((u64) capacity) * percent) return;
      atomic_add_u64(OFF_WAKE_EVENT_SIGNAL_COUNT, 1);
      ((SetEventFunc) p_set_event)(wake_event);
    }

    static void record_event_u64(u32 kind, u32 tid, u64 src, u64 dst, u32 flags) {
      u32 capacity;
      u32 record_size;
      u64 read_index;
      u64 write_index;
      u64 slot;
      u64 used;
      u32 ring_offset;
      unsigned char *record;
      typedef void (*SleepFunc)(u32);

      if (init_shared_memory() == 0) return;
      capacity = read_u32(OFF_RECORD_CAPACITY);
      record_size = read_u32(OFF_RECORD_SIZE);
      if (capacity == 0 || record_size == 0) return;

      while (1) {
        read_index = read_u64(OFF_READ_INDEX);
        write_index = read_u64(OFF_WRITE_INDEX);
        if (write_index - read_index < capacity) break;
        if ((read_u32(OFF_CONFIG_FLAGS) & SHM_FLAG_BLOCK_ON_FULL) == 0) {
          atomic_add_u64(OFF_DROPPED_COUNT, 1);
          return;
        }
        atomic_add_u64(OFF_BLOCKING_WAIT_COUNT, 1);
        ((SleepFunc) p_sleep)(0);
      }

      slot = atomic_fetch_add_u64(OFF_WRITE_INDEX, 1);
      read_index = read_u64(OFF_READ_INDEX);
      if (slot - read_index >= capacity) {
        if ((read_u32(OFF_CONFIG_FLAGS) & SHM_FLAG_BLOCK_ON_FULL) != 0) {
          while (slot - read_u64(OFF_READ_INDEX) >= capacity) {
            atomic_add_u64(OFF_BLOCKING_WAIT_COUNT, 1);
            ((SleepFunc) p_sleep)(0);
          }
        } else {
          atomic_add_u64(OFF_DROPPED_COUNT, 1);
          return;
        }
      }

      ring_offset = read_u32(OFF_EVENT_RING0_OFFSET);
      if (read_u32(OFF_ACTIVE_WRITE_BUFFER) == 1) {
        ring_offset = read_u32(OFF_EVENT_RING1_OFFSET);
      }

      record = shm_base + ring_offset + (slot % capacity) * record_size;
      *(u16 *) (record + 0x00) = (u16) kind;
      *(u16 *) (record + 0x02) = (u16) flags;
      *(u32 *) (record + 0x04) = tid;
      *(u64 *) (record + 0x08) = slot;
      *(u64 *) (record + 0x10) = src;
      *(u64 *) (record + 0x18) = dst;
      *(u64 *) (record + 0x20) = 0;
      *(u64 *) (record + 0x28) = 0;
      *(u64 *) (record + 0x30) = 0;
      *(u64 *) (record + 0x38) = 0;

      used = slot + 1 - read_index;
      signal_high_watermark_if_needed(used, capacity);
    }

    void record_event(u32 kind, u32 tid, gpointer src, gpointer dst, u32 flags) {
      record_event_u64(kind, tid, (u64) src, (u64) dst, flags);
    }

    void on_block_start(GumCpuContext *cpu_context, gpointer user_data) {
      BlockStartData *data = (BlockStartData *) user_data;
      u32 slot;
      (void) cpu_context;
      if (data == 0) return;

      slot = slot_for_tid(data->tid);
      if (native_last_is_jump[slot] != 0) {
        record_event_u64(2, data->tid, native_last_src[slot], data->start, 4);
        native_last_is_jump[slot] = 0;
      }
    }

    void on_branch_execute(GumCpuContext *cpu_context, gpointer user_data) {
      BranchData *data = (BranchData *) user_data;
      u32 slot;
      (void) cpu_context;
      if (data == 0) return;

      slot = slot_for_tid(data->tid);
      if (data->kind == 2) {
        native_last_src[slot] = data->address;
        native_last_is_jump[slot] = 1;
      } else {
        record_event_u64(data->kind, data->tid, data->address, 0, 0);
        native_last_is_jump[slot] = 0;
      }
    }
  `, {
          p_open_file_mapping_w: k32.getExportByName("OpenFileMappingW"),
          p_map_view_of_file: k32.getExportByName("MapViewOfFile"),
          p_open_event_w: k32.getExportByName("OpenEventW"),
          p_set_event: k32.getExportByName("SetEvent"),
          p_sleep: k32.getExportByName("Sleep")
        });
        g_bitmap_test = new NativeFunction(g_classifier_module.bitmap_test, "int", ["pointer", "uint64", "uint64"]);
        g_on_block_start_callout = g_classifier_module.on_block_start;
        g_on_branch_execute_callout = g_classifier_module.on_branch_execute;
        g_shared_init = new NativeFunction(g_classifier_module.init_shared_memory, "int", []);
        g_shared_alloc_callout = new NativeFunction(g_classifier_module.alloc_callout_data, "pointer", ["uint32"]);
        g_shared_write_event = new NativeFunction(g_classifier_module.record_event, "void", ["uint32", "uint32", "pointer", "pointer", "uint32"]);
        g_shared_init();
      }
      function writeU64Pointer(dst, value) {
        dst.writeU64(0);
        dst.writePointer(value);
      }
      function allocBlockStartData(tid, start) {
        ensureClassifier();
        if (!g_shared_alloc_callout)
          return ptr(0);
        const data = g_shared_alloc_callout(16);
        if (data.isNull())
          return data;
        data.writeU32(tid);
        data.add(4).writeU32(0);
        writeU64Pointer(data.add(8), start);
        return data;
      }
      function allocBranchData(tid, address, kind) {
        ensureClassifier();
        if (!g_shared_alloc_callout)
          return ptr(0);
        const data = g_shared_alloc_callout(16);
        if (data.isNull())
          return data;
        data.writeU32(tid);
        data.add(4).writeU32(kind);
        writeU64Pointer(data.add(8), address);
        return data;
      }
      function updateNativeTargetModuleMap() {
        ensureClassifier();
      }
      function allocBitmap(bitCount, fill, offsets = []) {
        void bitCount;
        void fill;
        void offsets;
        return ptr(0);
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
      function moduleOffset(addr, mod) {
        if (!mod)
          return "0x0";
        return "0x" + addr.sub(mod.base).toString(16).toUpperCase();
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
      function branchEventKind(mnemonic, isJump) {
        if (isJump)
          return 2;
        if (mnemonic === "call")
          return 0;
        if (mnemonic === "ret" || mnemonic === "retf")
          return 1;
        return null;
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
        void name;
        ensureClassifier();
        if (g_shared_write_event) {
          g_shared_write_event(3, Process.getCurrentThreadId(), base, ptr(size), 1);
        }
      }
      function recordUnload(name, base, size) {
        void name;
        ensureClassifier();
        if (g_shared_write_event) {
          g_shared_write_event(3, Process.getCurrentThreadId(), base, ptr(size), 2);
        }
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
              events: { call: false, ret: false },
              transform(iterator) {
                let instruction = iterator.next();
                if (instruction === null)
                  return;
                iterator.putCallout(onBlockStart, allocBlockStartData(tid, instruction.address));
                do {
                  const mnemonic = instruction.mnemonic;
                  const isJump = isJumpMnemonic(mnemonic);
                  const branchKind = branchEventKind(mnemonic, isJump);
                  if (branchKind !== null) {
                    iterator.putCallout(onBranchExecute, allocBranchData(tid, instruction.address, branchKind));
                  }
                  iterator.keep();
                  instruction = iterator.next();
                } while (instruction !== null);
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
          send({
            type: "status",
            text: "trace_stats shared=1 sync=" + g_sync_events.length + " handles=" + g_handle_events.length
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
          text: "flush_send hook=" + (hookName || "unknown") + " reason=" + reason + " shared=1"
        });
        cleanupStalkers(reason);
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
