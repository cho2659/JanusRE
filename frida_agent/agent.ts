/**
 * agent.ts  –  Frida Stalker 에이전트 (Windows x64 / WoW64 x86)
 *
 * 빌드: frida-compile agent.ts -o agent.js
 *
 * 설계:
 *   - CALL + RET + JMP 계열 Stalker 추적
 *   - 최적화/필터링보다 누락 방지를 우선한다.
 *   - Stalker call/ret/jump 이벤트는 tt/tf bitmap으로 필터링한다.
 *   - 메인 EXE 종료만 flush 트리거
 */

"use strict";

// ══════════════════════════════════════════════════════════
// 타입 정의
// ══════════════════════════════════════════════════════════

interface RawEvent {
  k:   0 | 1 | 2;   // 0=call, 1=ret, 2=jump
  src: string;  // 출발지 VA hex "0x..."
  dst: string;  // 목적지 VA hex
  tid: number;
  seq: number;  // 단조 증가 시퀀스 (모듈 타임라인 대조용)
  src_module?: string;
  src_offset?: string;
  src_symbol?: string;
  dst_module?: string;
  dst_offset?: string;
  dst_symbol?: string;
  dst_is_external?: boolean;
  src_tt?: boolean;
  dst_tt?: boolean;
  is_jump?: boolean;
  source?: string;
}

interface ModuleEvent {
  seq:    number;
  action: "load" | "unload";
  name:   string;
  base:   string; // hex
  size:   number;
}

interface SyncEvent {
  seq:       number;
  tid:       number;
  api:       string;
  kind:      "set_event" | "pulse_event" | "release_mutex"
           | "wait_single" | "wait_multiple"
           | "queue_apc"   | "alpc"
           | "post_message" | "send_message"
           | "get_message"  | "peek_message";
  handle:    string;
  handle_gen?: number;
  caller_va: string; // 타겟 모듈 내 역추적 VA, 없으면 "unknown"
  status?:   string;
  msg_id?:   number;
  wparam?:   string;
  lparam?:   string;
  timeout?:  number; // ms, -1=INFINITE
}

interface ThreadSpawnEvent {
  seq:        number;
  api:        string;
  parent_tid: number;
  child_tid:  number;
  thread_handle: string;
  handle_gen?: number;
  creator_va: string; // 타겟 내 역추적 VA
  creator_module?: string;
  creator_offset?: string;
  creator_symbol?: string;
  start_va:   string; // 새 스레드 시작 루틴 VA
  start_module?: string;
  start_offset?: string;
  start_symbol?: string;
  status?:    string;
}

interface HandleEvent {
  seq:        number;
  tid:        number;
  action:     "create" | "duplicate" | "close";
  api:        string;
  handle:     string;
  handle_gen: number;
  status?:    string;
  kind?:      string;
  source_handle?: string;
  source_gen?: number;
}

interface ExceptionMarkerEvent {
  seq: number;
  tid: number;
  address: string;
  exception_type: string;
  module?: string;
  offset?: string;
}

type TargetModuleConfig = {
  name: string;
  trace: boolean;
  function_starts: string[];
};

// ══════════════════════════════════════════════════════════
// 전역 상태
// ══════════════════════════════════════════════════════════

const g_sync_events:  SyncEvent[]         = [];
const g_spawn_events: ThreadSpawnEvent[]  = [];
const g_handle_events: HandleEvent[]      = [];
const g_exception_events: ExceptionMarkerEvent[] = [];
const g_stalked:      Set<number>         = new Set();
const g_attach_failed:Set<number>         = new Set();

let g_seq     = 0;
let g_flushed = false;
let g_started = false;
let g_status_timer: ReturnType<typeof setInterval> | null = null;
let g_thread_api: ThreadApi | null = null;
let g_thread_observer: any = null;
let g_module_observer: any = null;
let g_oep_hooked = false;
let g_oep_reached = false;
let g_stalker_cleanup_done = false;
let g_sent_sync_events = 0;
let g_sent_spawn_events = 0;
let g_sent_handle_events = 0;
let g_sent_exception_events = 0;
let g_exception_handler_installed = false;

const g_handle_gen_by_key: Map<string, number> = new Map();
let g_next_handle_gen = 1;
const g_symbol_name_by_va: Map<string, string> = new Map();

type LastExternalCall = {
  caller_va: string;
  target_va: string;
  target_module: string;
  at_ms: number;
};

type LastBlockState = {
  last: NativePointer;
  isJump: boolean;
};

const g_last_external_call_by_tid: Map<number, LastExternalCall> = new Map();
const g_last_block_by_tid: Map<number, LastBlockState> = new Map();
const g_export_symbols_by_module: Map<string, Array<{ name: string; address: NativePointer }>> = new Map();

// 타겟 모듈 집합 (소문자). rpc.setTargets()로 갱신.
let g_targets: Set<string> = new Set();
const g_function_starts_by_module: Map<string, string[]> = new Map();

type TargetModuleRecord = {
  name: string;
  base: NativePointer;
  size: number;
  targetBits: NativePointer;
  functionBits: NativePointer;
};

const g_target_module_records: TargetModuleRecord[] = [];
let g_classifier_module: CModule | null = null;
let g_bitmap_test: ((bits: NativePointer, bitCount: number, offset: number) => number) | null = null;
let g_on_block_start_callout: NativePointer | null = null;
let g_on_branch_execute_callout: NativePointer | null = null;
let g_shared_init: (() => number) | null = null;
let g_shared_alloc_callout: ((size: number) => NativePointer) | null = null;
let g_shared_write_event: ((kind: number, tid: number, src: NativePointer, dst: NativePointer, flags: number) => void) | null = null;

const SESSION_ID  = generateUUID();
const BOOTSTRAP_SHM_NAME = "__FRIDA_DELTA_SHM_NAME__";
const BOOTSTRAP_WAKE_EVENT_NAME = "__FRIDA_DELTA_WAKE_EVENT_NAME__";
const BOOTSTRAP_SHM_SIZE_TEXT = "__FRIDA_DELTA_SHM_SIZE__";
const BOOTSTRAP_MAIN_PID_TEXT = "__FRIDA_DELTA_MAIN_PID__";
const BOOTSTRAP_MAIN_TID_TEXT = "__FRIDA_DELTA_MAIN_TID__";
const MAX_BT      = 24; // 콜스택 역추적 최대 깊이
const FAILURE_SCAN_DELAY_MS = 50;
const LAST_EXTERNAL_CALL_TTL_MS = 1500;
const NATIVE_SLOT_COUNT = 4096;
const NATIVE_MODULE_CAPACITY = 1024;
const NATIVE_MODULE_RECORD_SIZE = 32;

// ══════════════════════════════════════════════════════════
// 유틸
// ══════════════════════════════════════════════════════════

function generateUUID(): string {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === "x" ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

function ph(p: NativePointer): string {
  return "0x" + p.toString(16).toUpperCase();
}

function nextSeq(): number { return g_seq++; }

function ntStatus(rv: NativePointer): string {
  return ph(rv);
}

function ntSuccess(rv: NativePointer): boolean {
  return rv.toInt32() >= 0;
}

function handleKey(handle: NativePointer | string): string {
  if (typeof handle === "string") return handle.toLowerCase();
  return ph(handle).toLowerCase();
}

function recordHandleCreate(
  api: string, handle: NativePointer, status: string, kind: string,
): number {
  const key = handleKey(handle);
  const gen = g_next_handle_gen++;
  g_handle_gen_by_key.set(key, gen);
  const ev: HandleEvent = {
    seq: nextSeq(), tid: Process.getCurrentThreadId(),
    action: "create", api, handle: ph(handle), handle_gen: gen,
    status, kind,
  };
  g_handle_events.push(ev);
  return gen;
}

function normalizedTargetName(name: string): string {
  const raw = (name || "").toLowerCase().replace(/\\/g, "/");
  const parts = raw.split("/");
  return parts[parts.length - 1] || raw;
}

function isTarget(mod: { name: string } | null): boolean {
  if (!mod) return false;
  return g_targets.has(normalizedTargetName(mod.name));
}

function wcharArrayLiteral(value: string): string {
  const out: number[] = [];
  for (let i = 0; i < value.length; i++) {
    out.push(value.charCodeAt(i));
  }
  out.push(0);
  return out.join(", ");
}

function ensureClassifier(): void {
  if (g_shared_init) return;
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
    p_sleep: k32.getExportByName("Sleep"),
  });
  g_bitmap_test = new NativeFunction(
    (g_classifier_module as any).bitmap_test,
    "int",
    ["pointer", "uint64", "uint64"],
  ) as unknown as ((bits: NativePointer, bitCount: number, offset: number) => number);
  g_on_block_start_callout = (g_classifier_module as any).on_block_start as NativePointer;
  g_on_branch_execute_callout = (g_classifier_module as any).on_branch_execute as NativePointer;
  g_shared_init = new NativeFunction(
    (g_classifier_module as any).init_shared_memory,
    "int",
    [],
  ) as unknown as (() => number);
  g_shared_alloc_callout = new NativeFunction(
    (g_classifier_module as any).alloc_callout_data,
    "pointer",
    ["uint32"],
  ) as unknown as ((size: number) => NativePointer);
  g_shared_write_event = new NativeFunction(
    (g_classifier_module as any).record_event,
    "void",
    ["uint32", "uint32", "pointer", "pointer", "uint32"],
  ) as unknown as ((kind: number, tid: number, src: NativePointer, dst: NativePointer, flags: number) => void);
  g_shared_init();
}

function pointerOffset(addr: NativePointer, base: NativePointer): number {
  return parseInt(addr.sub(base).toString(16), 16);
}

function writeU64Number(dst: NativePointer, value: number): void {
  dst.writeU64(uint64(value));
}

function writeU64Pointer(dst: NativePointer, value: NativePointer): void {
  dst.writeU64(0);
  dst.writePointer(value);
}

function allocBlockStartData(tid: number, start: NativePointer): NativePointer {
  ensureClassifier();
  if (!g_shared_alloc_callout) return ptr(0);
  const data = g_shared_alloc_callout(16);
  if (data.isNull()) return data;
  data.writeU32(tid);
  data.add(4).writeU32(0);
  writeU64Pointer(data.add(8), start);
  return data;
}

function allocBranchData(tid: number, address: NativePointer, kind: number): NativePointer {
  ensureClassifier();
  if (!g_shared_alloc_callout) return ptr(0);
  const data = g_shared_alloc_callout(16);
  if (data.isNull()) return data;
  data.writeU32(tid);
  data.add(4).writeU32(kind);
  writeU64Pointer(data.add(8), address);
  return data;
}

function updateNativeTargetModuleMap(): void {
  ensureClassifier();
}

function drainNativeTransitions(): void {
  ensureClassifier();
}

function allocBitmap(bitCount: number, fill: boolean, offsets: string[] = []): NativePointer {
  void bitCount;
  void fill;
  void offsets;
  return ptr(0);
}

function removeTargetModuleRecord(mod: Module): void {
  for (let i = g_target_module_records.length - 1; i >= 0; i--) {
    const rec = g_target_module_records[i]!;
    if (rec.name === normalizedTargetName(mod.name)
        && rec.base.equals(mod.base)) {
      g_target_module_records.splice(i, 1);
    }
  }
}

function refreshTargetModuleRecord(mod: Module): void {
  const name = normalizedTargetName(mod.name);
  removeTargetModuleRecord(mod);
  if (!g_targets.has(name)) return;
  const starts = g_function_starts_by_module.get(name) || [];
  g_target_module_records.push({
    name,
    base: mod.base,
    size: mod.size,
    targetBits: allocBitmap(mod.size, true),
    functionBits: allocBitmap(mod.size, false, starts),
  });
}

function rebuildTargetModuleRecords(): void {
  g_target_module_records.length = 0;
  for (const mod of Process.enumerateModules()) {
    refreshTargetModuleRecord(mod);
  }
  updateNativeTargetModuleMap();
}

function targetRecordForAddress(addr: NativePointer | null): TargetModuleRecord | null {
  if (!addr) return null;
  for (const rec of g_target_module_records) {
    if (addr.compare(rec.base) >= 0
        && addr.compare(rec.base.add(rec.size)) < 0) {
      return rec;
    }
  }
  return null;
}

function classifyAddress(addr: NativePointer | null): {
  tt: boolean;
  functionStart: boolean;
} {
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

function moduleOffset(addr: NativePointer, mod: Module | null): string {
  if (!mod) return "0x0";
  return "0x" + addr.sub(mod.base).toString(16).toUpperCase();
}

function symbolName(addr: NativePointer): string {
  const key = ph(addr);
  const cached = g_symbol_name_by_va.get(key);
  if (cached !== undefined) return cached;
  let name = "";
  try {
    const sym = DebugSymbol.fromAddress(addr);
    if (sym && sym.name) name = sym.name;
  } catch (_) {
    // fall through
  }
  if (!name) name = exportSymbolName(addr);
  g_symbol_name_by_va.set(key, name);
  return name;
}

function exportSymbolName(addr: NativePointer): string {
  const mod = findModuleSafe(addr);
  if (!mod) return "";
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
    } catch (_) {}
    symbols.sort((a, b) => a.address.compare(b.address));
    g_export_symbols_by_module.set(key, symbols);
  }
  let best: { name: string; address: NativePointer } | null = null;
  for (const sym of symbols) {
    if (sym.address.compare(addr) > 0) break;
    best = sym;
  }
  if (!best) return "";
  const delta = addr.sub(best.address).toInt32();
  if (delta === 0) return best.name;
  if (delta > 0 && delta < 0x2000) {
    return best.name + "+0x" + delta.toString(16).toUpperCase();
  }
  return "";
}

function findModuleSafe(addr: NativePointer | null): Module | null {
  if (!addr) return null;
  try {
    return Process.findModuleByAddress(addr);
  } catch (_) {
    return null;
  }
}

function pointerDetails(va: string): { module: string; offset: string; symbol: string } {
  if (!va || va === "unknown") {
    return { module: "unknown", offset: "0x0", symbol: "" };
  }
  try {
    const p = ptr(va);
    const mod = findModuleSafe(p);
    return {
      module: mod ? mod.name : "unknown",
      offset: moduleOffset(p, mod),
      symbol: symbolName(p),
    };
  } catch (_) {
    return { module: "unknown", offset: "0x0", symbol: "" };
  }
}

function noteExternalBoundaryCall(
  tid: number, loc: NativePointer, target: NativePointer, dstMod: Module | null,
): void {
  if (!dstMod) return;
  g_last_external_call_by_tid.set(tid, {
    caller_va: ph(loc),
    target_va: ph(target),
    target_module: dstMod.name,
    at_ms: Date.now(),
  });
}

function recordTraceEvent(
  kind: "call" | "ret",
  loc: NativePointer,
  target: NativePointer,
  tid: number,
  source: string,
): void {
  void source;
  ensureClassifier();
  if (!g_shared_write_event) return;
  g_shared_write_event(kind === "call" ? 0 : 1, tid, loc, target, 0);
}

function recordJumpEvent(
  loc: NativePointer,
  target: NativePointer,
  tid: number,
  source: string,
): void {
  void source;
  ensureClassifier();
  if (!g_shared_write_event) return;
  g_shared_write_event(2, tid, loc, target, 4);
}

function isJumpMnemonic(mnemonic: string): boolean {
  if (mnemonic.length < 2) return false;
  const first = mnemonic.charCodeAt(0);
  if (first !== 0x6a && first !== 0x4a) return false; // j/J
  if (mnemonic === "jmp" || mnemonic === "JMP") return true;
  for (let i = 1; i < mnemonic.length; i++) {
    const c = mnemonic.charCodeAt(i);
    const lower = c | 0x20;
    if (!((lower >= 0x61 && lower <= 0x7a)
        || (c >= 0x30 && c <= 0x39))) {
      return false;
    }
  }
  return true;
}

function isCallOrRetMnemonic(mnemonic: string): boolean {
  return mnemonic === "call" || mnemonic === "ret" || mnemonic === "retf";
}

function branchEventKind(mnemonic: string, isJump: boolean): number | null {
  if (isJump) return 2;
  if (mnemonic === "call") return 0;
  if (mnemonic === "ret" || mnemonic === "retf") return 1;
  return null;
}

function recordBlockTransition(
  tid: number,
  blockStart: NativePointer,
  blockLast: NativePointer,
  blockEndsWithJump: boolean,
): void {
  const prev = g_last_block_by_tid.get(tid);
  if (prev && prev.isJump) {
    recordJumpEvent(prev.last, blockStart, tid, "stalker_jump");
  }
  g_last_block_by_tid.set(tid, {
    last: blockLast,
    isJump: blockEndsWithJump,
  });
}

function hookTargetExports(mod: Module): void {
  void mod;
}

function tailJumpSite(entry: NativePointer): NativePointer {
  return entry.add(6);
}

function detectVtableTailJump(entry: NativePointer, ctx: CpuContext): NativePointer | null {
  if (Process.arch !== "x64") return null;

  let disp = -1;
  try {
    if (entry.readU8() !== 0x48) return null;
    if (entry.add(1).readU8() !== 0x8b) return null;
    if (entry.add(2).readU8() !== 0x09) return null;
    if (entry.add(3).readU8() !== 0x48) return null;
    if (entry.add(4).readU8() !== 0x8b) return null;
    if (entry.add(5).readU8() !== 0x01) return null;
    if (entry.add(6).readU8() !== 0x48) return null;
    if (entry.add(7).readU8() !== 0xff) return null;
    if (entry.add(8).readU8() !== 0x60) return null;
    disp = entry.add(9).readU8();
  } catch (_) {
    return null;
  }

  try {
    const x64 = ctx as X64CpuContext;
    const thisPtr = x64.rcx;
    if (!thisPtr || thisPtr.isNull()) return null;
    const implThis = thisPtr.readPointer();
    if (implThis.isNull()) return null;
    const vtable = implThis.readPointer();
    if (vtable.isNull()) return null;
    const target = vtable.add(disp).readPointer();
    if (target.isNull()) return null;
    if (!findModuleSafe(target)) return null;
    return target;
  } catch (_) {
    return null;
  }
}

function hookLoadedTargetExports(): void {
  // Target export Interceptor recording is intentionally disabled.
}

/**
 * 콜스택 역추적: stack pointer를 읽어 리턴 어드레스 체인을 탐색.
 * 타겟 모듈 범위에 속하는 가장 가까운 프레임 VA 반환.
 * 찾지 못하면 "unknown".
 */
function findTargetCaller(ctx: CpuContext, immediateReturn?: NativePointer): string {
  const immediateMod = findModuleSafe(immediateReturn || null);
  if (immediateMod && g_targets.has(immediateMod.name.toLowerCase())) {
    return ph(immediateReturn!);
  }

  const arch = Process.arch;
  const x64 = ctx as X64CpuContext;
  const ia32 = ctx as Ia32CpuContext;
  let rsp = arch === "ia32" ? ia32.esp : x64.rsp;
  for (let i = 0; i < MAX_BT; i++) {
    let ra: NativePointer;
    try { ra = rsp.readPointer(); } catch (_) { break; }
    if (ra.isNull()) break;
    const mod = findModuleSafe(ra);
    if (mod && g_targets.has(mod.name.toLowerCase())) return ph(ra);
    rsp = rsp.add(Process.pointerSize);
  }
  return "unknown";
}

function findThreadCreator(ctx: CpuContext, immediateReturn?: NativePointer): string {
  const tid = Process.getCurrentThreadId();
  const last = g_last_external_call_by_tid.get(tid);
  const lastMod = last ? last.target_module.toLowerCase() : "";
  const looksLikeThreadApi = lastMod === "ntdll.dll"
    || lastMod === "kernel32.dll"
    || lastMod === "kernelbase.dll";
  if (last && looksLikeThreadApi
      && Date.now() - last.at_ms <= LAST_EXTERNAL_CALL_TTL_MS) {
    return last.caller_va;
  }
  return findTargetCaller(ctx, immediateReturn);
}

type ThreadApi = {
  getThreadId: ((h: NativePointer) => number) | null;
  suspendThread: (h: NativePointer) => number;
  resumeThread: (h: NativePointer) => number;
  openThread: (access: number, inherit: number, tid: number) => NativePointer;
  closeHandle: (h: NativePointer) => boolean;
};

const THREAD_SUSPEND_RESUME = 0x0002;

function getThreadApi(): ThreadApi | null {
  if (g_thread_api) return g_thread_api;
  try {
    const k32 = Process.getModuleByName("kernel32.dll");
    const getThreadIdAddr = k32.findExportByName("GetThreadId");
    const getThreadId = getThreadIdAddr
      ? (new NativeFunction(getThreadIdAddr, "uint32", ["pointer"]) as unknown as ((h: NativePointer) => number))
      : null;
    g_thread_api = {
      getThreadId,
      suspendThread: new NativeFunction(k32.getExportByName("SuspendThread"), "int32", ["pointer"]) as unknown as ((h: NativePointer) => number),
      resumeThread: new NativeFunction(k32.getExportByName("ResumeThread"), "int32", ["pointer"]) as unknown as ((h: NativePointer) => number),
      openThread: new NativeFunction(k32.getExportByName("OpenThread"), "pointer", ["uint32", "bool", "uint32"]) as unknown as ((access: number, inherit: number, tid: number) => NativePointer),
      closeHandle: new NativeFunction(k32.getExportByName("CloseHandle"), "bool", ["pointer"]) as unknown as ((h: NativePointer) => boolean),
    };
    return g_thread_api;
  } catch (e) {
    send({ type: "status", text: "thread_api_failed " + e });
    return null;
  }
}

function withThreadSuspended(tid: number, reason: string, fn: () => boolean): boolean {
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

// ══════════════════════════════════════════════════════════
// 모듈 타임라인
// ══════════════════════════════════════════════════════════

function recordLoad(name: string, base: NativePointer, size: number) {
  void name;
  ensureClassifier();
  if (g_shared_write_event) {
    g_shared_write_event(3, Process.getCurrentThreadId(), base, ptr(size), 1);
  }
}
function recordUnload(name: string, base: NativePointer, size: number) {
  void name;
  ensureClassifier();
  if (g_shared_write_event) {
    g_shared_write_event(3, Process.getCurrentThreadId(), base, ptr(size), 2);
  }
}

function hookModules(): void {
  if (g_module_observer) return;
  if (typeof Process.attachModuleObserver !== "function") {
    throw new Error("Process.attachModuleObserver is not available");
  }
  g_module_observer = Process.attachModuleObserver({
    onAdded(mod) {
      recordLoad(mod.name, mod.base, mod.size);
      refreshTargetModuleRecord(mod);
      updateNativeTargetModuleMap();
      if (g_targets.size > 0) hookTargetExports(mod);
      send({
        type: "status",
        text: "module_observer:add " + mod.name + " base=" + ph(mod.base),
      });
    },
    onRemoved(mod) {
      recordUnload(mod.name, mod.base, mod.size);
      removeTargetModuleRecord(mod);
      updateNativeTargetModuleMap();
      send({
        type: "status",
        text: "module_observer:remove " + mod.name + " base=" + ph(mod.base),
      });
    },
  });
}

// ══════════════════════════════════════════════════════════
// Stalker
// ══════════════════════════════════════════════════════════

function attachStalker(tid: number, reason: string = "unknown"): boolean {
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
      const onBlockStart = g_on_block_start_callout!;
      const onBranchExecute = g_on_branch_execute_callout!;
      Stalker.follow(tid, {
        events: { call: false, ret: false },

        transform(iterator: StalkerArm64Iterator | StalkerArmIterator | StalkerThumbIterator | StalkerX86Iterator): void {
          let instruction = iterator.next();
          if (instruction === null) return;

          iterator.putCallout(onBlockStart, allocBlockStartData(tid, instruction.address));
          do {
            const mnemonic = instruction.mnemonic;
            const isJump = isJumpMnemonic(mnemonic);
            const branchKind = branchEventKind(mnemonic, isJump);
            if (branchKind !== null) {
              iterator.putCallout(
                onBranchExecute,
                allocBranchData(tid, instruction.address, branchKind),
              );
            }
            iterator.keep();
            instruction = iterator.next();
          } while (instruction !== null);
        },
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

function scanThreads(reason: string): void {
  const currentTid = Process.getCurrentThreadId();
  const tids = Process.enumerateThreads()
    .map(t => t.id)
    .filter(tid => tid !== currentTid);
  let attempted = 0;
  for (const tid of tids) {
    if (g_stalked.has(tid)) continue;
    attempted++;
    attachStalker(tid, reason);
  }
  send({
    type: "status",
    text: "thread_scan reason=" + reason
      + " seen=" + tids.length
      + " stalked=" + g_stalked.size
      + " failed=" + g_attach_failed.size
      + " attempted=" + attempted,
  });
}

function scheduleFailureScan(reason: string): void {
  if (!g_oep_reached) {
    send({ type: "status", text: "thread_scan_deferred reason=" + reason + " before_oep=1" });
    return;
  }
  setTimeout(() => scanThreads(reason), FAILURE_SCAN_DELAY_MS);
}

function findMainOep(): NativePointer | null {
  const mainMod = Process.enumerateModules()[0];
  if (!mainMod) return null;

  try {
    const base = mainMod.base;
    if (base.readU16() !== 0x5a4d) return null;
    const pe = base.add(base.add(0x3c).readU32());
    if (pe.readU32() !== 0x00004550) return null;
    const optional = pe.add(24);
    const magic = optional.readU16();
    if (magic !== 0x10b && magic !== 0x20b) return null;
    const entryRva = optional.add(16).readU32();
    if (entryRva === 0) return null;
    return base.add(entryRva);
  } catch (_) {
    return null;
  }
}

function markOepReached(source: string): void {
  if (g_oep_reached) return;
  g_oep_reached = true;
  send({ type: "status", text: "oep_reached source=" + source });
  scanThreads("after_oep");
}

function hookMainOep(): void {
  if (g_oep_hooked) return;
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
    if (!mod) continue;
    const addr = mod.findExportByName("SetUnhandledExceptionFilter");
    if (!addr) continue;

    try {
      Interceptor.attach(addr, {
        onLeave(_) {
          markOepReached("SetUnhandledExceptionFilter_onleave");
        },
      });
      hooks++;
      send({
        type: "status",
        text: "oep_suef_hook module=" + moduleName + " address=" + ph(addr),
      });
    } catch (e) {
      send({
        type: "status",
        text: "oep_suef_hook_failed module=" + moduleName + " " + e,
      });
    }
  }

  if (hooks === 0) {
    send({ type: "status", text: "oep_suef_hook_failed no_export=1" });
  }
}

function beginTrace(initialTids: number[] = []): void {
  if (g_started) return;
  g_started = true;

  hookMainOep();
  for (const tid of initialTids) attachStalker(tid, "initial");
  send({ type: "status", text: "trace_threads=" + Array.from(g_stalked).join(",") });
  g_status_timer = setInterval(() => {
    send({
      type: "status",
      text: "trace_stats shared=1"
        + " sync=" + g_sync_events.length
        + " handles=" + g_handle_events.length,
    });
  }, 1000);
}

function enumerateInitialThreadIds(): number[] {
  try {
    return Process.enumerateThreads().map(t => t.id);
  } catch (_) {
    return [];
  }
}

// ══════════════════════════════════════════════════════════
// 스레드 관찰
// ══════════════════════════════════════════════════════════

function hookThreadCreation(): void {
  if (g_thread_observer) return;
  if (typeof Process.attachThreadObserver !== "function") {
    throw new Error("Process.attachThreadObserver is not available");
  }
  g_thread_observer = Process.attachThreadObserver({
    onAdded(thread) {
      const tid = thread.id;
      send({ type: "status", text: "thread_observer:add tid=" + tid });
      if (!g_started) return;
      g_spawn_events.push({
        seq: nextSeq(), api: "thread_observer",
        parent_tid: 0, child_tid: tid,
        thread_handle: "unknown",
        creator_va: "unknown", start_va: "unknown",
        creator_module: "unknown", creator_offset: "0x0",
        creator_symbol: "",
        start_module: "unknown", start_offset: "0x0",
        start_symbol: "",
        status: "observed",
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
        text: "thread_observer:rename tid=" + thread.id
          + " previous=" + (previousName || ""),
      });
    },
  });
}

// ══════════════════════════════════════════════════════════
// 프로세스 종료 감지
// ══════════════════════════════════════════════════════════

function hookExit(): void {
  const ntdll = Process.getModuleByName("ntdll.dll");
  for (const fn of ["RtlExitUserProcess", "NtTerminateProcess"]) {
    const addr = ntdll.findExportByName(fn);
    if (addr) {
      Interceptor.attach(addr, {
        onEnter(_) { flushAndSend("exit", fn); },
      });
    }
  }

  const k32 = Process.findModuleByName("kernel32.dll");
  if (!k32) return;
  for (const fn of ["ExitProcess", "TerminateProcess"]) {
    const addr = k32.findExportByName(fn);
    if (addr) {
      Interceptor.attach(addr, {
        onEnter(_) { flushAndSend("exit", fn); },
      });
    }
  }
}

function hookExceptions(): void {
  if (g_exception_handler_installed) return;
  g_exception_handler_installed = true;
  Process.setExceptionHandler((details: any) => {
    try {
      const address = details.address as NativePointer | undefined;
      const mod = address ? findModuleSafe(address) : null;
      if (g_started) {
        g_exception_events.push({
          seq: nextSeq(),
          tid: Process.getCurrentThreadId(),
          address: address ? ph(address) : "unknown",
          exception_type: String(details.type || "unknown"),
          module: mod ? mod.name : "unknown",
          offset: address ? moduleOffset(address, mod) : "0x0",
        });
      }
      send({
        type: "status",
        text: "exception_marker type=" + String(details.type || "unknown")
          + " address=" + (address ? ph(address) : "unknown"),
      });
    } catch (_) {}
    return false;
  });
}

// ══════════════════════════════════════════════════════════
// 데이터 전송
// ══════════════════════════════════════════════════════════

function flushAndSend(reason: "exit" | "user_stop", hookName?: string): void {
  if (g_flushed) return;
  g_flushed = true;
  if (g_status_timer !== null) {
    clearInterval(g_status_timer);
    g_status_timer = null;
  }

  send({
    type: "status",
    text: "flush_send hook=" + (hookName || "unknown") + " reason=" + reason
      + " shared=1",
  });

  cleanupStalkers(reason);
}

function cleanupStalkers(reason: string): void {
  if (g_stalker_cleanup_done) return;
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
        text: "stalker_unfollow_failed:tid=" + tid
          + " reason=" + reason + " " + e,
      });
    }
  }
  g_stalked.clear();
  g_attach_failed.clear();

  try {
    Stalker.garbageCollect();
    send({
      type: "status",
      text: "stalker_cleanup reason=" + reason
        + " unfollowed=" + unfollowed
        + " failed=" + failed,
    });
  } catch (e) {
    send({
      type: "status",
      text: "stalker_garbage_collect_failed reason=" + reason + " " + e,
    });
  }
}

// ══════════════════════════════════════════════════════════
// 진입점
// ══════════════════════════════════════════════════════════

(function main() {
  if (Process.arch !== "x64" && Process.arch !== "ia32") {
    throw new Error("unsupported architecture: " + Process.arch + " (x64/ia32 required)");
  }

  Stalker.queueDrainInterval = 0;
  Stalker.trustThreshold = -1;
  send({ type: "status", text: "agent:start session=" + SESSION_ID + " arch=" + Process.arch });
  send({
    type: "status",
    text: "bootstrap shm=" + BOOTSTRAP_SHM_NAME
      + " wake=" + BOOTSTRAP_WAKE_EVENT_NAME
      + " size=" + BOOTSTRAP_SHM_SIZE_TEXT
      + " main_pid=" + BOOTSTRAP_MAIN_PID_TEXT
      + " main_tid=" + BOOTSTRAP_MAIN_TID_TEXT,
  });

  // 메인 EXE를 초기 타겟으로
  const mainMod = Process.enumerateModules()[0];
  if (mainMod) g_targets.add(normalizedTargetName(mainMod.name));

  hookModules();
  hookThreadCreation();
  hookExceptions();
  hookExit();
  rebuildTargetModuleRecords();
  hookLoadedTargetExports();
  setImmediate(() => beginTrace(enumerateInitialThreadIds()));
})();
