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

interface AgentPayload {
  type:         "trace_complete" | "trace_chunk";
  session_id:   string;
  reason:       "exit" | "user_stop" | "periodic";
  sent_at_ms:   number;
  events:       RawEvent[];
  mod_events:   ModuleEvent[];
  sync_events:  SyncEvent[];
  spawn_events: ThreadSpawnEvent[];
  handle_events: HandleEvent[];
  exception_events: ExceptionMarkerEvent[];
}

type TargetModuleConfig = {
  name: string;
  trace: boolean;
  function_starts: string[];
};

// ══════════════════════════════════════════════════════════
// 전역 상태
// ══════════════════════════════════════════════════════════

const g_events:       RawEvent[]          = [];
const g_mod_events:   ModuleEvent[]       = [];
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
let g_sent_events = 0;
let g_sent_mod_events = 0;
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
let g_drain_transitions: ((out: NativePointer, maxCount: number) => number) | null = null;
let g_transition_drain_buffer: NativePointer | null = null;
let g_native_last_src: NativePointer | null = null;
let g_native_last_is_jump: NativePointer | null = null;
let g_native_transitions: NativePointer | null = null;
let g_native_transition_read_index: NativePointer | null = null;
let g_native_transition_write_index: NativePointer | null = null;
let g_native_module_records: NativePointer | null = null;
let g_native_module_count: NativePointer | null = null;
let g_callout_arena_current: NativePointer | null = null;
let g_callout_arena_offset = 0;
let g_callout_arena_size = 0;
const g_callout_arena_chunks: NativePointer[] = [];

const SESSION_ID  = generateUUID();
const MAX_BT      = 24; // 콜스택 역추적 최대 깊이
const FAILURE_SCAN_DELAY_MS = 50;
const LAST_EXTERNAL_CALL_TTL_MS = 1500;
const NATIVE_SLOT_COUNT = 4096;
const NATIVE_QUEUE_CAPACITY = 65536;
const NATIVE_TRANSITION_SIZE = 24;
const NATIVE_TRANSITION_BATCH = 4096;
const NATIVE_MODULE_CAPACITY = 1024;
const NATIVE_MODULE_RECORD_SIZE = 32;
const CALLOUT_ARENA_CHUNK_SIZE = 4 * 1024 * 1024;

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

function allocZeroed(size: number): NativePointer {
  const mem = Memory.alloc(size);
  mem.writeByteArray(new Uint8Array(size).buffer);
  return mem;
}

function ensureClassifier(): void {
  if (g_bitmap_test) return;
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
    native_module_count: g_native_module_count,
  });
  g_bitmap_test = new NativeFunction(
    (g_classifier_module as any).bitmap_test,
    "int",
    ["pointer", "uint64", "uint64"],
  ) as unknown as ((bits: NativePointer, bitCount: number, offset: number) => number);
  g_on_block_start_callout = (g_classifier_module as any).on_block_start as NativePointer;
  g_on_branch_execute_callout = (g_classifier_module as any).on_branch_execute as NativePointer;
  g_drain_transitions = new NativeFunction(
    (g_classifier_module as any).drain_transitions,
    "uint32",
    ["pointer", "uint32"],
  ) as unknown as ((out: NativePointer, maxCount: number) => number);
  g_transition_drain_buffer = Memory.alloc(NATIVE_TRANSITION_SIZE * NATIVE_TRANSITION_BATCH);
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

function arenaAlloc(size: number, align: number = 8): NativePointer {
  const alignedOffset = (g_callout_arena_offset + align - 1) & ~(align - 1);
  if (!g_callout_arena_current
      || alignedOffset + size > g_callout_arena_size) {
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

function allocBlockStartData(tid: number, start: NativePointer): NativePointer {
  const data = arenaAlloc(16);
  data.writeU32(tid);
  data.add(4).writeU32(0);
  writeU64Pointer(data.add(8), start);
  return data;
}

function allocBranchData(tid: number, address: NativePointer, isJump: boolean): NativePointer {
  const data = arenaAlloc(16);
  data.writeU32(tid);
  data.add(4).writeU32(isJump ? 1 : 0);
  writeU64Pointer(data.add(8), address);
  return data;
}

function updateNativeTargetModuleMap(): void {
  ensureClassifier();
  if (!g_native_module_records || !g_native_module_count) return;

  const count = Math.min(g_target_module_records.length, NATIVE_MODULE_CAPACITY);
  g_native_module_count.writeU32(0);
  for (let i = 0; i < count; i++) {
    const rec = g_target_module_records[i]!;
    const out = g_native_module_records.add(i * NATIVE_MODULE_RECORD_SIZE);
    writeU64Pointer(out, rec.base);
    writeU64Number(out.add(8), rec.size);
    out.add(16).writePointer(rec.targetBits);
    out.add(24).writePointer(rec.functionBits);
  }
  g_native_module_count.writeU32(count);
}

function drainNativeTransitions(): void {
  ensureClassifier();
  if (!g_drain_transitions || !g_transition_drain_buffer) return;

  while (true) {
    const count = g_drain_transitions(g_transition_drain_buffer, NATIVE_TRANSITION_BATCH);
    if (count <= 0) return;
    for (let i = 0; i < count; i++) {
      const rec = g_transition_drain_buffer.add(i * NATIVE_TRANSITION_SIZE);
      const tid = rec.readU32();
      const src = rec.add(8).readPointer();
      const dst = rec.add(16).readPointer();
      recordJumpEvent(src, dst, tid, "stalker_jump");
    }
    if (count < NATIVE_TRANSITION_BATCH) return;
  }
}

function allocBitmap(bitCount: number, fill: boolean, offsets: string[] = []): NativePointer {
  ensureClassifier();
  const byteCount = Math.max(1, Math.ceil(Math.max(0, bitCount) / 8));
  const bytes = new Uint8Array(byteCount);
  if (fill) {
    bytes.fill(0xff);
  } else {
    for (const offText of offsets) {
      const offset = parseInt(String(offText), 16);
      if (!Number.isFinite(offset) || offset < 0 || offset >= bitCount) continue;
      const byteIndex = offset >> 3;
      bytes[byteIndex] = (bytes[byteIndex] || 0) | (1 << (offset & 7));
    }
  }
  const mem = Memory.alloc(byteCount);
  mem.writeByteArray(bytes.buffer);
  return mem;
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
  const srcClass = classifyAddress(loc);
  const dstClass = classifyAddress(target);
  if (!srcClass.tt && !dstClass.tt) return;

  const srcMod = findModuleSafe(loc);
  const dstMod = findModuleSafe(target);
  const isCall = kind === "call";
  const dstIsExternal = isCall
    && srcClass.tt
    && dstMod !== null
    && !dstClass.tt;

  const out: RawEvent = {
    k: isCall ? 0 : 1,
    src: ph(loc), dst: ph(target),
    tid, seq: nextSeq(),
    src_module: srcMod ? srcMod.name : "unknown",
    src_offset: moduleOffset(loc, srcMod),
    dst_module: dstMod ? dstMod.name : "unknown",
    dst_offset: moduleOffset(target, dstMod),
    dst_is_external: dstIsExternal,
    src_tt: srcClass.tt,
    dst_tt: dstClass.tt,
    source,
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

function recordJumpEvent(
  loc: NativePointer,
  target: NativePointer,
  tid: number,
  source: string,
): void {
  const srcClass = classifyAddress(loc);
  const dstClass = classifyAddress(target);
  if (!srcClass.tt && !dstClass.tt) return;
  if (dstClass.tt && !dstClass.functionStart) return;

  const srcMod = findModuleSafe(loc);
  const dstMod = findModuleSafe(target);
  const out: RawEvent = {
    k: 2,
    src: ph(loc), dst: ph(target),
    tid, seq: nextSeq(),
    src_module: srcMod ? srcMod.name : "unknown",
    src_offset: moduleOffset(loc, srcMod),
    dst_module: dstMod ? dstMod.name : "unknown",
    dst_offset: moduleOffset(target, dstMod),
    dst_is_external: srcClass.tt && dstMod !== null && !dstClass.tt,
    src_tt: srcClass.tt,
    dst_tt: dstClass.tt,
    is_jump: true,
    source,
  };
  out.src_symbol = symbolName(loc);
  out.dst_symbol = symbolName(target);
  g_events.push(out);
  if (out.dst_is_external && dstMod) {
    noteExternalBoundaryCall(tid, loc, target, dstMod);
  }
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
  g_mod_events.push({ seq: nextSeq(), action: "load",
                      name, base: ph(base), size });
}
function recordUnload(name: string, base: NativePointer, size: number) {
  g_mod_events.push({ seq: nextSeq(), action: "unload",
                      name, base: ph(base), size });
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
        events: { call: true, ret: true },

        transform(iterator: StalkerArm64Iterator | StalkerArmIterator | StalkerThumbIterator | StalkerX86Iterator): void {
          let instruction = iterator.next();
          if (instruction === null) return;

          iterator.putCallout(onBlockStart, allocBlockStartData(tid, instruction.address));
          do {
            const mnemonic = instruction.mnemonic;
            const isJump = isJumpMnemonic(mnemonic);
            if (isJump || isCallOrRetMnemonic(mnemonic)) {
              iterator.putCallout(
                onBranchExecute,
                allocBranchData(tid, instruction.address, isJump),
              );
            }
            iterator.keep();
            instruction = iterator.next();
          } while (instruction !== null);
        },

        onReceive(evbuf: ArrayBuffer): void {
          const parsed = Stalker.parse(evbuf, {
            annotate: true, stringify: false,
          }) as StalkerEventFull[];

          for (const ev of parsed) {
            const ks = ev[0];
            if (ks !== "call" && ks !== "ret") continue;

            const loc    = ev[1] as NativePointer;
            const target = ev[2] as NativePointer;
            recordTraceEvent(ks, loc, target, tid, "stalker");
          }
          drainNativeTransitions();
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
    send({ type: "status", text: "oep_hook_failed" });
    return;
  }

  try {
    Interceptor.attach(oep, {
      onEnter(_) {
        markOepReached("main_oep");
      },
    });
    send({ type: "status", text: "oep_hook address=" + ph(oep) });
  } catch (e) {
    send({ type: "status", text: "oep_hook_failed " + e });
  }
}

function beginTrace(initialTids: number[] = []): void {
  if (g_started) return;
  g_started = true;

  hookMainOep();
  for (const tid of initialTids) attachStalker(tid, "initial");
  send({ type: "status", text: "trace_threads=" + Array.from(g_stalked).join(",") });
  g_status_timer = setInterval(() => {
    sendTraceChunk("periodic");
    send({
      type: "status",
      text: "trace_stats events=" + g_events.length
        + " modules=" + g_mod_events.length
        + " sync=" + g_sync_events.length
        + " handles=" + g_handle_events.length,
    });
  }, 1000);
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

function sendTraceChunk(reason: "periodic" | "exit" | "user_stop"): void {
  drainNativeTransitions();

  const events = g_events.slice(g_sent_events);
  const modEvents = g_mod_events.slice(g_sent_mod_events);
  const syncEvents = g_sync_events.slice(g_sent_sync_events);
  const spawnEvents = g_spawn_events.slice(g_sent_spawn_events);
  const handleEvents = g_handle_events.slice(g_sent_handle_events);
  const exceptionEvents = g_exception_events.slice(g_sent_exception_events);

  if (
    events.length === 0 && modEvents.length === 0
    && syncEvents.length === 0 && spawnEvents.length === 0
    && handleEvents.length === 0 && exceptionEvents.length === 0
  ) {
    return;
  }

  send({
    type: "trace_chunk", session_id: SESSION_ID, reason,
    sent_at_ms: Date.now(),
    events,
    mod_events: modEvents, sync_events: syncEvents,
    spawn_events: spawnEvents,
    handle_events: handleEvents,
    exception_events: exceptionEvents,
  } as AgentPayload);

  g_sent_events = g_events.length;
  g_sent_mod_events = g_mod_events.length;
  g_sent_sync_events = g_sync_events.length;
  g_sent_spawn_events = g_spawn_events.length;
  g_sent_handle_events = g_handle_events.length;
  g_sent_exception_events = g_exception_events.length;
}

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
      + " events=" + g_events.length
      + " modules=" + g_mod_events.length,
  });

  sendTraceChunk(reason);
  send({
    type: "trace_complete", session_id: SESSION_ID, reason,
    sent_at_ms: Date.now(),
    events: [],
    mod_events: [], sync_events: [],
    spawn_events: [],
    handle_events: [],
    exception_events: [],
  } as AgentPayload);
}

// ══════════════════════════════════════════════════════════
// RPC
// ══════════════════════════════════════════════════════════

rpc.exports = {
  stopTrace(): void { flushAndSend("user_stop"); },

  startTrace(initialTids?: number[]): void {
    beginTrace(initialTids ?? []);
  },

  /**
   * 타겟 모듈 목록 주입. frida_bridge_server.py가 세션 시작 후 호출.
   * project_info에서 받은 파일명 목록 (소문자).
   */
  setTargets(targets: string[]): void {
    g_targets = new Set(targets.map(t => normalizedTargetName(t)));
    // 메인 EXE는 항상 포함
    const mainMod = Process.enumerateModules()[0];
    if (mainMod) g_targets.add(normalizedTargetName(mainMod.name));
    rebuildTargetModuleRecords();
    hookLoadedTargetExports();
    send({ type: "status", text: "targets=" + Array.from(g_targets).join(",") });
  },

  setTargetConfig(configs: TargetModuleConfig[]): void {
    g_targets = new Set();
    g_function_starts_by_module.clear();
    for (const cfg of configs) {
      if (!cfg.trace) continue;
      const name = normalizedTargetName(cfg.name);
      g_targets.add(name);
      g_function_starts_by_module.set(
        name, (cfg.function_starts || []).map(v => String(v)));
    }
    rebuildTargetModuleRecords();
    hookLoadedTargetExports();
    let starts = 0;
    for (const offsets of g_function_starts_by_module.values()) {
      starts += offsets.length;
    }
    send({
      type: "status",
      text: "target_config modules=" + Array.from(g_targets).join(",")
        + " function_starts=" + starts,
    });
  },
};

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

  // 메인 EXE를 초기 타겟으로
  const mainMod = Process.enumerateModules()[0];
  if (mainMod) g_targets.add(normalizedTargetName(mainMod.name));

  hookModules();
  hookThreadCreation();
  hookExceptions();
  hookExit();
})();
