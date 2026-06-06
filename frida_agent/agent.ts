/**
 * agent.ts  –  Frida Stalker 에이전트 (Windows x64 / WoW64 x86)
 *
 * 빌드: frida-compile agent.ts -o agent.js
 *
 * 설계:
 *   - CALL + RET 만 Stalker 추적 (JMP 제외)
 *   - 최적화/필터링보다 누락 방지를 우선한다.
 *   - Stalker call/ret 이벤트는 모듈 필터 없이 기록한다.
 *   - 타겟 모듈 export는 하나씩 Interceptor로도 기록한다.
 *   - 모든 인터셉트는 ntdll / user32 수준
 *   - 메인 EXE 종료만 flush 트리거
 */

"use strict";

// ══════════════════════════════════════════════════════════
// 타입 정의
// ══════════════════════════════════════════════════════════

interface RawEvent {
  k:   0 | 1;   // 0=call, 1=ret
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
const g_stalked:      Set<number>         = new Set();
const g_attach_failed:Set<number>         = new Set();

let g_seq     = 0;
let g_flushed = false;
let g_started = false;
let g_status_timer: ReturnType<typeof setInterval> | null = null;
let g_thread_api: ThreadApi | null = null;
let g_thread_observer: any = null;
let g_module_observer: any = null;
let g_sent_events = 0;
let g_sent_mod_events = 0;
let g_sent_sync_events = 0;
let g_sent_spawn_events = 0;
let g_sent_handle_events = 0;

const g_handle_gen_by_key: Map<string, number> = new Map();
let g_next_handle_gen = 1;
const g_symbol_name_by_va: Map<string, string> = new Map();
const g_hooked_target_exports: Set<string> = new Set();

type LastExternalCall = {
  caller_va: string;
  target_va: string;
  target_module: string;
  at_ms: number;
};

const g_last_external_call_by_tid: Map<number, LastExternalCall> = new Map();
const g_export_symbols_by_module: Map<string, Array<{ name: string; address: NativePointer }>> = new Map();

// 타겟 모듈 집합 (소문자). rpc.setTargets()로 갱신.
let g_targets: Set<string> = new Set();
const g_function_starts_by_module: Map<string, string[]> = new Map();

const SESSION_ID  = generateUUID();
const MAX_BT      = 24; // 콜스택 역추적 최대 깊이
const FAILURE_SCAN_DELAY_MS = 50;
const LAST_EXTERNAL_CALL_TTL_MS = 1500;

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
  const srcMod = findModuleSafe(loc);
  const dstMod = findModuleSafe(target);
  const isCall = kind === "call";
  const dstIsExternal = isCall
    && isTarget(srcMod)
    && dstMod !== null
    && !isTarget(dstMod);

  const out: RawEvent = {
    k: isCall ? 0 : 1,
    src: ph(loc), dst: ph(target),
    tid, seq: nextSeq(),
    src_module: srcMod ? srcMod.name : "unknown",
    src_offset: moduleOffset(loc, srcMod),
    dst_module: dstMod ? dstMod.name : "unknown",
    dst_offset: moduleOffset(target, dstMod),
    dst_is_external: dstIsExternal,
    source,
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

function hookTargetExports(mod: Module): void {
  if (!isTarget(mod)) return;

  let hooked = 0;
  let failed = 0;
  let exports: ModuleExportDetails[] = [];
  try {
    exports = mod.enumerateExports();
  } catch (_) {
    return;
  }

  for (const ex of exports) {
    if (ex.type !== "function") continue;
    const key = normalizedTargetName(mod.name) + "!" + ex.name + "@" + ph(ex.address);
    if (g_hooked_target_exports.has(key)) continue;
    g_hooked_target_exports.add(key);
    try {
      Interceptor.attach(ex.address, {
        onEnter(_) {
          const tid = Process.getCurrentThreadId();
          const ra = (this as any).returnAddress as NativePointer;
          const tailTarget = detectVtableTailJump(ex.address, (this as any).context);
          (this as any)._fd_tid = tid;
          (this as any)._fd_ra = ra;
          (this as any)._fd_tail_target = tailTarget;
          (this as any)._fd_tail_site = tailTarget ? tailJumpSite(ex.address) : null;
          recordTraceEvent("call", ra, ex.address, tid, "target_export");
          if (tailTarget) {
            recordTraceEvent("call", tailJumpSite(ex.address), tailTarget, tid, "target_export_tail_jump");
          }
        },
        onLeave(_) {
          const tid = (this as any)._fd_tid || Process.getCurrentThreadId();
          const ra = (this as any)._fd_ra as NativePointer | undefined;
          const tailTarget = (this as any)._fd_tail_target as NativePointer | null | undefined;
          const tailSite = (this as any)._fd_tail_site as NativePointer | null | undefined;
          if (tailTarget && tailSite) {
            recordTraceEvent("ret", tailTarget, tailSite, tid, "target_export_tail_jump");
          }
          if (ra) recordTraceEvent("ret", ex.address, ra, tid, "target_export");
        },
      });
      hooked++;
    } catch (_) {
      failed++;
    }
  }

  if (hooked > 0 || failed > 0) {
    send({
      type: "status",
      text: "target_export_hooks module=" + mod.name
        + " hooked=" + hooked + " failed=" + failed,
    });
  }
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
  for (const mod of Process.enumerateModules()) {
    hookTargetExports(mod);
  }
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
      if (g_targets.size > 0) hookTargetExports(mod);
      send({
        type: "status",
        text: "module_observer:add " + mod.name + " base=" + ph(mod.base),
      });
    },
    onRemoved(mod) {
      recordUnload(mod.name, mod.base, mod.size);
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
      Stalker.follow(tid, {
        events: { call: true, ret: true },

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
  setTimeout(() => scanThreads(reason), FAILURE_SCAN_DELAY_MS);
}

function beginTrace(initialTids: number[] = []): void {
  if (g_started) return;
  g_started = true;

  scanThreads("start_before_initial");
  for (const tid of initialTids) attachStalker(tid, "initial");
  scanThreads("start_after_initial");
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

// ══════════════════════════════════════════════════════════
// 데이터 전송
// ══════════════════════════════════════════════════════════

function sendTraceChunk(reason: "periodic" | "exit" | "user_stop"): void {
  const events = g_events.slice(g_sent_events);
  const modEvents = g_mod_events.slice(g_sent_mod_events);
  const syncEvents = g_sync_events.slice(g_sent_sync_events);
  const spawnEvents = g_spawn_events.slice(g_sent_spawn_events);
  const handleEvents = g_handle_events.slice(g_sent_handle_events);

  if (
    events.length === 0 && modEvents.length === 0
    && syncEvents.length === 0 && spawnEvents.length === 0
    && handleEvents.length === 0
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
  } as AgentPayload);

  g_sent_events = g_events.length;
  g_sent_mod_events = g_mod_events.length;
  g_sent_sync_events = g_sync_events.length;
  g_sent_spawn_events = g_spawn_events.length;
  g_sent_handle_events = g_handle_events.length;
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
  hookExit();
})();
