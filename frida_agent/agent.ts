/**
 * agent.ts  –  Frida Stalker 에이전트 (Windows x64 / WoW64 x86)
 *
 * 빌드: frida-compile agent.ts -o agent.js
 *
 * 설계:
 *   - CALL + RET 만 Stalker 추적 (JMP 제외)
 *   - 타겟 모듈(rpc.setTargets로 주입) 외부-외부 call은 Stalker 미추적
 *     단, 타겟→외부 또는 외부→타겟 경계 이벤트는 기록
 *   - 실행 중 최소 작업: raw VA 저장, 오프셋 보정은 Python 후처리
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
}

interface StackSnapshot {
  seq:   number;
  kind:  0; // 0=enter(call 직전)
  tid:   number;
  arch: string;
  rcx: string; rdx: string; r8: string; r9: string;
  rsp: string;
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
  start_va:   string; // 새 스레드 시작 루틴 VA
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
  snapshots:    StackSnapshot[];
  mod_events:   ModuleEvent[];
  sync_events:  SyncEvent[];
  spawn_events: ThreadSpawnEvent[];
  handle_events: HandleEvent[];
}

// ══════════════════════════════════════════════════════════
// 전역 상태
// ══════════════════════════════════════════════════════════

const g_events:       RawEvent[]          = [];
const g_snapshots:    StackSnapshot[]     = [];
const g_mod_events:   ModuleEvent[]       = [];
const g_sync_events:  SyncEvent[]         = [];
const g_spawn_events: ThreadSpawnEvent[]  = [];
const g_handle_events: HandleEvent[]      = [];
const g_stalked:      Set<number>         = new Set();
const g_attach_failed:Set<number>         = new Set();

type LastExternalCall = {
  caller_va: string;
  target_va: string;
  target_module: string;
  at_ms: number;
};

const g_last_external_call_by_tid: Map<number, LastExternalCall> = new Map();

let g_seq     = 0;
let g_flushed = false;
let g_started = false;
let g_status_timer: ReturnType<typeof setInterval> | null = null;
let g_thread_api: ThreadApi | null = null;
let g_sent_events = 0;
let g_sent_snapshots = 0;
let g_sent_mod_events = 0;
let g_sent_sync_events = 0;
let g_sent_spawn_events = 0;
let g_sent_handle_events = 0;

const g_handle_gen_by_key: Map<string, number> = new Map();
let g_next_handle_gen = 1;

// 타겟 모듈 집합 (소문자). rpc.setTargets()로 갱신.
let g_targets: Set<string> = new Set();

const SESSION_ID  = generateUUID();
const MAX_BT      = 24; // 콜스택 역추적 최대 깊이
const LAST_EXTERNAL_CALL_TTL_MS = 1000;
const ENABLE_ARG_SNAPSHOTS = false;
const FAILURE_SCAN_DELAY_MS = 50;

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

function isTarget(mod: { name: string } | null): boolean {
  if (!mod) return false;
  return g_targets.has(mod.name.toLowerCase());
}

function moduleOffset(addr: NativePointer, mod: Module | null): string {
  if (!mod) return "0x0";
  return "0x" + addr.sub(mod.base).toString(16).toUpperCase();
}

function symbolName(addr: NativePointer): string {
  try {
    const sym = DebugSymbol.fromAddress(addr);
    return sym && sym.name ? sym.name : "";
  } catch (_) {
    return "";
  }
}

function asNativePointer(value: unknown): NativePointer | null {
  if (value === null || value === undefined) return null;
  try {
    if (typeof value === "number") return ptr("0x" + value.toString(16));
    if (typeof value === "string") return ptr(value);
    const s = (value as { toString?: () => string }).toString;
    if (typeof s === "function") return ptr(s.call(value));
  } catch (_) {
    return null;
  }
  return null;
}

function numberFromAny(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const s = value.trim();
    const n = s.startsWith("0x") || s.startsWith("-0x")
      ? parseInt(s, 16)
      : parseInt(s, 10);
    return Number.isFinite(n) ? n : null;
  }
  try {
    const s = (value as { toString?: () => string }).toString;
    if (typeof s === "function") return numberFromAny(s.call(value));
  } catch (_) {}
  return null;
}

function findModuleSafe(addr: NativePointer | null): Module | null {
  if (!addr) return null;
  try {
    return Process.findModuleByAddress(addr);
  } catch (_) {
    return null;
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

function noteExternalCall(caller: NativePointer, target: NativePointer): void {
  const targetMod = findModuleSafe(target);
  g_last_external_call_by_tid.set(Process.getCurrentThreadId(), {
    caller_va: ph(caller),
    target_va: ph(target),
    target_module: targetMod ? targetMod.name.toLowerCase() : "unknown",
    at_ms: Date.now(),
  });
}

function consumeRecentExternalCaller(
  ctx: CpuContext, immediateReturn?: NativePointer
): string {
  const tid = Process.getCurrentThreadId();
  const last = g_last_external_call_by_tid.get(tid);
  if (last && Date.now() - last.at_ms <= LAST_EXTERNAL_CALL_TTL_MS) {
    return last.caller_va;
  }
  return findTargetCaller(ctx, immediateReturn);
}

function directCallTarget(instr: X86Instruction): NativePointer | null {
  const i = instr as any;
  const operands = i.operands || [];
  if (operands.length > 0) {
    const op = operands[0];
    const value = op.value;
    if ((op.type === "imm" || op.type === "immediate") && value !== undefined) {
      return asNativePointer(value);
    }
  }

  const opStr = String(i.opStr || "");
  if (opStr.indexOf("[") >= 0) return null;
  const m = opStr.match(/0x[0-9a-fA-F]+/);
  if (!m) return null;
  try { return ptr(m[0]); } catch (_) { return null; }
}

function readPointerSafe(addr: NativePointer | null): NativePointer | null {
  if (!addr) return null;
  try {
    const p = addr.readPointer();
    return p.isNull() ? null : p;
  } catch (_) {
    return null;
  }
}

function memoryCallTarget(instr: X86Instruction): NativePointer | null {
  const i = instr as any;
  const src = asNativePointer(i.address);
  if (!src) return null;

  const operands = i.operands || [];
  if (operands.length > 0) {
    const op = operands[0];
    if (op && (op.type === "mem" || op.type === "memory")) {
      const value = op.value || op.mem || {};
      const base = String(value.base || "").toLowerCase();
      const disp = numberFromAny(value.disp ?? value.displacement);
      if (Process.arch === "x64" && base === "rip" && disp !== null) {
        const next = asNativePointer(i.next) || src.add(i.size || 0);
        return readPointerSafe(next.add(disp));
      }
      if ((!base || base === "0" || base === "invalid") && disp !== null) {
        return readPointerSafe(ptr("0x" + disp.toString(16)));
      }
    }
  }

  const opStr = String(i.opStr || "");
  const rip = opStr.match(/\[\s*rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\s*\]/i);
  if (rip) {
    const raw = numberFromAny(rip[2] || "");
    if (raw !== null) {
      const disp = rip[1] === "-" ? -raw : raw;
      const next = asNativePointer(i.next) || src.add(i.size || 0);
      return readPointerSafe(next.add(disp));
    }
  }
  const absolute = opStr.match(/\[\s*(0x[0-9a-fA-F]+)\s*\]/i);
  if (absolute && absolute[1]) return readPointerSafe(ptr(absolute[1]));
  return null;
}

function callTarget(instr: X86Instruction): NativePointer | null {
  return directCallTarget(instr) || memoryCallTarget(instr);
}

function shouldTrackExternalCallsite(instr: X86Instruction): NativePointer | null {
  const src = asNativePointer((instr as any).address);
  const srcMod = findModuleSafe(src);
  if (!isTarget(srcMod)) return null;
  const target = callTarget(instr);
  if (!target) return null;
  const dstMod = findModuleSafe(target);
  if (!dstMod || isTarget(dstMod)) return null;
  return target;
}

function captureArgs(
  ctx: CpuContext, seq: number, tid: number
): StackSnapshot {
  if (Process.arch === "ia32") {
    const x = ctx as Ia32CpuContext;
    const arg0 = x.esp;
    const arg1 = x.esp.add(4);
    const arg2 = x.esp.add(8);
    const arg3 = x.esp.add(12);
    const readArg = (p: NativePointer): string => {
      try { return p.readPointer().toString(); } catch (_) { return ""; }
    };
    return {
      seq, kind: 0, tid, arch: "ia32",
      rcx: readArg(arg0), rdx: readArg(arg1),
      r8:  readArg(arg2), r9:  readArg(arg3),
      rsp: x.esp.toString(),
    };
  }
  const x = ctx as X64CpuContext;
  return {
    seq, kind: 0, tid, arch: "x64",
    rcx: x.rcx.toString(), rdx: x.rdx.toString(),
    r8:  x.r8.toString(),  r9:  x.r9.toString(),
    rsp: x.rsp.toString(),
  };
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
  for (const mod of Process.enumerateModules()) recordLoad(mod.name, mod.base, mod.size);

  const ntdll = Process.getModuleByName("ntdll.dll");

  const ldrLoad = ntdll.findExportByName("LdrLoadDll");
  if (ldrLoad) {
    Interceptor.attach(ldrLoad, {
      onEnter(_) {
        (this as any)._before = new Set(
          Process.enumerateModules().map(m => m.name.toLowerCase()));
      },
      onLeave(rv) {
        if (rv.toInt32() !== 0) return;
        for (const mod of Process.enumerateModules()) {
          if (!(this as any)._before.has(mod.name.toLowerCase()))
            recordLoad(mod.name, mod.base, mod.size);
        }
      },
    });
  }

  const ldrUnload = ntdll.findExportByName("LdrUnloadDll");
  if (ldrUnload) {
    Interceptor.attach(ldrUnload, {
      onEnter(args) {
        const mod = Process.findModuleByAddress(args[0]!);
        if (mod) recordUnload(mod.name, mod.base, mod.size);
      },
    });
  }
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
            const srcMod = findModuleSafe(loc);
            const dstMod = findModuleSafe(target);

            // 타겟 필터: 출발지나 목적지 중 하나라도 타겟이어야 기록
            if (g_targets.size > 0) {
              if (!isTarget(srcMod) && !isTarget(dstMod)) continue;
            }

            const seq = nextSeq();
            const out: RawEvent = {
              k: ks === "call" ? 0 : 1,
              src: ph(loc), dst: ph(target),
              tid, seq,
              src_module: srcMod ? srcMod.name : "unknown",
              src_offset: moduleOffset(loc, srcMod),
              src_symbol: symbolName(loc),
              dst_module: dstMod ? dstMod.name : "unknown",
              dst_offset: moduleOffset(target, dstMod),
              dst_symbol: symbolName(target),
            };
            g_events.push(out);
          }
        },

        transform(iterator: StalkerX86Iterator): void {
          let instr: X86Instruction | null;
          while ((instr = iterator.next()) !== null) {
            const mn = instr.mnemonic.toLowerCase();
            if (mn === "call") {
              const caller = (instr as any).address as NativePointer;
              const externalTarget = shouldTrackExternalCallsite(instr);
              if (externalTarget) {
                iterator.putCallout(() => {
                  noteExternalCall(caller, externalTarget);
                });
              }
              if (ENABLE_ARG_SNAPSHOTS) {
                const _tid = tid;
                iterator.putCallout((ctx: CpuContext) => {
                  // seq는 onReceive에서 할당되므로 현재 인덱스로 근사
                  g_snapshots.push(captureArgs(ctx, g_events.length, _tid));
                });
              }
            }
            iterator.keep();
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
        + " snapshots=" + g_snapshots.length
        + " modules=" + g_mod_events.length
        + " sync=" + g_sync_events.length
        + " handles=" + g_handle_events.length,
    });
  }, 1000);
}

// ══════════════════════════════════════════════════════════
// 스레드 생성 (ntdll)
// ══════════════════════════════════════════════════════════

function hookThreadCreation(): void {
  const ntdll = Process.getModuleByName("ntdll.dll");

  const onNewThread = (
    apiName: string, status: string, handlePtr: NativePointer,
    startVa: string, callerVa: string, parentTid: number,
  ) => {
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

    g_spawn_events.push({
      seq: nextSeq(), api: apiName,
      parent_tid: parentTid, child_tid: tid,
      thread_handle: ph(handle), handle_gen: gen,
      creator_va: callerVa, start_va: startVa,
      status,
    });
    send({
      type: "status",
      text: "thread_create tid=" + tid
        + " parent_tid=" + parentTid
        + " start=" + startVa
        + " caller=" + callerVa,
    });
    if (!attachStalker(tid, "thread_create")) {
      scheduleFailureScan("thread_create_attach_failed");
    }
  };

  const ntCreateThreadEx = ntdll.findExportByName("NtCreateThreadEx");
  if (ntCreateThreadEx) {
    Interceptor.attach(ntCreateThreadEx, {
      onEnter(args) {
        (this as any)._hp  = args[0]!;
        (this as any)._sv  = ph(args[4]!);
        (this as any)._cv  = consumeRecentExternalCaller(
          this.context, (this as any).returnAddress as NativePointer);
        (this as any)._pt  = Process.getCurrentThreadId();
      },
      onLeave(rv) {
        if (rv.toInt32() === 0)
          onNewThread("NtCreateThreadEx", ntStatus(rv), (this as any)._hp, (this as any)._sv,
                      (this as any)._cv, (this as any)._pt);
      },
    });
  }

  const ntCreateThread = ntdll.findExportByName("NtCreateThread");
  if (ntCreateThread) {
    Interceptor.attach(ntCreateThread, {
      onEnter(args) {
        (this as any)._hp = args[0]!;
        (this as any)._sv = "unknown";
        (this as any)._cv = consumeRecentExternalCaller(
          this.context, (this as any).returnAddress as NativePointer);
        (this as any)._pt = Process.getCurrentThreadId();
      },
      onLeave(rv) {
        if (rv.toInt32() === 0)
          onNewThread("NtCreateThread", ntStatus(rv), (this as any)._hp, (this as any)._sv,
                      (this as any)._cv, (this as any)._pt);
      },
    });
  }
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
        onEnter(_) { flushAndSend("exit"); },
      });
    }
  }

  const k32 = Process.findModuleByName("kernel32.dll");
  if (!k32) return;
  for (const fn of ["ExitProcess", "TerminateProcess"]) {
    const addr = k32.findExportByName(fn);
    if (addr) {
      Interceptor.attach(addr, {
        onEnter(_) { flushAndSend("exit"); },
      });
    }
  }
}

// ══════════════════════════════════════════════════════════
// 데이터 전송
// ══════════════════════════════════════════════════════════

function sendTraceChunk(reason: "periodic" | "exit" | "user_stop"): void {
  const events = g_events.slice(g_sent_events);
  const snapshots = g_snapshots.slice(g_sent_snapshots);
  const modEvents = g_mod_events.slice(g_sent_mod_events);
  const syncEvents = g_sync_events.slice(g_sent_sync_events);
  const spawnEvents = g_spawn_events.slice(g_sent_spawn_events);
  const handleEvents = g_handle_events.slice(g_sent_handle_events);

  if (
    events.length === 0 && snapshots.length === 0 && modEvents.length === 0
    && syncEvents.length === 0 && spawnEvents.length === 0
    && handleEvents.length === 0
  ) {
    return;
  }

  send({
    type: "trace_chunk", session_id: SESSION_ID, reason,
    sent_at_ms: Date.now(),
    events, snapshots,
    mod_events: modEvents, sync_events: syncEvents,
    spawn_events: spawnEvents,
    handle_events: handleEvents,
  } as AgentPayload);

  g_sent_events = g_events.length;
  g_sent_snapshots = g_snapshots.length;
  g_sent_mod_events = g_mod_events.length;
  g_sent_sync_events = g_sync_events.length;
  g_sent_spawn_events = g_spawn_events.length;
  g_sent_handle_events = g_handle_events.length;
}

function flushAndSend(reason: "exit" | "user_stop"): void {
  if (g_flushed) return;
  g_flushed = true;
  if (g_status_timer !== null) {
    clearInterval(g_status_timer);
    g_status_timer = null;
  }

  send({
    type: "status",
    text: "flush_send reason=" + reason
      + " events=" + g_events.length
      + " snapshots=" + g_snapshots.length
      + " modules=" + g_mod_events.length,
  });

  sendTraceChunk(reason);
  send({
    type: "trace_complete", session_id: SESSION_ID, reason,
    sent_at_ms: Date.now(),
    events: [], snapshots: [],
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
    g_targets = new Set(targets.map(t => t.toLowerCase()));
    // 메인 EXE는 항상 포함
    const mainMod = Process.enumerateModules()[0];
    if (mainMod) g_targets.add(mainMod.name.toLowerCase());
    send({ type: "status", text: "targets=" + Array.from(g_targets).join(",") });
  },
};

// ══════════════════════════════════════════════════════════
// 진입점
// ══════════════════════════════════════════════════════════

(function main() {
  if (Process.arch !== "x64" && Process.arch !== "ia32") {
    throw new Error("unsupported architecture: " + Process.arch + " (x64/ia32 required)");
  }

  Stalker.queueDrainInterval = 50;
  send({ type: "status", text: "agent:start session=" + SESSION_ID + " arch=" + Process.arch });

  // 메인 EXE를 초기 타겟으로
  const mainMod = Process.enumerateModules()[0];
  if (mainMod) g_targets.add(mainMod.name.toLowerCase());

  hookModules();
  hookThreadCreation();
  hookExit();
})();
