/**
 * agent.ts  –  Frida Stalker 에이전트 (Windows x64)
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
  kind:      "set_event" | "pulse_event" | "release_mutex"
           | "wait_single" | "wait_multiple"
           | "queue_apc"   | "alpc"
           | "post_message" | "send_message"
           | "get_message"  | "peek_message";
  handle:    string;
  caller_va: string; // 타겟 모듈 내 역추적 VA, 없으면 "unknown"
  msg_id?:   number;
  wparam?:   string;
  lparam?:   string;
  timeout?:  number; // ms, -1=INFINITE
}

interface ThreadSpawnEvent {
  seq:        number;
  parent_tid: number;
  child_tid:  number;
  creator_va: string; // 타겟 내 역추적 VA
  start_va:   string; // 새 스레드 시작 루틴 VA
}

interface AgentPayload {
  type:         "trace_complete" | "trace_chunk";
  session_id:   string;
  reason:       "exit" | "user_stop" | "periodic";
  events:       RawEvent[];
  snapshots:    StackSnapshot[];
  mod_events:   ModuleEvent[];
  sync_events:  SyncEvent[];
  spawn_events: ThreadSpawnEvent[];
}

// ══════════════════════════════════════════════════════════
// 전역 상태
// ══════════════════════════════════════════════════════════

const g_events:       RawEvent[]          = [];
const g_snapshots:    StackSnapshot[]     = [];
const g_mod_events:   ModuleEvent[]       = [];
const g_sync_events:  SyncEvent[]         = [];
const g_spawn_events: ThreadSpawnEvent[]  = [];
const g_stalked:      Set<number>         = new Set();
const g_attach_failed:Set<number>         = new Set();

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

// 타겟 모듈 집합 (소문자). rpc.setTargets()로 갱신.
let g_targets: Set<string> = new Set();

const SESSION_ID  = generateUUID();
const MAX_BT      = 24; // 콜스택 역추적 최대 깊이
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

/**
 * 콜스택 역추적: rsp를 읽어 리턴 어드레스 체인을 탐색.
 * 타겟 모듈 범위에 속하는 가장 가까운 프레임 VA 반환.
 * 찾지 못하면 "unknown".
 */
function findTargetCaller(ctx: CpuContext): string {
  const x64 = ctx as X64CpuContext;
  let rsp = x64.rsp;
  for (let i = 0; i < MAX_BT; i++) {
    let ra: NativePointer;
    try { ra = rsp.readPointer(); } catch (_) { break; }
    if (ra.isNull()) break;
    const mod = Process.findModuleByAddress(ra);
    if (mod && g_targets.has(mod.name.toLowerCase())) return ph(ra);
    rsp = rsp.add(8);
  }
  return "unknown";
}

function captureArgs(
  ctx: CpuContext, seq: number, tid: number
): StackSnapshot {
  const x = ctx as X64CpuContext;
  return {
    seq, kind: 0, tid,
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
            const srcMod = Process.findModuleByAddress(loc);
            const dstMod = Process.findModuleByAddress(target);

            // 타겟 필터: 출발지나 목적지 중 하나라도 타겟이어야 기록
            if (g_targets.size > 0) {
              if (!isTarget(srcMod) && !isTarget(dstMod)) continue;
            }

            const seq = nextSeq();
            g_events.push({
              k: ks === "call" ? 0 : 1,
              src: ph(loc), dst: ph(target),
              tid, seq,
              src_module: srcMod ? srcMod.name : "unknown",
              src_offset: moduleOffset(loc, srcMod),
              src_symbol: symbolName(loc),
              dst_module: dstMod ? dstMod.name : "unknown",
              dst_offset: moduleOffset(target, dstMod),
              dst_symbol: symbolName(target),
            });
          }
        },

        transform: ENABLE_ARG_SNAPSHOTS
          ? ((iterator: StalkerX86Iterator): void => {
              let instr: X86Instruction | null;
              while ((instr = iterator.next()) !== null) {
                const mn = instr.mnemonic.toLowerCase();
                if (mn === "call") {
                  const _tid = tid;
                  iterator.putCallout((ctx: CpuContext) => {
                    // seq는 onReceive에서 할당되므로 현재 인덱스로 근사
                    g_snapshots.push(captureArgs(ctx, g_events.length, _tid));
                  });
                }
                iterator.keep();
              }
            })
          : undefined,
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
        + " sync=" + g_sync_events.length,
    });
  }, 1000);
}

// ══════════════════════════════════════════════════════════
// 스레드 생성 (ntdll)
// ══════════════════════════════════════════════════════════

function hookThreadCreation(): void {
  const ntdll = Process.getModuleByName("ntdll.dll");

  const onNewThread = (handlePtr: NativePointer, startVa: string, callerVa: string, parentTid: number) => {
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
      seq: nextSeq(), parent_tid: parentTid, child_tid: tid,
      creator_va: callerVa, start_va: startVa,
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
        (this as any)._cv  = findTargetCaller(this.context);
        (this as any)._pt  = Process.getCurrentThreadId();
      },
      onLeave(rv) {
        if (rv.toInt32() === 0)
          onNewThread((this as any)._hp, (this as any)._sv,
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
        (this as any)._cv = findTargetCaller(this.context);
        (this as any)._pt = Process.getCurrentThreadId();
      },
      onLeave(rv) {
        if (rv.toInt32() === 0)
          onNewThread((this as any)._hp, (this as any)._sv,
                      (this as any)._cv, (this as any)._pt);
      },
    });
  }
}

// ══════════════════════════════════════════════════════════
// 동기화 이벤트 (ntdll)
// ══════════════════════════════════════════════════════════

function hookSync(): void {
  type SyncDef = {
    fn:     string;
    kind:   SyncEvent["kind"];
    handle: (a: InvocationArguments) => string;
    extra?: (a: InvocationArguments, ev: Partial<SyncEvent>) => void;
  };

  const ntdll = Process.getModuleByName("ntdll.dll");

  const defs: SyncDef[] = [
    { fn: "NtSetEvent",     kind: "set_event",      handle: a => ph(a[0]!) },
    { fn: "NtPulseEvent",   kind: "pulse_event",    handle: a => ph(a[0]!) },
    { fn: "NtReleaseMutant",kind: "release_mutex",  handle: a => ph(a[0]!) },
    {
      fn: "NtWaitForSingleObject", kind: "wait_single", handle: a => ph(a[0]!),
      extra: (a, ev) => {
        if (!a[2]!.isNull()) {
          try {
            const v = a[2]!.readS64();
            ev.timeout = v.compare(0) < 0 ? Math.round(Number(v.toNumber() * -1) / 10000) : -2;
          } catch (_) { ev.timeout = -1; }
        } else { ev.timeout = -1; }
      },
    },
    {
      fn: "NtWaitForMultipleObjects", kind: "wait_multiple", handle: a => ph(a[1]!),
      extra: (a, ev) => {
        if (!a[3]!.isNull()) {
          try {
            const v = a[3]!.readS64();
            ev.timeout = v.compare(0) < 0 ? Math.round(Number(v.toNumber() * -1) / 10000) : -2;
          } catch (_) { ev.timeout = -1; }
        } else { ev.timeout = -1; }
      },
    },
    { fn: "NtQueueApcThread",          kind: "queue_apc", handle: a => ph(a[0]!) },
    { fn: "NtAlpcSendWaitReceivePort", kind: "alpc",      handle: a => ph(a[0]!) },
  ];

  for (const d of defs) {
    const addr = ntdll.findExportByName(d.fn);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter(args) {
        const ev: Partial<SyncEvent> = {
          seq:       nextSeq(),
          tid:       Process.getCurrentThreadId(),
          kind:      d.kind,
          handle:    d.handle(args),
          caller_va: findTargetCaller(this.context),
        };
        if (d.extra) d.extra(args, ev);
        g_sync_events.push(ev as SyncEvent);
      },
    });
  }
}

// ══════════════════════════════════════════════════════════
// 유저 입력 / GUI 메시지 (user32)
// ══════════════════════════════════════════════════════════

function hookUserInput(): void {
  const u32 = Process.findModuleByName("user32.dll");
  if (!u32) return;

  // MSG 구조체에서 필드 읽기 (x64: hwnd[8] message[4] wParam[8] lParam[8])
  const readMsg = (lpMsg: NativePointer) => {
    try {
      return {
        hwnd:   ph(lpMsg.readPointer()),
        msg_id: lpMsg.add(8).readU32(),
        wparam: ph(lpMsg.add(12).readPointer()),
        lparam: ph(lpMsg.add(20).readPointer()),
      };
    } catch (_) { return null; }
  };

  const getMsgAddr = u32.findExportByName("GetMessageW");
  if (getMsgAddr) {
    Interceptor.attach(getMsgAddr, {
      onEnter(args) { (this as any)._lp = args[0]!; (this as any)._cv = findTargetCaller(this.context); },
      onLeave(rv) {
        if (rv.toInt32() <= 0) return;
        const m = readMsg((this as any)._lp);
        if (!m) return;
        g_sync_events.push({ seq: nextSeq(), tid: Process.getCurrentThreadId(),
          kind: "get_message", handle: m.hwnd, caller_va: (this as any)._cv,
          msg_id: m.msg_id, wparam: m.wparam, lparam: m.lparam });
      },
    });
  }

  const peekMsgAddr = u32.findExportByName("PeekMessageW");
  if (peekMsgAddr) {
    Interceptor.attach(peekMsgAddr, {
      onEnter(args) { (this as any)._lp = args[0]!; (this as any)._cv = findTargetCaller(this.context); },
      onLeave(rv) {
        if (rv.toInt32() === 0) return;
        const m = readMsg((this as any)._lp);
        if (!m) return;
        g_sync_events.push({ seq: nextSeq(), tid: Process.getCurrentThreadId(),
          kind: "peek_message", handle: m.hwnd, caller_va: (this as any)._cv,
          msg_id: m.msg_id, wparam: m.wparam, lparam: m.lparam });
      },
    });
  }

  // PostMessageW(hWnd, Msg, wParam, lParam)
  const postMsg = u32.findExportByName("PostMessageW");
  if (postMsg) {
    Interceptor.attach(postMsg, {
      onEnter(args) {
        g_sync_events.push({ seq: nextSeq(), tid: Process.getCurrentThreadId(),
          kind: "post_message", handle: ph(args[0]!), caller_va: findTargetCaller(this.context),
          msg_id: args[1]!.toInt32(), wparam: ph(args[2]!), lparam: ph(args[3]!) });
      },
    });
  }

  // SendMessageW(hWnd, Msg, wParam, lParam)
  const sendMsg = u32.findExportByName("SendMessageW");
  if (sendMsg) {
    Interceptor.attach(sendMsg, {
      onEnter(args) {
        g_sync_events.push({ seq: nextSeq(), tid: Process.getCurrentThreadId(),
          kind: "send_message", handle: ph(args[0]!), caller_va: findTargetCaller(this.context),
          msg_id: args[1]!.toInt32(), wparam: ph(args[2]!), lparam: ph(args[3]!) });
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

  if (
    events.length === 0 && snapshots.length === 0 && modEvents.length === 0
    && syncEvents.length === 0 && spawnEvents.length === 0
  ) {
    return;
  }

  send({
    type: "trace_chunk", session_id: SESSION_ID, reason,
    events, snapshots,
    mod_events: modEvents, sync_events: syncEvents,
    spawn_events: spawnEvents,
  } as AgentPayload);

  g_sent_events = g_events.length;
  g_sent_snapshots = g_snapshots.length;
  g_sent_mod_events = g_mod_events.length;
  g_sent_sync_events = g_sync_events.length;
  g_sent_spawn_events = g_spawn_events.length;
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
    events: [], snapshots: [],
    mod_events: [], sync_events: [],
    spawn_events: [],
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
  if (Process.arch !== "x64") {
    throw new Error("unsupported architecture: " + Process.arch + " (x64 required)");
  }

  Stalker.queueDrainInterval = 50;
  send({ type: "status", text: "agent:start session=" + SESSION_ID });

  // 메인 EXE를 초기 타겟으로
  const mainMod = Process.enumerateModules()[0];
  if (mainMod) g_targets.add(mainMod.name.toLowerCase());

  hookModules();
  hookThreadCreation();
  hookSync();
  hookUserInput();
  hookExit();
})();
