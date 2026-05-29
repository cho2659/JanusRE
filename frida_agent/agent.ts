/**
 * agent.ts  –  Frida Stalker 에이전트 (Windows x64 / WoW64 x86)
 *
 * 빌드: frida-compile agent.ts -o agent.js
 *
 * 설계:
 *   - CALL + RET + 타겟 모듈 indirect JMP 를 Stalker 추적
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
let g_target_ranges: Array<{ base: NativePointer; end: NativePointer; name: string }> = [];

// 타겟 모듈 집합 (소문자). rpc.setTargets()로 갱신.
let g_targets: Set<string> = new Set();

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

function refreshTargetRanges(): void {
  const ranges: Array<{ base: NativePointer; end: NativePointer; name: string }> = [];
  for (const mod of Process.enumerateModules()) {
    if (!isTarget(mod)) continue;
    ranges.push({
      base: mod.base,
      end: mod.base.add(mod.size),
      name: mod.name,
    });
  }
  g_target_ranges = ranges;
}

function isTargetAddress(addr: NativePointer): boolean {
  for (const range of g_target_ranges) {
    if (addr.compare(range.base) >= 0 && addr.compare(range.end) < 0) {
      return true;
    }
  }
  return false;
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
          (this as any)._fd_tid = tid;
          (this as any)._fd_ra = ra;
          recordTraceEvent("call", ra, ex.address, tid, "target_export");
        },
        onLeave(_) {
          const tid = (this as any)._fd_tid || Process.getCurrentThreadId();
          const ra = (this as any)._fd_ra as NativePointer | undefined;
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

function hookLoadedTargetExports(): void {
  for (const mod of Process.enumerateModules()) {
    hookTargetExports(mod);
  }
}

function parseSignedInteger(text: string): number | null {
  const s = text.trim().toLowerCase();
  if (!s) return null;
  const sign = s.startsWith("-") ? -1 : 1;
  const body = s.replace(/^[+-]/, "");
  const value = body.startsWith("0x")
    ? parseInt(body.slice(2), 16)
    : parseInt(body, 10);
  if (!Number.isFinite(value)) return null;
  return sign * value;
}

function contextRegister(ctx: CpuContext, name: string): NativePointer | null {
  const c = ctx as any;
  const key = name.toLowerCase();
  const aliases: { [key: string]: string } = {
    eax: "eax", ebx: "ebx", ecx: "ecx", edx: "edx",
    esi: "esi", edi: "edi", esp: "esp", ebp: "ebp", eip: "eip",
    rax: "rax", rbx: "rbx", rcx: "rcx", rdx: "rdx",
    rsi: "rsi", rdi: "rdi", rsp: "rsp", rbp: "rbp", rip: "rip",
    r8: "r8", r9: "r9", r10: "r10", r11: "r11",
    r12: "r12", r13: "r13", r14: "r14", r15: "r15",
  };
  const prop = aliases[key];
  if (!prop || c[prop] === undefined || c[prop] === null) return null;
  try {
    return ptr(c[prop].toString());
  } catch (_) {
    return null;
  }
}

function isIndirectJumpOperand(opStr: string): boolean {
  const op = opStr.trim().toLowerCase();
  if (!op) return false;
  if (op.includes("[")) return true;
  if (op.startsWith("0x")) return false;
  return /^[a-z][a-z0-9]*$/.test(op);
}

function resolveJumpTarget(
  opStr: string,
  ctx: CpuContext,
  instrAddress: NativePointer,
  instrSize: number,
): NativePointer | null {
  const op = opStr.trim().toLowerCase();
  if (!op) return null;

  if (!op.includes("[") && /^[a-z][a-z0-9]*$/.test(op)) {
    return contextRegister(ctx, op);
  }

  const m = op.match(/\[([^\]]+)\]/);
  if (!m) return null;
  const inner = m[1];
  if (!inner) return null;

  const expr = inner.replace(/\s+/g, "");
  const terms = expr.match(/[+-]?[^+-]+/g) || [];
  let base: NativePointer | null = null;
  let disp = 0;

  for (const term of terms) {
    const clean = term.replace(/^\+/, "");
    const reg = clean.replace(/^-/, "");
    if (/^[a-z][a-z0-9]*$/.test(reg)) {
      if (reg === "rip" || reg === "eip") {
        base = instrAddress.add(instrSize);
      } else {
        const rv = contextRegister(ctx, reg);
        if (rv) base = rv;
      }
      continue;
    }
    const n = parseSignedInteger(clean);
    if (n !== null) disp += n;
  }

  if (!base) {
    const absolute = parseSignedInteger(expr);
    if (absolute === null) return null;
    base = ptr(absolute);
  }

  try {
    return base.add(disp).readPointer();
  } catch (_) {
    return null;
  }
}

function symbolBase(name: string): string {
  return (name || "").replace(/\+0x[0-9a-f]+$/i, "").toLowerCase();
}

function isFunctionBoundaryJump(src: NativePointer, dst: NativePointer): boolean {
  const srcMod = findModuleSafe(src);
  const dstMod = findModuleSafe(dst);
  if (!srcMod || !dstMod) return false;
  if (!isTarget(srcMod)) return false;
  if (srcMod.name.toLowerCase() !== dstMod.name.toLowerCase()) return true;

  const srcSym = symbolBase(symbolName(src));
  const dstSym = symbolBase(symbolName(dst));
  if (srcSym && dstSym) return srcSym !== dstSym;
  if (srcSym || dstSym) return src.compare(dst) !== 0;
  return false;
}

function recordJumpFromCallout(
  tid: number,
  instrAddress: NativePointer,
  instrSize: number,
  opStr: string,
  ctx: CpuContext,
): void {
  const target = resolveJumpTarget(opStr, ctx, instrAddress, instrSize);
  if (!target || target.isNull()) return;
  if (!isFunctionBoundaryJump(instrAddress, target)) return;
  recordTraceEvent("call", instrAddress, target, tid, "stalker_jmp");
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
          if (!(this as any)._before.has(mod.name.toLowerCase())) {
            recordLoad(mod.name, mod.base, mod.size);
            refreshTargetRanges();
            hookTargetExports(mod);
          }
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
        transform(iterator: any): void {
          let instruction: any;
          while ((instruction = iterator.next()) !== null) {
            const mnemonic = String(instruction.mnemonic || "").toLowerCase();
            if (mnemonic === "jmp") {
              const address = instruction.address as NativePointer;
              const opStr = String(instruction.opStr || "");
              if (isTargetAddress(address) && isIndirectJumpOperand(opStr)) {
                const size = Number(instruction.size || 0);
                iterator.putCallout((ctx: CpuContext) => {
                  recordJumpFromCallout(tid, address, size, opStr, ctx);
                });
              }
            }
            iterator.keep();
          }
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

    const creator = pointerDetails(callerVa);
    const start = pointerDetails(startVa);
    g_spawn_events.push({
      seq: nextSeq(), api: apiName,
      parent_tid: parentTid, child_tid: tid,
      thread_handle: ph(handle), handle_gen: gen,
      creator_va: callerVa, start_va: startVa,
      creator_module: creator.module,
      creator_offset: creator.offset,
      creator_symbol: creator.symbol,
      start_module: start.module,
      start_offset: start.offset,
      start_symbol: start.symbol,
      status,
    });
    send({
      type: "status",
      text: "thread_create tid=" + tid
        + " parent_tid=" + parentTid
        + " start=" + startVa
        + " caller=" + callerVa
        + " caller_mod=" + creator.module + "!" + creator.offset
        + " start_mod=" + start.module + "!" + start.offset,
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
        (this as any)._cv  = findThreadCreator(
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
        (this as any)._cv = findThreadCreator(
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
    refreshTargetRanges();
    hookLoadedTargetExports();
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

  Stalker.queueDrainInterval = 0;
  Stalker.trustThreshold = -1;
  send({ type: "status", text: "agent:start session=" + SESSION_ID + " arch=" + Process.arch });

  // 메인 EXE를 초기 타겟으로
  const mainMod = Process.enumerateModules()[0];
  if (mainMod) g_targets.add(normalizedTargetName(mainMod.name));
  refreshTargetRanges();

  hookModules();
  hookThreadCreation();
  hookExit();
})();
