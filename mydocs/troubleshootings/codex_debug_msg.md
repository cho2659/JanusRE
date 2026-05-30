디버거 로그 기준으로 보면, 원인은 거의 확정적으로 **SaveAs가 “call”이 아니라 export thunk의 indirect tail-jmp라서 Stalker 기본 call 이벤트로는 잡히지 않고, 현재 수동 jmp 기록 경로도 그 실행 스레드/명령에 도달하지 못한 것**입니다.

**근거**
`debugger_log.txt`에서 `hwpsdk.dll` base는 `0x7FFC41F10000`이고, SaveAs 진입은 `0x7FFC41F11550`입니다. 즉 SaveAs RVA는 `0x1550`입니다.  
[debugger_log.txt](d:/openhwp/custom_tools/frida_delta/mydocs/troubleshootings/debugger_log.txt:2), [debugger_log.txt](d:/openhwp/custom_tools/frida_delta/mydocs/troubleshootings/debugger_log.txt:6)

SaveAs 내부의 실제 분기 명령은 다음입니다.

```asm
00007FFC41F11556 jmp qword ptr ds:[rax+28]
```

이는 `hwpsdk.dll!0x1556`입니다.  
[debugger_log.txt](d:/openhwp/custom_tools/frida_delta/mydocs/troubleshootings/debugger_log.txt:150)

그 시점의 `RAX`는 `0x7FFBD9209528`, 즉 `shdk.dll` 내부 주소입니다. 따라서 jmp operand가 읽는 슬롯 주소는:

```text
RAX + 0x28 = 0x7FFBD9209550
```

그리고 실제 도착지는 로그에 나온:

```text
0x7FFBD8497CB0 = shdk.dll RVA 0x937CB0
```

입니다.  
[debugger_log.txt](d:/openhwp/custom_tools/frida_delta/mydocs/troubleshootings/debugger_log.txt:152), [debugger_log.txt](d:/openhwp/custom_tools/frida_delta/mydocs/troubleshootings/debugger_log.txt:294)

따라서 올바른 그래프 이벤트는 개념적으로 이것이어야 합니다.

```text
hwpsdk.dll!SaveAs / hwpsdk.dll!0x1556
  -> shdk.dll!0x937CB0
```

**현재 코드와 어긋나는 지점**
현재 Stalker 기본 이벤트는 `call`/`ret`만 받습니다. `jmp`는 기본 call 이벤트로 들어오지 않으므로, 별도 transform에서 `jmp`를 찾아 callout을 넣어야 합니다. 이 로직은 [agent.ts](d:/openhwp/custom_tools/frida_delta/frida_agent/agent.ts:796) 근처에 있습니다.

```ts
if (mnemonic === "jmp") {
  ...
  if (isTargetAddress(address) && isIndirectJumpOperand(opStr)) {
    iterator.putCallout(...)
  }
}
```

그리고 callout에서 `resolveJumpTarget()`로 `[rax+28]`을 해석한 뒤 `recordTraceEvent(..., "stalker_jmp")`를 만듭니다.  
[agent.ts](d:/openhwp/custom_tools/frida_delta/frida_agent/agent.ts:471), [agent.ts](d:/openhwp/custom_tools/frida_delta/frida_agent/agent.ts:527), [agent.ts](d:/openhwp/custom_tools/frida_delta/frida_agent/agent.ts:600)

만약 이 이벤트가 생성되기만 했다면 전송 필터에서 버려질 가능성은 낮습니다. 필터는 `src_module` 또는 `dst_module` 중 하나가 타겟이면 통과시키는데, 이 경우 `src_module = hwpsdk.dll`이므로 통과해야 합니다.  
[agent.ts](d:/openhwp/custom_tools/frida_delta/frida_agent/agent.ts:1060)

그래프 빌더도 `stalker_jmp`를 tail-call처럼 처리하도록 되어 있으므로, 이벤트가 들어오기만 하면 SaveAs 하위 또는 대체 흐름으로 그릴 수 있습니다.  
[bridge_server.py](d:/openhwp/custom_tools/frida_delta/bridge_server.py:382)

그래서 결론은 이쪽입니다.

```text
Python 그래프 필터가 버린 문제가 아니라,
Frida agent 쪽에서 hwpsdk.dll!0x1556 jmp 이벤트가 생성되지 않았거나,
생성 전에 target 해석 실패로 return 된 문제다.
```

**가장 가능성 높은 직접 원인**
1. SaveAs를 실행한 UI 스레드가 Stalker에 실제로 follow되지 않았을 가능성이 큽니다.  
   과거 디버그 로그에는 SaveAs entry/range는 찍혔지만 `jmp_location`은 없었습니다. entry hook은 `Interceptor.attach()`로 동작하므로 Stalker 없이도 찍힙니다. 반면 `jmp_location`은 Stalker transform/callout이 실행되어야만 찍힙니다. 즉 “entry는 잡혔는데 jmp가 없다”는 것은 Stalker 경로가 해당 instruction까지 가지 못했다는 강한 증거입니다.

2. `resolveJumpTargetFromOperands()`가 Frida operand 구조를 기대와 다르게 받아 target을 `null`로 만들었을 가능성도 있습니다.  
   다만 예전 디버그 코드에서는 target 해석 전에 `jmp_location`을 남기도록 했는데도 로그에 없었으므로, 현재 증거만 보면 “해석 실패”보다 “callout 미실행” 가능성이 더 높습니다.

3. `shdk.dll`이 타겟 목록에 없어서 누락된 것은 1차 원인이 아닙니다.  
   `src`가 `hwpsdk.dll`이면 전송 필터는 통과합니다. 다만 그래프에서는 외부 노드로 표시되어야 합니다.

**수정 방안**
가장 안전한 수정은 두 겹으로 가는 것입니다.

1. `stalker_jmp` 경로는 유지하되, callout 진단을 가볍게 보강합니다.  
   무거운 인자/스택/디스어셈블 로그는 다시 넣으면 프리징을 만들 수 있으므로 금지하고, 카운터 또는 최소 이벤트만 둡니다.

```text
jmp instruction VA
operand 문자열
slot address = RAX + 0x28
resolved target = [slot]
src/dst module + RVA
실패 사유: no_callout / no_target / read_failed / non_exec 등
```

2. SaveAs 같은 export thunk는 Stalker에만 의존하지 않고 `Interceptor.onEnter`에서 직접 vtable slot을 해석합니다.  
   이 케이스는 코드 패턴이 명확합니다.

```asm
mov rcx, [rcx]
mov rax, [rcx]
jmp qword ptr [rax + 0x28]
```

따라서 SaveAs entry 시점에:

```text
real_this = RCX.readPointer()
vtable    = real_this.readPointer()
target    = vtable.add(0x28).readPointer()
```

로 `shdk.dll!0x937CB0`를 직접 얻을 수 있습니다. 이 방식은 UI 스레드가 Stalker에 붙었는지와 무관하게 동작합니다.

3. 그래프 이벤트 source를 `export_tailjmp` 또는 기존 `stalker_jmp`와 같은 tail-call 계열로 처리합니다.  
   그래프 빌더에서는 현재 `stalker_jmp`일 때 stack top을 교체합니다. 새 source를 만들 경우 같은 정책에 포함해야 합니다.

```text
caller -> hwpsdk.dll!SaveAs
hwpsdk.dll!SaveAs -> shdk.dll!0x937CB0
```

4. 주소 표기는 VA/RVA/file offset을 분리해야 합니다.  
   이번 로그 기준으로 확정 가능한 값은:

```text
hwpsdk.dll SaveAs entry RVA: 0x1550
hwpsdk.dll jmp RVA:          0x1556
shdk.dll target RVA:         0x937CB0
```

로그의 `#9370B0` 표기는 RVA가 아니라 파일 오프셋이거나 별도 기준값일 수 있으므로, PE 섹션 변환으로 검증한 뒤에만 file offset으로 써야 합니다.

정리하면, 지금 문제는 “SaveAs 목적지가 불명확한 것”이 아니라 이미 디버거로 목적지는 명확합니다. 문제는 현재 agent가 그 `jmp [rax+28]`를 **Stalker가 놓치면 대체 경로 없이 잃어버리는 구조**라는 점입니다. 수정은 SaveAs/export thunk에 대해 Interceptor 기반 vtable-slot 해석을 추가하고, Stalker jmp는 일반 보조 경로로 유지하는 방향이 가장 신뢰성이 높습니다.