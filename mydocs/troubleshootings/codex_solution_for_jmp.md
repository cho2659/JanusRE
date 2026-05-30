맞습니다. 그 이벤트를 보면 **현재 `stalker_jmp` 판정이 잘못 구현되어 있다는 신호가 분명히 있습니다.**

```json
"src_symbol": "HncGetPluginProxy",
"dst_symbol": "HncGetPluginProxy",
"source": "stalker_jmp"
```

이건 “함수 호출”로 기록하면 안 되는 가능성이 큽니다. 같은 모듈, 같은 symbol 내부의 indirect jmp입니다.

현재 코드의 문제는 이 조건입니다.

```ts
if (!isFunctionBoundaryJump(instrAddress, target) && !isExecutableAddress(target)) return;
recordTraceEvent("call", instrAddress, target, tid, "stalker_jmp");
```

즉 `isFunctionBoundaryJump()`가 false여도, 목적지가 executable이면 기록합니다. 이 fallback이 너무 넓습니다. 그래서 jump table, 내부 분기, 같은 함수 안의 indirect jmp까지 `call`처럼 기록됩니다. `HncGetPluginProxy -> HncGetPluginProxy`가 바로 그 증거입니다.

정책은 이렇게 바뀌어야 합니다.

```text
기록 가능:
- src target, dst 다른 모듈
- src/dst 같은 모듈이지만 symbol base가 명확히 다름
- export thunk/vtable thunk로 판명됨

기록 금지:
- src_symbol == dst_symbol 인 same-function indirect jmp
- symbol 불명확한데 executable이라는 이유만으로 통과하는 jmp
```

그리고 “SaveAs가 왜 안 잡혔냐”에 대한 답은, 이제 더 명확히 말할 수 있습니다.

**가장 가능성 높은 직접 원인은 `hookTargetExports()`의 Interceptor export hook과 Stalker jmp transform이 충돌했기 때문입니다.**

현재 agent는 타겟 모듈 export마다 `Interceptor.attach(ex.address, ...)`를 겁니다. SaveAs도 export이므로 여기에 걸립니다. 그런데 SaveAs는 아주 짧은 thunk입니다.

```asm
0x1550 mov rcx, [rcx]
0x1553 mov rax, [rcx]
0x1556 jmp qword ptr [rax + 0x28]
```

이런 짧은 함수에 `Interceptor.attach()`를 걸면 Frida가 원본 entry를 패치하고, 일부 원본 instruction을 trampoline/relocated code에서 실행할 수 있습니다. 그러면 Stalker transform이 기대한 원본 주소:

```text
hwpsdk.dll!0x1556
```

에서 `jmp qword ptr [rax+28]`를 보지 못합니다. 보더라도 relocated trampoline 주소에서 보게 되고, 현재 코드는 다음 조건 때문에 버립니다.

```ts
if (isTargetAddress(address) && isIndirectJumpOperand(opStr)) {
```

trampoline 주소는 `hwpsdk.dll` 안이 아니므로 `isTargetAddress(address)`가 false가 됩니다.

즉 흐름은 이렇습니다.

```text
SaveAs entry hook은 Interceptor 때문에 잡힘
하지만 Interceptor가 짧은 thunk를 패치/relocate함
Stalker는 원본 hwpsdk.dll!0x1556 jmp를 target 주소로 보지 못함
따라서 stalker_jmp 이벤트가 생성되지 않음
그래서 JSON trace에 shdk.dll!0x937CB0이 없음
```

이게 사용자가 묻는 “그 이유”입니다. 단순히 “기본 Stalker가 jmp를 안 따라간다”가 아니라, 이 케이스에서는 **export hook이 SaveAs thunk의 원본 jmp 관찰 지점을 없애거나 target 밖으로 옮겨서, 우리가 추가한 jmp transform도 못 잡은 것**으로 보는 게 맞습니다.

수정 방안은 두 가지입니다.

1. `stalker_jmp` 판정 수정  
   `isExecutableAddress()` fallback만으로 call 기록하지 않게 해야 합니다. 같은 symbol 내부 jmp는 제외해야 합니다.

2. export thunk는 Stalker에 맡기지 않고 `Interceptor.onEnter`에서 직접 해석  
   SaveAs entry에서 `RCX -> [RCX] -> [[RCX]] -> [vtable + 0x28]`를 계산해 `hwpsdk.dll!0x1556 -> shdk.dll!0x937CB0` synthetic tail-call 이벤트를 생성해야 합니다.

이렇게 해야 `HncGetPluginProxy -> HncGetPluginProxy` 같은 가짜 call은 줄이고, SaveAs처럼 Interceptor 때문에 Stalker가 놓치는 짧은 thunk는 정확히 잡을 수 있습니다.