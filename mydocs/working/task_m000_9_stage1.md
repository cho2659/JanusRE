# Task M000 #9 Stage 1 보고서

GitHub Issue: [#9](https://github.com/cho2659/JanusRE/issues/9)
구현계획서: [`task_m000_9_impl.md`](../plans/task_m000_9_impl.md)
Stage: 1 - 공유 메모리 ABI와 bootstrap 문서화

## 단계 목적

Python과 Frida agent가 공유할 memory layout, state machine, fixed-size event record, bootstrap 상수를 먼저 고정했다. 이후 Python owner/reader와 agent writer 구현이 같은 ABI를 기준으로 진행되도록 하는 단계다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `mydocs/tech/task_m000_9_shared_memory_abi.md` | shared memory header, state/command, module record, event record, ring buffer, agent allocation policy 정의 |

## 본문 변경 정도 / 본문 무손실 여부

신규 문서 작성이다. 기존 문서 본문은 변경하지 않았다.

## 검증 결과

실행 명령:

```bash
rg -n "FRIDA_DELTA_SHM|record_size|main_tid|STOP_REQUESTED" mydocs/tech/task_m000_9_shared_memory_abi.md
git diff --check
```

결과:

- OK: bootstrap 상수, `record_size`, `main_tid`, `STOP_REQUESTED` 정의가 문서에 존재함을 확인했다.
- OK: `git diff --check` 통과.

## 잔여 위험

- Windows named file mapping을 agent에서 여는 구체 API binding은 Stage 2/3 구현 중 코드로 확정해야 한다.
- atomic helper는 CModule 또는 native Interlocked API 중 실제 Frida build 제약에 맞는 방식으로 확정해야 한다.

## 다음 단계 영향

- Stage 2는 이 ABI를 기준으로 Python shared memory owner와 binary reader를 구현한다.
- event record는 우선 64-byte 고정 record로 구현한다.

## 승인 요청

- Stage 1 산출물과 검증 결과를 승인하면 Stage 2로 진행한다.
