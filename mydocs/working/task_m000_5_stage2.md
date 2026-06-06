# Task M000 #5 Stage 2 완료 보고서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)
Stage: 2

## 단계 목적

사용자 추가 지시에 따라 그래프 노드 더블클릭 Ghidra 이동, Qt 창/패널 크기 제한, 그래프 최대 축소 비율, 창 종료 시 타겟 프로세스 잔존 문제를 한 번에 보정한다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | 노드 더블클릭 시 기존 Ghidra sync 경로 재사용, 메인/오른쪽 패널 splitter 유연화, 그래프 축소 하한 계산 추가, Frida spawn PID/경로 저장 및 창 종료 시 이미지 경로 일치 프로세스 강제 종료 추가 |

## 검증 결과

실행 명령:

```bash
python -m py_compile bridge_server.py
git diff --check
```

결과:

- OK: Python 문법 검증 통과
- OK: diff 공백 검사 통과

## 잔여 확인

- 실제 Ghidra 연결 상태에서 노드 더블클릭 GoTo 동작 수동 확인 필요
- 실제 타겟 exe 실행 중 창 종료 시 프로세스 종료 동작 수동 확인 필요
