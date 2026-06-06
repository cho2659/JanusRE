# Task M000 #4 Stage 2 완료 보고서

GitHub Issue: [#4](https://github.com/cho2659/JanusRE/issues/4)
구현계획서: [`task_m000_4_impl.md`](../plans/task_m000_4_impl.md)
Stage: 2

## 단계 목적

스레드 선택 UI를 중앙 그래프 위 탭에서 오른쪽 함수 검색 패널 아래 목록으로 이동했다. 추가 승인된 범위에 따라 세션 재로드 시 첫 스레드로 튀는 문제와 함수 검색 결과 이동 시 확대 포커스도 함께 처리했다.

## 산출물

| 파일 | 변경 요약 |
|---|---|
| `bridge_server.py` | 중앙 그래프를 탭 없는 `QStackedWidget`으로 변경, 오른쪽 패널에 `ThreadListPanel` 배치, TID 더블클릭 전환 연결, 세션 재로드 시 기존 TID 유지, 함수 검색 이동 시 확대 포커스 추가 |
| `mydocs/plans/task_m000_4_impl.md` | Stage 2 확장 범위 반영 |

## 본문 변경 정도 / 본문 무손실 여부

코드 작업이므로 문서 본문 보존 항목은 해당 없다. Frida agent, Ghidra 통신, 콜 그래프 레이아웃 알고리즘은 변경하지 않았다.

## 검증 결과

실행 명령:

```bash
python -m py_compile bridge_server.py
git diff --check
```

결과:

- OK: `python -m py_compile bridge_server.py` 통과
- OK: `git diff --check` 통과

## 잔여 위험

- 실제 Windows GUI에서 스레드 목록 스크롤과 더블클릭 전환은 수동 확인이 필요하다.
- 함수 검색의 그래프 토큰이 없는 항목은 기존처럼 module/offset 기반으로 탐색하므로 같은 주소 중복 노드가 있을 때 첫 매칭 노드로 이동한다.

## 다음 단계 영향

- Stage 3에서 최종 검증과 보고서를 정리한다.
- Issue #5는 노드 더블클릭/보라색 스레드 라벨/Ghidra goto 점검용 별도 작업으로 생성했으며, #4에서는 진행하지 않는다.

## 승인 요청

- Stage 2 산출물과 검증 결과를 승인하면 Stage 3으로 진행한다.
