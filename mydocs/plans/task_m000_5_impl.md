# Task M000 #5 구현계획서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)

## Stage 1 - 노드 상호작용 제거

- `NodeItem`의 하위 호출 펼침 hotspot 제거
- `mousePressEvent()`의 custom 클릭 처리 제거
- `mouseDoubleClickEvent()`는 이벤트를 소비하고 아무 동작도 하지 않게 변경
- 검증: `python -m py_compile bridge_server.py`, `git diff --check`

## Stage 2 - 보고

- 단계/최종 보고서 정리
