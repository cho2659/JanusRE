# Task M000 #5 수행계획서

GitHub Issue: [#5](https://github.com/cho2659/JanusRE/issues/5)
마일스톤: M000

## 목적

그래프 노드 클릭/더블클릭 및 펼침 상호작용을 제거해 더블클릭 시 노드가 이상한 위치로 이동하는 문제를 막는다.

## 범위

- `bridge_server.py`의 `NodeItem` 클릭/더블클릭/펼침 처리 제거
- 하위 호출 목록은 표시만 유지하고 클릭 hotspot은 만들지 않음
- Frida/Ghidra/CallTreeBuilder 로직은 변경하지 않음

## 검증

- `python -m py_compile bridge_server.py`
- `git diff --check`
