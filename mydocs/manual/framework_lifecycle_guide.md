# Framework Lifecycle 작업 가이드

이 문서는 Hyper-Waterfall 방법론 자체를 새 저장소에 설치하거나 기존 적용 저장소를 새 version으로 업데이트할 때의 판단 기준과 일반 task 전환 규칙을 정의한다. 일반 기능 task의 단계 진행 절차는 `task_workflow_guide.md`를 따른다.

## 적용 시점

- 대상 저장소에 Hyper-Waterfall을 처음 적용할 때
- 이미 적용된 저장소를 새 GitHub Release/tag 기준으로 업데이트할 때

## 파일 변경 전 판단

Lifecycle 판단 결과는 파일 변경 전 보고다. 신규 적용이나 기존 업데이트 모두 다음 정보를 먼저 작업지시자에게 제시하고 승인을 받아야 한다.

- 대상 저장소
- 목표 release/tag
- 현재 version (기존 업데이트)
- 자동 적용 가능 항목
- 수동 확인 필요 항목
- conflict 항목
- 승인 요청

기존 사용자 수정 파일이 감지되면 즉시 덮어쓰지 않는다. 자동 적용 가능 항목, 수동 확인 필요 항목, conflict 항목을 구분한 뒤 작업지시자 승인을 받는다.

## 일반 task 흐름 전환

판단 결과가 승인되면 다음처럼 일반 타스크 흐름으로 전환한다.

1. 이슈가 없으면 `task-register`로 lifecycle 반영 이슈를 먼저 등록한다.
2. 이미 이슈가 있으면 `task-start`로 브랜치, 오늘할일, 수행계획서를 만든다.
3. 승인 전에는 변경 파일을 실제 대상 저장소에 적용하지 않는다.

## 관련 문서

- [`task_workflow_guide.md`](task_workflow_guide.md): 승인 후 일반 task 진행 절차.
- [`document_structure_guide.md`](document_structure_guide.md): 폴더 역할과 파일명 규칙.
