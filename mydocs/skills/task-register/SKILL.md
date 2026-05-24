---
name: task-register
description: |
  하이퍼-워터폴 작업에서 아직 GitHub Issue가 없는 신규 타스크를 등록한다.
  열린 milestone과 기존 label을 조회해 후보를 고르고,
  이슈 생성 전 작업지시자 확인을 받은 뒤 GitHub Issue 번호를 만든다.
  이슈 생성 후 브랜치/오늘할일/수행계획서는 task-start 절차로 넘긴다.
---

# 하이퍼-워터폴 이슈 등록

## 트리거

- 작업지시자가 "이 작업 이슈 등록", "새 타스크 생성", "이슈부터 만들어줘"처럼 GitHub Issue 생성을 명시한 경우
- 작업지시자가 본 SKILL을 직접 호출한 경우

## 사전 조건

- 아직 이슈 번호가 없는 작업
- 작업 목적, 배경, 범위가 최소한 초안 수준으로 정리됨
- 현재 사용자 자격 증명으로 `gh` CLI 인증 완료
- 가능하면 GitHub Issue Form `.github/ISSUE_TEMPLATE/task.yml`을 읽을 수 있음
- 이슈 생성 전 제목, 본문, milestone, label 초안을 작업지시자에게 확인받을 수 있음

## 절차

1. 중복 이슈 확인
   ```bash
   gh issue list --state all --search "{작업 키워드}" --limit 20 \
     --json number,title,state,milestone,labels,url
   ```
   - 실질적으로 같은 열린 이슈가 있으면 새 이슈를 만들지 말고 기존 이슈 사용 여부를 확인한다.
2. 열린 milestone 목록 확인
   ```bash
   gh api repos/{owner}/{repo}/milestones \
     --jq '.[] | {number,title,state,description,open_issues,closed_issues}'
   ```
3. 기존 label 목록 확인
   ```bash
   gh api repos/{owner}/{repo}/labels --paginate \
     --jq '.[] | {name,description,color}'
   ```
4. milestone 후보 선택 — 열린 milestone만 후보로 사용. 후보가 명확하지 않으면 작업지시자에게 확인
5. label 후보 선택 — 기존 label만 후보로 사용. 새 label은 만들지 않는다
6. 이슈 초안 작성 (`.github/ISSUE_TEMPLATE/task.yml` 기준 섹션 사용)
7. 이슈 생성 전 승인 요청 — 작업지시자 명시 승인 전에는 `gh issue create` 실행 금지
8. 승인 후 이슈 생성
   ```bash
   gh issue create --title "{제목}" --body "{본문}" \
     --milestone "{milestone}" --label "{label}"
   ```
9. 생성 결과 확인 후 작업지시자에게 이슈 번호·URL 보고 및 `task-start` 진입 승인 요청

## 검증

- 생성된 이슈가 `OPEN` 상태여야 한다
- milestone이 live 조회 결과에 있던 열린 milestone이어야 한다
- label은 초안에서 승인된 기존 label만 붙어 있어야 한다

## 절대 하지 말 것

- 작업지시자 승인 없이 `gh issue create` 실행
- 새 milestone 또는 새 label 생성
- 이슈 생성 후 승인 없이 `task-start`까지 이어서 실행

## 호출 방법

- Claude Code: `/task-register`
