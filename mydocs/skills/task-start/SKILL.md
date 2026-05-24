---
name: task-start
description: |
  하이퍼-워터폴 타스크 시작 절차를 적용한다.
  GitHub 이슈 등록 확인, main 최신화, local/task{N} 브랜치 생성,
  오늘할일 항목 추가, 수행계획서 템플릿 생성을 수행한다.
  새 코드/문서 변경을 시작하기 전 진행 단계 정렬 용도.
---

# 하이퍼-워터폴 타스크 시작

## 트리거

- 작업지시자가 "이슈 #N 시작", "타스크 #N 진행"처럼 명시 지시한 경우
- 작업지시자가 본 SKILL을 직접 호출한 경우

## 사전 조건

- 작업지시자 승인된 이슈 번호와 마일스톤이 존재
- 작업 대상 저장소 working tree clean (또는 분리된 worktree 사용 결정)
- 현재 사용자 자격 증명으로 `gh` CLI 인증 완료

## 절차

1. 이슈 정보 확인
   ```bash
   gh issue view {N} --json number,title,milestone,state,body
   ```
2. main 최신화
   ```bash
   git fetch origin
   git checkout main
   git pull --ff-only
   ```
3. 작업 브랜치 생성
   ```bash
   git checkout -b local/task{N}
   ```
4. 오늘할일 갱신: `mydocs/orders/{yyyymmdd}.md`에 행 추가
   - 출력 형식은 `mydocs/_templates/orders.md`를 기준으로 한다.
   - 형식: `| #{N} | {타스크 제목} | 진행중 | M{milestone}, 수행계획서 작성 후 승인 대기 |`
5. 수행계획서 생성: `mydocs/plans/task_m{milestone}_{N}.md`
   - 중앙 템플릿 `mydocs/_templates/task_plan.md`를 기준으로 작성한다.
6. 변경 검증
   ```bash
   git status --short
   git diff --check
   ```
7. 단일 커밋
   ```bash
   git add mydocs/plans/task_m{milestone}_{N}.md mydocs/orders/{yyyymmdd}.md
   git commit -m "Task #{N}: 수행 계획서 작성과 오늘할일 갱신"
   ```
8. 작업지시자에게 수행계획서 승인 요청

## 검증

- `git log --oneline -1`이 `Task #{N}: 수행 계획서 작성과 오늘할일 갱신`을 보여야 한다
- `mydocs/orders/{yyyymmdd}.md`에 #{N} 행 존재
- `mydocs/plans/task_m{milestone}_{N}.md`가 필수 섹션을 채움

## 절대 하지 말 것

- 수행계획서 승인 전 구현 계획서 작성
- 수행계획서 승인 전 코드/매뉴얼 변경

## 호출 방법

- Claude Code: `/task-start`
