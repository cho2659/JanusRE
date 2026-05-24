---
name: task-final-report
description: |
  하이퍼-워터폴 타스크의 최종 보고와 PR 게시 절차를 적용한다.
  최종 결과 보고서(`_report.md`) 작성, 오늘할일 완료 처리, 최종 커밋,
  publish/task{N} 원격 push, main 대상 Open PR 생성을 수행한다.
  모든 단계 완료 후 PR 직전에만 호출.
---

# 하이퍼-워터폴 최종 보고와 PR 게시

## 트리거

- 작업지시자가 "최종 보고서 작성", "PR 준비"를 명시 지시한 경우
- 본 SKILL을 직접 호출한 경우

## 사전 조건

- 구현 계획서의 모든 단계 종료, 각 단계 보고서 커밋 완료
- 통합 검증(전체 수용 기준) 통과 확인
- `local/task{N}`에 commit 안 된 변경 없음 또는 본 절차에서 함께 커밋할 것만 남아 있음

## 절차

1. 통합 검증: 구현 계획서의 "수용 기준" 명령 실행
2. 최종 보고서 작성: `mydocs/report/task_m{milestone}_{N}_report.md`
   - 중앙 템플릿 `mydocs/_templates/final_report.md`를 기준으로 작성한다.
3. 오늘할일 갱신: `mydocs/orders/{yyyymmdd}.md`의 #{N} 행 상태 `완료`로 변경, 비고에 `완료: HH:mm` 기록
4. 변경 점검
   ```bash
   git status --short
   git diff --check
   git log --oneline main..local/task{N}
   ```
5. 최종 커밋
   ```bash
   git add mydocs/report/task_m{milestone}_{N}_report.md mydocs/orders/{yyyymmdd}.md
   git commit -m "Task #{N} Stage {마지막} + 최종 보고서: {요약}"
   ```
6. 원격 게시 브랜치 push
   ```bash
   git push origin local/task{N}:publish/task{N}
   ```
7. main 대상 Open PR 생성
   ```bash
   HEAD_SHA=$(git rev-parse HEAD)
   PR_BODY=/tmp/task{N}-pr-body.md
   gh pr create --base main --head publish/task{N} \
     --title "Task #{N}: {제목}" \
     --body-file "$PR_BODY"
   ```
   - PR 본문은 `.github/pull_request_template.md`를 기준으로 작성한다.
8. 작업지시자에게 PR URL 전달과 리뷰·merge 승인 요청

## 검증

- 모든 단계 보고서 + 최종 보고서 존재
- `git status --short` 결과 빈 출력
- `gh pr view` 결과에 draft가 아닌 PR이 정확한 base/head로 등록
- 오늘할일 #{N} 상태 `완료` + `완료: HH:mm`

## 절대 하지 말 것

- 통합 검증 실패 상태에서 PR 생성
- `local/task{N}` 브랜치를 원격에 직접 push (반드시 `publish/task{N}`로 명명)
- 작업지시자 명시 지시 없이 Draft PR로 생성하거나 self-merge

## 호출 방법

- Claude Code: `/task-final-report`
