# 문서 구조와 명명 규칙 매뉴얼

본 매뉴얼은 `mydocs/` 하위 폴더 역할, 문서 파일명 규칙, 중앙 문서 템플릿 정책, GitHub 플랫폼 템플릿 경계, 외부 기여자 PR 검토 폴더 정책, Agent Skills 위치 정책을 정의한다. 새 문서를 만들거나 기존 문서의 위치를 옮기기 전에 읽는다. 코드 작성 방식, Git 브랜치 운용, 타스크 단계 진행 절차는 이 문서가 아니라 관련 매뉴얼에서 다룬다. 모든 문서는 한국어로 작성한다.

`mydocs/`는 문서를 많이 쌓기 위한 폴더가 아니다. 새 세션의 AI가 "지금 무엇을 해야 하는가", "어떻게 하기로 했는가", "어디까지 했는가", "왜 그렇게 판단했는가", "어떤 함정이 있었는가"를 저장소만 읽고 복원하게 하는 작업 기억 체계다.

## 핵심 용어

- **문서 진실 원천**: 같은 정보를 여러 곳에 복제하지 않고, 최신 기준으로 삼는 단일 문서 또는 폴더.
- **문서 템플릿 진실 원천**: 산출물별 출력 형식을 정의하는 `mydocs/_templates/` 폴더.
- **GitHub 플랫폼 템플릿**: GitHub Issue나 Pull Request처럼 GitHub UI/CLI가 만드는 플랫폼 산출물의 입력 또는 본문 형식을 정의하는 `.github/ISSUE_TEMPLATE/`와 `.github/pull_request_template.md`.
- **공식 문서 루트**: 대상 프로젝트가 사용자, 기여자, 외부 통합자, 배포 채널을 위해 공식적으로 채택한 제품 문서 위치. 예: `docs/`, `specs/`, `site/`, `website/`, `adr/`, `book/`, GitHub Wiki. Hyper-Waterfall은 이 이름을 고정하지 않는다.
- **실제 산출물 문서**: 특정 날짜, 이슈, PR, 조사 주제에 대해 작성된 문서. 예: `orders/20260506.md`, `plans/task_m010_3.md`.
- **내부 타스크**: GitHub Issue를 기준으로 수행계획서, 구현계획서, 단계 보고서, 최종 보고서를 남기는 저장소 내부 작업.
- **외부 기여 PR**: 외부 기여자가 제출한 Pull Request를 검토하는 작업. 내부 타스크와 다른 폴더와 절차를 사용한다.
- **마일스톤 포함 문서명**: `task_m010_49.md`처럼 마일스톤과 이슈 번호를 함께 넣은 신규 문서명.
- **Agent Skills 진실 원천**: Claude Code가 함께 읽는 `mydocs/skills/{skill-name}/SKILL.md`.

## 문서 파일명 규칙

신규 내부 타스크 문서의 표준 형식은 GitHub Issue 번호와 마일스톤을 함께 사용한다.

- 수행 계획서: `task_{milestone}_{이슈번호}.md` (예: `task_m100_7.md`)
- 구현 계획서: `task_{milestone}_{이슈번호}_impl.md` (예: `task_m100_7_impl.md`)
- 단계별 완료 보고서: `task_{milestone}_{이슈번호}_stage{N}.md` (예: `task_m100_7_stage1.md`)
- 최종 보고서: `task_{milestone}_{이슈번호}_report.md` (예: `task_m100_7_report.md`)

지원 문서는 주제와 날짜를 함께 알 수 있게 작성한다.

- 오늘할일: `{yyyymmdd}.md` (예: `20260506.md`)
- 피드백: `{yyyymmdd}_{topic}.md` 또는 `task_{milestone}_{이슈번호}_feedback.md`
- 기술 조사: `{yyyymmdd}_{topic}.md` 또는 `task_{milestone}_{이슈번호}_{topic}.md`
- 트러블슈팅: `{yyyymmdd}_{topic}.md` 또는 `task_{milestone}_{이슈번호}_{topic}.md`
- 외부 PR 검토 문서: `pr_{번호}_review.md`, `pr_{번호}_review_impl.md`, `pr_{번호}_report.md`

강제 규칙:

- 신규 내부 타스크 문서는 반드시 `task_{milestone}_{이슈번호}` 형식을 사용한다.
- 마일스톤은 항상 `m{숫자}` 형식으로 적는다. 예: `m100`, `m200`
- 마일스톤 없이 `task_{이슈번호}` 형식으로 신규 내부 타스크 문서를 만들지 않는다.
- 기존 레거시 문서명은 유지할 수 있으나, 신규 이슈부터는 마일스톤 포함 형식을 고정한다.
- 실제 산출물 폴더 내부에는 템플릿 파일을 두지 않는다. 템플릿은 중앙 템플릿 폴더인 `mydocs/_templates/`에만 둔다.

## 폴더 역할 (엄격 준수)

| 폴더 | 용도 | 비고 |
|------|------|------|
| `_templates/` | 문서 출력 형식 템플릿 | 실제 task 산출물이 아니라 산출물별 작성 형식의 진실 원천 |
| `orders/` | 오늘 할일 | `yyyymmdd.md`만 허용. 상세 조사/분석은 `tech/` 또는 `troubleshootings/`에 기록. 완료 항목은 비고에 `완료: HH:mm` 형식으로 완료 시각 기록 |
| `plans/` | 수행/구현 계획서 | `_stage{N}`, `_report` 파일은 두지 않는다 |
| `plans/archives/` | 완료된 계획서 보관 | merge 후 정리 시 사용 |
| `working/` | 단계별 완료 보고서 (`_stage{N}.md`) | 최종 보고서는 두지 않는다 |
| `report/` | 최종 결과보고서 (`_report.md`) + 장기 보관 보고서 | 최종 보고서는 반드시 이 폴더 |
| `feedback/` | 작업지시자 피드백, 코드 리뷰 의견 | AI가 스스로 만들 수 없는 인간 판단을 보존 |
| `tech/` | 기술 조사, 구조/스펙 분석 | 재사용 가능한 조사 근거, 대안 비교, 공식화 전 초안 |
| `manual/` | 운영 매뉴얼, 가이드 | Hyper-Waterfall 운영 절차, 에이전트 규칙, 반복 적용되는 작업 기준 |
| `troubleshootings/` | 트러블슈팅, 재발 방지 기록 | 해결 과정과 함정을 남기는 폴더 |
| `pr/` | 외부 기여자 PR 검토 기록 | 내부 타스크와 분리 |
| `pr/archives/` | 처리 완료된 PR 검토 기록 보관 | |
| `skills/` | Agent Skills SKILL.md 진실 원천 | `.claude/skills` 심볼릭 링크가 이 폴더를 가리킨다 |

## 공식 문서 루트와 `mydocs/` 경계 정책

Hyper-Waterfall은 적용 대상 프로젝트의 공식 문서 루트 이름을 고정하지 않는다. 대상 프로젝트는 성격에 따라 `docs/`, `specs/`, `site/`, `website/`, `adr/`, `book/`, GitHub Wiki 등을 선택할 수 있다.

강제 규칙:

- 신규 Hyper-Waterfall 적용 중에는 공식 문서 루트를 선택하거나 생성하지 않는다.
- 제품/사용자/기여자/외부 통합/API/아키텍처/로드맵 문서를 만들거나 옮기는 task는 수행계획서에 문서 위치 판단을 기록하고 작업지시자 승인을 받는다.
- `mydocs/manual/`은 대상 프로젝트 제품 문서 위치가 아니다. 반복 적용되는 Hyper-Waterfall 운영 절차와 기준만 둔다.
- `mydocs/tech/`는 기술 조사와 설계 판단 근거 위치다. 공식 계약이나 사용자 참조 문서로 승격하려면 별도 task에서 공식 문서 루트를 선택하고 승인받는다.

## Agent Skills 위치 정책

진실 원천은 `mydocs/skills/{skill-name}/SKILL.md`다. Claude Code는 `.claude/skills` 심볼릭 링크 또는 직접 경로로 이 파일을 읽는다.

강제 규칙:

- 새 Skill을 추가하면 `mydocs/skills/`에 폴더를 만들고 `SKILL.md`를 작성한다.
- `mydocs/skills/`와 `.claude/skills/` 내용이 항상 동일해야 한다.
- Skill 파일을 변경하면 `task_workflow_guide.md`의 "SKILL 호출 표시 안내" 섹션을 함께 확인한다.

## 중앙 템플릿 정책

문서 출력 형식은 `mydocs/_templates/`에서 관리한다.

강제 규칙:

- 산출물 폴더 내부에는 템플릿 파일을 두지 않는다.
- 템플릿 파일은 실제 산출물로 오해되지 않도록 첫 제목에 `템플릿`을 포함한다.
- 템플릿이 바뀌면 관련 Skill의 템플릿 참조와 `task_workflow_guide.md`의 문서 구조 설명을 함께 확인한다.

## GitHub 플랫폼 템플릿 정책

- Issue Form 위치: `.github/ISSUE_TEMPLATE/task.yml`
- PR 본문 템플릿 위치: `.github/pull_request_template.md`

역할 구분:

- `.github/ISSUE_TEMPLATE/task.yml`: GitHub Issue를 다음 작업의 첫 입력 프롬프트로 만들기 위해 배경, 목표, 포함 범위, 제외 범위, 수용 기준, 검증 기준, 참고, 메타데이터를 구조화한다.
- `.github/pull_request_template.md`: 최종 보고 후 PR 리뷰 화면에 들어갈 요약, 변경 내역, 검증, 남은 리스크의 출력 형식을 정의한다.
- `mydocs/_templates/`: 수행계획서, 구현계획서, 단계 보고서, 최종 보고서, 피드백, 기술 조사, 트러블슈팅, 외부 PR 검토 문서처럼 저장소 안에 남는 문서 산출물의 출력 형식을 정의한다.

## 관련 매뉴얼

- [`task_workflow_guide.md`](task_workflow_guide.md): 타스크 진행 절차, 커밋 메시지, 승인 조건.
- [`git_workflow_guide.md`](git_workflow_guide.md): 브랜치 흐름과 merge 전략.
- [`agent_code_hyperfall_rule_conflict.md`](agent_code_hyperfall_rule_conflict.md): 에이전트 기본 동작과 충돌 지점.
