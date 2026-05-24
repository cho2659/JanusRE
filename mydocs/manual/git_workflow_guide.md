# Git 워크플로우 매뉴얼

본 매뉴얼은 본 저장소의 브랜치 정책, Git 워크플로우 다이어그램, 메인테이너/컨트리뷰터 워크플로우 스크립트를 정의한다. 새 타스크 브랜치를 만들거나 PR 게시·merge·정리를 수행하기 전에 읽는다. 문서 파일 위치와 타스크 승인 절차는 각각 `document_structure_guide.md`, `task_workflow_guide.md`에서 다룬다.

## 핵심 용어

- **`main`**: 모든 작업 PR이 모이는 개발 통합 브랜치. 새 작업 브랜치는 최신 `origin/main` 기준으로 만든다.
- **`local/taskN`**: 이슈 번호 N의 로컬 작업 브랜치. 단계 커밋과 보고서 커밋은 이 브랜치에 쌓는다.
- **`publish/taskN`**: `local/taskN`을 원격에 게시하기 위한 PR용 브랜치. PR merge 후 삭제한다.
- **Open PR**: 검토 가능한 상태의 PR. 하이퍼-워터폴 최종 보고 후 `main` 대상으로 만든다.
- **분리 worktree**: 메인 worktree가 다른 작업에 쓰이고 있을 때 별도 디렉터리에서 같은 저장소의 다른 브랜치를 작업하는 방식.

## 브랜치 관리

| 브랜치 | 용도 |
|--------|------|
| `main` | 개발 통합 및 릴리즈 |
| `local/task{num}` | 타스크별 작업 |
| `publish/task{num}` | `main` 대상 PR 생성을 위한 원격 게시 브랜치. PR merge 후 삭제 |

## Git 워크플로우

```
local/task{N} ── 커밋 · 커밋 · 커밋 ──→ publish/task{N} push
                                          │
                                          └─→ main 대상 PR → 리뷰 → merge
                                                             │
                                                             └─→ main 누적 → 태그
```

병렬 task는 각각 독립적인 `local/task{N}` 브랜치로 위 흐름을 반복한다.

- **타스크 브랜치**: `local/task{N}`에서 잘게 커밋. 작업 단위마다 커밋.
- **원격 게시 브랜치**: `local/task{N}` 작업이 리뷰 가능한 상태가 되면 `publish/task{N}` 이름으로 원격에 push하고 `main` 대상 PR을 생성한다.
- **원격 push**: `local/task` 브랜치는 **로컬 유지 (원격 push 금지)**를 원칙으로 한다. 원격에는 `publish/task{N}`와 merge 결과 브랜치만 유지한다.
- **merge 전략**: `main` 대상 PR은 merge commit 유지 또는 `--no-ff` 원칙을 기본으로 한다. squash merge는 단계별 커밋 의미가 사라질 수 있으므로 기본값으로 두지 않는다.

## 메인테이너 워크플로우

```bash
# 1. local/taskN → publish/taskN push + main 대상 Open PR
git checkout local/task17
git push origin local/task17:publish/task17
gh pr create --base main --head publish/task17 --title "Task #17: 제목" --body-file /tmp/task17-pr-body.md

# 2. main 대상 PR 리뷰 + merge
gh pr review --approve
gh pr merge --merge --delete-branch

# 3. merge 후 정리
git fetch origin --prune
git checkout main
git pull --ff-only
git branch -d local/task17
```

## 컨트리뷰터 워크플로우 (Fork 기반)

```bash
# 1. 원본 저장소 Fork (GitHub에서 1회)
# 2. Fork한 저장소에서 작업
git clone https://github.com/{contributor}/frida_delta.git
git checkout -b feature/my-task
# ... 작업 + 커밋 ...
git push origin feature/my-task

# 3. 원본 저장소의 main으로 PR 생성
gh pr create --repo frida_delta --base main --head {contributor}:feature/my-task --title "제목"
```

## FAQ / 흔한 실수

### 잘못된 브랜치를 원격에 push했을 때

원격에 `local/taskN`을 직접 올렸거나 잘못된 이름으로 push한 경우 즉시 추가 push를 멈춘다. 아직 PR을 만들지 않았다면 올바른 `publish/taskN` 브랜치를 새로 push하고, 잘못 올라간 원격 브랜치는 작업지시자 확인 후 삭제한다.

### merge 후에도 로컬 브랜치가 남아 있을 때

PR이 `MERGED` 상태인지 먼저 확인한다. merge 확인 후 `main`으로 돌아와 최신화하고, 원격 `publish/taskN`과 로컬 `local/taskN`을 정리한다. 이 절차는 [`pr-merge-cleanup`](../skills/pr-merge-cleanup/SKILL.md) SKILL이 문서화한 순서를 따른다.

## 관련 매뉴얼

- [`task_workflow_guide.md`](task_workflow_guide.md): 이슈 기반 타스크 시작, 단계 승인, 최종 보고, PR 게시 순서.
- [`document_structure_guide.md`](document_structure_guide.md): 계획서, 단계 보고서, 최종 보고서의 문서 위치와 파일명.
- [`pr_process_guide.md`](pr_process_guide.md): PR 처리 entrypoint.
