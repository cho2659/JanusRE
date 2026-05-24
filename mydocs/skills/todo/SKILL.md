---
name: todo
description: |
  하이퍼-워터폴의 오늘할일 보드(`mydocs/orders/yyyymmdd.md`)를 작성·갱신한다.
  마일스톤별 표 형식, 상태 갱신, 백로그 섹션 작성 규칙을 적용한다.
  task-start, task-stage-report, task-final-report, pr-merge-cleanup
  절차에서 오늘할일을 갱신할 때도 본 SKILL의 형식을 따른다.
---

# 오늘할일 보드 작성

## 목적

`mydocs/orders/{yyyymmdd}.md`는 그날의 작업 보드 한 장이다. 계획서, 보고서, 기술 노트로 사용하지 않는다. 마일스톤별 작업 진행 상태를 한눈에 보여주고, 완료 시각을 기록하는 용도다.

## 트리거

- 작업지시자가 "오늘할일 작성", "orders 갱신", "오늘할일 마감"처럼 명시 지시한 경우
- `task-start`, `task-stage-report`, `task-final-report`, `pr-merge-cleanup` 절차에서 오늘할일을 갱신할 때 본 SKILL의 형식을 적용
- 본 SKILL을 직접 호출한 경우

## 산출물

- 갱신 대상: `mydocs/orders/{yyyymmdd}.md` 한 파일
- 작성 언어: 한국어
- 출력 형식 기준: `mydocs/_templates/orders.md`

## 표준 형식

중앙 템플릿 `mydocs/_templates/orders.md`를 우선 기준으로 사용한다.

```md
# 오늘 할일 - YYYY년 M월 D일

## M{마일스톤} — {마일스톤 이름}

| Issue | 타스크 | 상태 | 비고 |
|------|--------|------|------|
| #{번호} | {작업} | 예정 | {메모} |
| #{번호} | {작업} | 진행중 | {메모} |
| #{번호} | {작업} | 완료 | {메모} |
```

## 작성 규칙

- GitHub Issue 번호가 있으면 `#번호` 형식으로 적는다.
- 아직 이슈가 없으면 임의 번호나 `미정` 대신 `생성필요`로 적는다.
- 완료 작업은 비고에 `완료: HH:mm`을 포함한다.
- 상태값: `예정`, `진행중`, `완료`, `보류`.

## 절대 하지 말 것

- 계획서, 보고서, 기술 노트 형식의 본문을 `orders/`에 작성
- 마일스톤이 모호하다는 이유로 임의 마일스톤 이름 생성
- 이슈가 있는데도 `생성필요`로 두기

## 호출 방법

- Claude Code: `/todo`
