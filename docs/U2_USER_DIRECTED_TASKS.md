# 사용자 지시형 Codex–Claude 업무 매뉴얼

이 문서는 사용자가 “이 일은 Claude가 해”, “Codex가 구현하고 Claude가
검토해”라고 말하는 흔한 상황을 정식 업무 경로로 정의한다. 사용자가 Claude
세션을 열어 프롬프트와 답을 옮기는 방식은 정상 운영 절차가 아니다.

## 정확한 분기

| 사용자의 말 | 작업자 | 반대편 검증자 | 자동 경로 |
|---|---|---|---|
| “Codex가 구현해” | Codex | Claude Reviewer | Codex가 구현한 정확한 Head를 Claude가 검토한다 |
| “Claude가 구현해” | Claude Maker | Codex | 별도 Maker 상시 위임이 승인된 뒤에만 자동 실행한다 |
| “Claude/Fable이 디자인을 검토해” | Claude Reviewer / Fable 5 | Codex | 실제 코드 스냅샷을 읽기 전용으로 검토하고 Codex가 사실관계를 교차검증한다 |
| “둘이 독립적으로 비교해” | Codex와 Claude | Codex가 증거 비교 | 서로의 초안을 보지 않은 두 결과를 만든 뒤 비교한다 |
| “중단해/방향을 바꿔” | 기존 작업 중지 | Controller | 아직 실행되지 않은 release를 무효화하고 새 지시로 다시 분류한다 |

Codex는 Claude에게 배정된 결과를 먼저 작성하지 않는다. Codex가 작성하는 것은
목표, 제외 범위, 실제 코드 SHA, 읽을 수 있는 경로, 완료 기준, 호출 한도뿐이다.

## “Claude가 디자인을 검토해”의 전체 흐름

1. Codex가 원문 지시의 해시와 `requested_assignee=Claude`,
   `intent=design_review`를 기록한다.
2. 코드가 수정 중이면 `create-review-snapshot.py`가 허용된 경로만 별도 커밋과
   worktree로 고정한다. 사용자의 원래 index와 working tree는 건드리지 않는다.
3. `u2_task_intake.py`가 실제 Base, Head, branch를 다시 확인한 뒤
   `draft_paused` 대기열을 만든다. 이 단계에서는 Claude를 호출하지 않는다.
4. 사용자 소유 runner의 review-snapshot lane이 새 작업공간을 자동 발견한다.
   허용된 `codex/review-snapshot/` branch가 아니면 발견해도 실행하지 않는다.
5. 사용자 서명 상시 위임이 그 저장소, 읽기 경로, Reviewer 역할, Fable 5
   프로필, 일일 한도와 유효기간을 모두 포함할 때만 로컬 runner가 대기열을
   자동 해제한다.
6. Claude는 스크린샷 요약이 아니라 제한된 저장소 도구로 실제 diff와 코드를
   직접 읽는다. 소스 수정, Git, shell, 네트워크 도구는 없다.
7. Claude의 원본 결과와 세션 식별자는 owner-only `.agent-state`에 남는다.
8. Codex는 별도 결과로 사실관계와 우선순위를 교차검증한다. Claude 의견을
   Codex 의견으로 덮어쓰지 않는다.
9. 커맨드센터는 지시 접수, 코드 고정, 정책 확인, 배정, 실행, 결과 수신,
   교차검증, 완료를 서로 다른 상태로 표시한다.

## 자동으로 진행하지 않는 경우

- 사용자가 Claude에게 “구현”을 맡겼지만 Reviewer 상시 위임만 있는 경우
- 현재 코드에 비밀, 고객·개인 정보, 원시 래스터, 모델 가중치가 필요한 경우
- 요청 경로가 상시 위임의 읽기 범위를 벗어난 경우
- 하루 호출 한도, 작업당 1회, 유효기간 중 하나라도 끝난 경우
- 스냅샷 이후 코드가 바뀌어 Head가 달라진 경우
- merge, 배포, PR 댓글, 외부 연락, 결제처럼 별도 승인 대상인 경우

이 경우에는 수동 Claude 세션으로 우회하지 않는다. 대기 상태와 정확한 이유를
기록하고, 필요한 권한 또는 방향을 하나의 사용자 결정문으로 묶는다.

## 실행기 명령의 책임

- `scripts/create-review-snapshot.py` (Season 2): 수정 중인 실제 코드를 안전한
  별도 Head로 고정한다.
- `scripts/u2_task_intake.py`: 작업 manifest를 검증하고 paused queue를 만든다.
- `scripts/u2_controller.py sign-standing-policy`: 사용자가 한 번 승인한 정확한
  정책 digest를 서명한다. 설치나 호출은 하지 않는다.
- `scripts/u2_controller.py inspect-standing-policy-draft`: 서명 전 정책의 범위,
  한도, 만료일과 승인할 단 하나의 digest를 기계적으로 계산한다.
- `scripts/u2_user_runner.py`: 사용자 소유 프로세스로서 정책에 맞는 paused
  Reviewer queue를 최대 한 번 해제하고 실행한다. 재시도하지 않는다.
- `scripts/u2_controller.py run-next`: Claude 결과를 요청·검증·기록한다.

## 현재 활성화 경계

코드가 존재하는 것과 실제 상시 위임이 활성화된 것은 다르다. 실행기 변경이
검토·병합되고 정확한 SHA가 runner에 고정되며, 사용자가 숫자 한도와 만료일을
포함한 정책 digest를 한 번 승인·서명하고 외부 runner config에 설치하기 전까지
이 경로는 `proposed_paused`이다. 기존 attended queue 경로는 그대로 유지된다.
