# 11. ACK, BYE, CANCEL 흐름

## 11.1 이 장의 목적

INVITE가 통화를 시작하는 장이라면, ACK/BYE/CANCEL은 그 통화를 안정화하거나 종료하는 장이다. SIPLite에서 이 세 메서드는 모두 stateful 처리의 핵심이다.

관련 코드:

- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1152) `handleAck()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1247) `handleBye()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1433) `handleCancel()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2474) `buildAckForPending()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2539) `buildCancelForPending()`

## 11.2 ACK: 통화 확정

ACK는 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1152)의 `handleAck()`가 담당한다.

흐름은 다음과 같다.

1. `Call-ID`, `CSeq` 확인
2. `ActiveCall`에서 caller/callee 측 판별
3. `confirmed = true` 반영
4. `Dialog.confirmed = true`
5. 해당 pending INVITE 제거
6. 필요 시 callee 방향으로 ACK 전달

이 구현에서 중요한 점은 ACK가 단순 전송이 아니라 상태 전이 이벤트라는 점이다.

### caller 쪽 ACK

caller가 ACK를 보내면:

- 통화는 확정된 것으로 간주
- callee로 ACK 전달

### callee 쪽 ACK

callee 쪽에서 들어온 ACK를 별도 문맥으로 만날 수 있는 경우도 고려한다. 이 경우에도 상태는 confirmed로 본다.

즉 ACK는 단순 confirmation message가 아니라 `ActiveCall`, `Dialog`를 확정 상태로 전환하는 이벤트다.

## 11.3 ACK 전달 시 헤더 처리

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1224) 이후를 보면 전달되는 ACK는 다음 조작을 거친다.

- `addProxyVia(...)`
- `decrementMaxForwards(...)`
- `stripOwnRoute(...)`

즉 ACK도 in-dialog proxy routing 규칙을 따른다. 특히 `Route` 제거가 들어간다는 점은 loose routing을 의식한 구현이다.

## 11.4 BYE: 통화 종료

BYE는 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1247)의 `handleBye()`가 담당한다.

큰 흐름:

1. `Call-ID` 확인
2. `Dialog`에서 상대편 정보 조회
3. 필요 시 `ActiveCall`에서 보조 조회
4. 첫 번째 BYE인지, 재전송인지, cross-BYE인지 판정
5. pending INVITE 정리
6. `200 OK` 생성
7. 상대편으로 BYE 전달

이 흐름은 단순 "상태 삭제"가 아니라, SIP BYE를 양쪽 사이에 실제로 중계하는 프록시/B2BUA 성격을 보여준다.

## 11.5 첫 번째 BYE와 cross-BYE

현재 구현에서 흥미로운 부분은 BYE를 한 번 받았다고 바로 상태를 지우지 않는다는 점이다.

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1296) 이후를 보면 다음 구분이 있다.

- 같은 방향 재전송
- 상대편도 BYE를 보낸 cross-BYE
- 첫 번째 정상 BYE

### 첫 번째 BYE

- `byeReceived = true`
- 발신자 IP/port 기록
- 상태를 바로 지우지 않음

### 같은 방향 재전송

- UDP 손실 대비 재전송으로 간주
- 상태 유지

### cross-BYE

- 상대편도 종료 요청 보낸 상황
- `Dialog`, `ActiveCall` 제거

이 설계는 실제 네트워크 환경의 중복 BYE와 양방향 종료 경쟁을 의식한 구현이다.

## 11.6 BYE 전달

BYE는 단순히 상태를 정리하는 것으로 끝나지 않는다. [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1395) 이후에서 상대편에게도 전달한다.

전달 시 수행되는 작업:

- 프록시 `Via` 추가
- `Max-Forwards` 감소
- 자신의 `Route` 제거
- 상대방 Contact URI로 Request-URI 재작성

이 점은 중요하다. SIPLite의 BYE 처리는 "call teardown bookkeeping"이 아니라, 실제 in-dialog SIP routing 구현이다.

## 11.7 존재하지 않는 통화의 BYE

상태를 찾지 못하면 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1418) 이후에서 `481 Call/Transaction Does Not Exist`를 반환한다.

이는 표준적이고 합리적인 선택이다. 의미 없는 BYE를 조용히 성공 처리하지 않는다.

테스트 근거:

- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L379)

## 11.8 CANCEL: 아직 성립되지 않은 INVITE 취소

CANCEL은 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1433)의 `handleCancel()`가 처리한다.

핵심 개념:

- CANCEL은 확정 dialog를 끝내는 것이 아니라, 아직 진행 중인 INVITE transaction을 취소한다.
- 따라서 매칭 기준은 dialog state보다 `PendingInvite`다.

흐름:

1. `Call-ID`, `CSeq` 확인
2. `Call-ID:CSeq` 키 생성
3. `pendingInvites_` 조회
4. 있으면 caller에 `200 OK`
5. 아직 완료되지 않은 INVITE면 callee로 CANCEL 전달
6. 없으면 `481`
7. 동시에 `pendingCancels_`에 등록 가능

## 11.9 COMPLETED INVITE에 대한 CANCEL

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1475) 이후를 보면, 이미 `COMPLETED` 상태인 INVITE에 대해서는 CANCEL이 실질 효과를 갖지 않는다.

이 경우:

- CANCEL 요청 자체에는 `200 OK`
- callee에게는 실제 CANCEL 전달 안 함

이는 SIP transaction semantics에 맞는 처리다.

## 11.10 INVITE보다 먼저 온 CANCEL

이 프로젝트의 흥미로운 구현 중 하나는 `pendingCancels_`다.

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1504) 이후를 보면, matching INVITE가 아직 없으면 `pendingCancels_`에 key를 넣는다.

이유:

- UDP 재정렬
- 멀티 워커 환경에서 처리 순서 역전

나중에 INVITE가 오면 `handleInvite()`에서 deferred CANCEL로 바로 취소한다.

즉 SIPLite는 CANCEL을 순서에 민감한 단순 부속 메서드로 다루지 않는다. 실제 네트워크 비정상 순서를 흡수하려는 설계다.

## 11.11 CANCEL 생성

callee 방향 CANCEL은 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2539)의 `buildCancelForPending()`가 만든다.

핵심 규칙:

- 원본 INVITE의 top Via 사용
- 같은 Request-URI 사용
- 같은 `Call-ID`
- 같은 숫자 CSeq에 메서드만 `CANCEL`
- 기존 `Route` 포함

이 구현은 CANCEL이 원본 INVITE와 transaction적으로 강하게 묶여 있음을 잘 보여준다.

## 11.12 에러 응답과 프록시 ACK

ACK는 caller가 보내는 2xx ACK만 있는 것이 아니다. 프록시는 3xx-6xx 응답에 대해 ACK를 생성해야 하는 경우가 있다.

이 흐름은 `handleResponse()`에서 보인다.

- 에러 응답 수신
- `buildAckForPending()`
- callee로 ACK 전송
- caller에는 응답 forward

즉 ACK 장을 쓸 때는 "request method ACK"와 "proxy-generated error ACK"를 함께 설명해야 한다.

## 11.13 관련 테스트

중요 테스트:

- 기본 CANCEL flow: [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L168)
- BYE terminates active call: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L338)
- nonexistent BYE → 481: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L379)
- CANCEL missing Call-ID → 400: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L1101)
- BYE forwarded to callee: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L1127)

이 테스트들은 ACK/BYE/CANCEL이 단순 상태 삭제가 아니라 실제 포워딩과 응답 생성을 포함한 흐름임을 뒷받침한다.

## 11.14 이 장의 핵심 정리

ACK, BYE, CANCEL은 각각 역할이 다르다.

- ACK는 통화를 확정한다.
- BYE는 성립된 통화를 상대편과 함께 종료한다.
- CANCEL은 아직 성립되지 않은 INVITE를 취소한다.

SIPLite는 이 차이를 상태 모델과 transaction 모델 안에 실제로 반영하고 있다.

다음 장에서는 call control을 잠시 벗어나, subscription 기반 흐름인 SUBSCRIBE/NOTIFY를 본다.
