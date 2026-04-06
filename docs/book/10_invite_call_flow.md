# 10. INVITE와 통화 성립 흐름

## 10.1 왜 INVITE가 핵심인가

REGISTER가 위치를 준비하는 단계라면, INVITE는 이 프로젝트의 실제 통화 제어 중심이다. SIPLite의 stateful proxy 성격은 대부분 INVITE 처리에서 가장 선명하게 드러난다.

핵심 구현:

- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L900) `handleInvite()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2223) `addProxyVia()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2295) `addRecordRoute()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2401) `buildInviteResponse()`
- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L1119) `PendingInvite`
- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L301) `ActiveCall`
- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L325) `Dialog`

## 10.2 INVITE의 큰 흐름

그림 5는 INVITE가 `PendingInvite`와 `Dialog`로 이어지는 중간 상태를 요약한다.

```text
INVITE 수신
  |
  +--> registration lookup
  |      +--> not found -> 404
  |      +--> offline   -> 480
  |
  +--> retransmission check
  +--> caller에게 100 Trying
  +--> Via / Record-Route / Max-Forwards 조정
  +--> Request-URI -> callee Contact
  +--> ActiveCall 생성
  +--> PendingInvite 생성
  +--> callee로 INVITE 전달
  +--> provisional response -> Timer C 연장
  +--> final 2xx -> Dialog 생성
  +--> ACK -> confirmed = true, PendingInvite 제거
```

표 5는 각 단계에서 상태가 어떻게 바뀌는지 보여 준다.

| 단계 | ActiveCall | PendingInvite | Dialog |
|---|---|---|---|
| INVITE 수신 직후 | 생성 | 생성 | 없음 |
| provisional response | 유지 | 유지, Timer C 연장 | 없음 |
| 2xx response | 유지 | 유지 | 생성 가능 |
| ACK 수신 | `confirmed=true` | 제거 | `confirmed=true` |
| CANCEL / error / timeout | 정리 대상 | 제거 | 생성 안 됨 또는 제거 |

`handleInvite()`의 전체 흐름은 다음처럼 정리할 수 있다.

1. 필수 헤더 추출
2. 목적 AoR의 등록 정보 조회
3. 오프라인/미등록 판단
4. CSeq 파싱
5. 재전송 여부 확인
6. caller에게 `100 Trying`
7. 프록시 `Via`, `Record-Route`, `Max-Forwards` 조정
8. Request-URI를 callee Contact로 재작성
9. `ActiveCall` 생성
10. `PendingInvite` 생성
11. deferred CANCEL 여부 확인
12. callee에게 INVITE 전달
13. 이후 응답은 `handleResponse()`에서 이어 처리

이 순서만 봐도 INVITE는 단순 forward가 아니라 다단계 상태 생성 흐름임을 알 수 있다.

## 10.3 목적지 조회

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L918) 이후에서는 `To` URI를 기준으로 등록 정보를 찾는다.

결과는 세 경우로 나뉜다.

- 등록되어 있고 로그인됨 → 전달 가능
- XML상 known user지만 현재 오프라인 → `480 Temporarily Unavailable`
- 아예 없는 사용자 → `404 Not Found`

이 구분은 사용자 경험과 운영 관점에서 중요하다. 서버는 "사용자 자체를 모름"과 "등록은 있으나 현재 부재"를 다르게 답한다.

테스트 근거:

- 미등록 INVITE → 404: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L291)
- registered-but-offline → 480: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L907)
- deregistered user → 480: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L930)

## 10.4 재전송 감지

INVITE는 UDP 환경에서 재전송 가능성이 높다. 이 프로젝트는 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L969) 이후에서 `pendingInvites_`를 보고 재전송 여부를 판단한다.

동작 요약:

- 같은 `Call-ID:CSeq`가 있고 아직 진행 중이면 재전송으로 간주
- 마지막 응답이 있으면 그 응답 재전송
- 없으면 `100 Trying` 재전송
- 새 `ActiveCall`/`PendingInvite`를 다시 만들지 않음

이 처리는 중요하다. 재전송을 새 INVITE로 오해하면 상태가 덮어써지고 call state가 깨질 수 있다.

테스트 근거:

- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L873)

## 10.5 `100 Trying`

새 INVITE에 대해서는 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1013) 이후에서 caller에게 `100 Trying`을 보낸다.

이 응답은 다음 의미를 가진다.

- 요청을 받았음을 즉시 caller에게 알림
- 재전송 억제에 도움
- 이후 실제 callee provisional/final response를 기다리는 동안 transaction을 유지

즉 SIPLite는 caller를 오래 침묵 속에 두지 않으려는 구조다.

## 10.6 헤더 재작성: `Via`, `Record-Route`, `Max-Forwards`

INVITE 처리의 핵심은 헤더 조작이다.

### `addProxyVia()`

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2223)

- 프록시 자신의 top Via 추가
- transport별 `SIP/2.0/UDP`, `TCP`, `TLS` 반영
- 응답이 프록시를 반드시 경유하게 함

### `addRecordRoute()`

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2295)

- 이후 ACK/BYE/re-INVITE가 프록시를 경유하도록 route set 형성
- TLS면 `sips:`
- TCP면 `;transport=tcp`

### `decrementMaxForwards()`

- 루프 방지용 hop 감소

이 세 함수는 INVITE 처리의 프록시적 성격을 가장 잘 보여준다.

## 10.7 Request-URI 재작성

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1028) 이후에서 callee의 `Contact`를 기준으로 Request-URI를 재작성한다.

이 작업의 의미:

- 논리 주소 AoR에서 실제 도달 주소 Contact로 내려간다.
- location service 조회 결과를 실제 네트워크 목적지로 반영한다.
- 이후 BYE 같은 in-dialog 요청에서도 이 Contact 정보가 중요해진다.

즉 이 단계에서 "사용자 주소"가 "실제 라우팅 주소"로 바뀐다.

## 10.8 `ActiveCall` 생성

새 INVITE는 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1056) 이후에서 `ActiveCall`을 만든다.

저장되는 핵심 정보:

- caller/callee URI
- fromTag/toTag
- caller/callee IP, port
- caller/callee transport
- startTime
- confirmed = false

중요한 점은 caller/callee transport를 둘 다 저장한다는 것이다. 이것이 나중에 ACK/BYE/CANCEL/응답을 정확한 transport로 보내는 기반이 된다.

## 10.9 `PendingInvite` 생성

`PendingInvite`는 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1072) 이후에서 생성된다.

핵심 저장값:

- caller/callee 주소와 transport
- `origRequest`
- `callerRequest`
- `callerContact`
- `timerCExpiry`
- `lastResponse`

### 왜 중요한가

이 구조는 다음 후속 처리를 위해 필요하다.

- provisional / final response 매칭
- caller에게 응답 역전달
- callee에게 CANCEL 생성
- ACK 생성
- Timer C timeout 처리

즉 `PendingInvite`는 "통화가 아직 성립되지 않은 중간 세계"를 표현하는 상태다.

## 10.10 deferred CANCEL

이 프로젝트의 흥미로운 구현 중 하나는 INVITE와 CANCEL의 순서 역전을 고려한다는 점이다.

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1095) 이후를 보면, 이미 `pendingCancels_`에 동일 키가 존재하면 INVITE를 곧바로 취소 상태로 처리한다.

이 설계는 현실적인 네트워크 문제를 반영한다.

- UDP 재정렬
- 멀티 워커 환경에서 처리 순서 차이

즉 SIPLite는 "항상 INVITE가 먼저, CANCEL이 나중"이라는 순진한 가정을 두지 않는다.

## 10.11 실제 전달

모든 상태가 준비되면 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1134) 이후에서 callee에게 INVITE를 보낸다.

중요한 점:

- 목적지는 `regCopy.ip`, `regCopy.port`
- transport는 `regCopy.transport`

즉 라우팅 결과는 등록 상태를 통해 나온다. 이것이 REGISTER와 INVITE가 긴밀히 연결되는 이유다.

## 10.12 응답 처리와 dialog 생성

INVITE 흐름은 `handleInvite()`만으로 끝나지 않는다. 실제 호 성립은 `handleResponse()`와 연결해서 봐야 한다.

핵심 동작:

- provisional response면 pending state 갱신, Timer C 연장
- 2xx면 dialog 생성 가능
- 3xx-6xx면 ACK 생성, call/dialog 정리

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L476) 이후를 보면 2xx 응답에서 `Dialog`를 만들고, callee Contact를 `remoteTarget`으로 저장한다.

이것이 이후 ACK, BYE forwarding의 핵심 기반이 된다.

## 10.13 ACK와 통화 확정

caller가 ACK를 보내면 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1152)의 `handleAck()`가 실행된다.

핵심 동작:

- caller/callee 어느 쪽에서 온 ACK인지 판별
- `ActiveCall.confirmed = true`
- `Dialog.confirmed = true`
- pending INVITE 제거
- 필요 시 callee로 ACK 전달

즉 INVITE 흐름에서 ACK는 "호출 성공 응답의 부속 메시지"가 아니라, 통화 상태를 확정하는 이벤트다.

## 10.14 Timer C

정리 상자:
`Timer C`는 "callee가 최종 응답을 보내지 않는 INVITE"가 영원히 남지 않게 하는 안전장치다.
timeout이 나면 caller에는 `408 Request Timeout`, callee에는 `CANCEL`을 보내고 관련 pending state를 정리한다.

INVITE 흐름의 시간 기반 보호장치는 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L535)의 `cleanupTimerC()`다.

동작:

- 최종 응답 없이 오래 남은 pending INVITE 탐색
- caller에게 `408 Request Timeout`
- callee에게 `CANCEL`
- 관련 상태 정리

테스트 근거:

- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L961)

이 기능은 stateful proxy로서의 완성도를 높이는 요소다.

## 10.15 TLS와 INVITE

INVITE 흐름에서 TLS는 매우 중요하다.

만약 callee 등록이 TLS transport라면:

- `regCopy.transport == TLS`
- `sender_`는 `TlsServer::sendTo()` 경로를 택함
- 헤더는 `Via: SIP/2.0/TLS`, `Record-Route: <sips:...>`

테스트 근거:

- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L638)

즉 TLS는 INVITE 처리에서 단순 포트 차이가 아니라 전체 라우팅 의미를 바꾼다.

## 10.16 INVITE 관련 테스트

중요 테스트:

- 기본 INVITE flow: [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L132)
- 미등록 사용자: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L291)
- 필수 헤더 누락: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L311)
- 재전송 감지: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L873)
- offline user: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L907)
- Timer C: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L961)

## 10.17 이 장의 핵심 정리

SIPLite의 INVITE 흐름은 다음 네 가지가 결합된 구조다.

- 등록 조회
- SIP 헤더 재작성
- 상태 생성
- 응답/타이머 기반 후속 제어

즉 `handleInvite()`는 단순 포워딩 함수가 아니라 통화 상태 머신의 시작점이다.

다음 장에서는 성립된 통화가 어떻게 유지되다가 종료되는지, ACK/BYE/CANCEL 흐름을 본다.
