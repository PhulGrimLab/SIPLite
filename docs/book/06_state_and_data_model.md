# 6. 상태와 데이터 모델

## 6.1 이 장의 목적

SIPLite를 이해하는 데서 가장 어려운 부분은 "어떤 메시지를 처리하는가"보다 "어떤 상태를 보관하는가"다. SIP는 본질적으로 상태를 많이 요구하는 프로토콜이기 때문이다.

현재 프로젝트의 상태 모델은 거의 모두 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)에 정의되어 있다. 이 장에서는 그 상태 구조를 중심으로 전체 서버의 기억 체계를 설명한다.

## 6.2 상태 모델을 왜 먼저 봐야 하는가

메서드 핸들러는 순간 동작을 보여주지만, 상태 구조는 시스템의 장기 기억을 보여준다.

예를 들어 다음 질문은 함수 하나만 봐서는 답하기 어렵다.

- 등록 정보는 무엇을 기억하는가?
- INVITE 타임아웃은 어디에 저장되는가?
- ACK 이후 확정 통화는 어디에 남는가?
- 구독자 transport는 어디에 보존되는가?
- cleanup은 무엇을 기준으로 삭제하는가?

이 질문들은 모두 상태 구조를 읽어야 답할 수 있다.

## 6.3 `Registration`

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L131)의 `Registration`은 registrar 역할의 핵심이다.

필드의 의미를 정리하면 다음과 같다.

- `aor`: 논리 주소
- `contact`: 단말이 제시한 도달 주소
- `ip`, `port`: 실제 수신 source 주소
- `transport`: UDP/TCP/TLS
- `authPassword`: REGISTER Digest 검증용 값
- `expiresAt`: 바인딩 만료 시각
- `loggedIn`: 실제 REGISTER로 로그인했는지
- `isStatic`: XML로 사전 등록된 항목인지

### 왜 `contact`만 저장하지 않는가

이 질문은 중요하다.

`contact`만 저장하면 NAT 환경이나 transport-aware 라우팅에서 부족하다. 그래서 실제 구현은 `ip`, `port`, `transport`를 별도로 보관한다. 이는 "단말이 자기 주소라고 주장한 값"과 "서버가 실제로 본 네트워크 경로"를 분리하려는 설계다.

### `isStatic`의 의미

정적 등록은 동적 REGISTER와 다르게 cleanup 시 삭제하지 않고, 로그인 상태만 해제할 수 있다. 이 차이는 개발 환경과 실제 등록 흐름을 공존시키기 위한 실용적 선택이다.

## 6.4 등록 저장소 `regs_`

등록 저장소는 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L1094) 부근의 `regs_`에 있다.

```cpp
mutable std::mutex regMutex_;
std::map<std::string, Registration> regs_;
```

즉 등록 저장소는 AoR 문자열을 key로 하는 map이다. 다만 조회 시에는 단순 문자열 비교만 쓰지 않고 AoR 정규화 도우미를 사용한다.

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L1099)의 `findByUser_()`와 `extractAorKeyFromUri()` 경로를 보면, 현재 프로젝트는 `user@domain` 단위 조회를 상당히 중시한다.

이는 단순히 `1001` 사용자만 보는 구현에서 벗어나 multi-domain을 의식한 확장이다.

## 6.5 `ActiveCall`

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L301)의 `ActiveCall`은 "통화가 실제로 진행 중이거나 진행 중으로 간주되는 상태"를 담는다.

중요 필드:

- `callId`
- `fromUri`, `toUri`
- `fromTag`, `toTag`
- caller/callee 각각의 IP, port, transport
- `startTime`
- `confirmed`
- `byeReceived`
- 마지막 SDP 정보

이 구조는 단순 다이얼로그 식별을 넘어서 "실제 미디어 교환 맥락" 일부까지 간접적으로 기억한다. 특히 SDP body를 pass-through로 보관하는 점이 그렇다.

### `confirmed`

이 플래그는 매우 중요하다.

- `false`면 아직 완전히 성립되지 않은 통화일 수 있다.
- `true`면 ACK 이후 확정된 통화다.

cleanup 시나리오와 BYE 처리 모두 이 값에 영향을 받는다.

## 6.6 `Dialog`

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L325)의 `Dialog`는 `ActiveCall`과 유사해 보이지만 역할이 다르다.

`Dialog`는 SIP dialog routing에 더 가깝다.

중요 필드:

- `callId`
- caller/callee tag
- 각 측 transport 주소
- `cseq`
- `confirmed`
- `remoteTarget`
- `callerContact`
- 생성 시각

### 왜 `ActiveCall`과 `Dialog`를 둘 다 두는가

실용적으로 보면:

- `ActiveCall`은 통화 상태 관점
- `Dialog`는 SIP in-dialog routing 관점

으로 분화된 흔적이다.

엄밀한 이론상 완전히 다른 개념이라고만 보기보다는, 현재 구현에서는 둘이 일부 중복 정보를 가지며 서로 다른 처리 경로에서 편의상 쓰이는 구조라고 이해하는 편이 현실적이다.

## 6.7 `PendingInvite`

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L1119)의 `PendingInvite`는 stateful proxy 구현의 핵심이다.

주요 필드:

- caller/callee 주소와 transport
- `origRequest`
- `callerRequest`
- `callerContact`
- `lastResponse`
- `state`
- `attempts`
- `ts`
- `expiry`
- `timerCExpiry`

### 이 구조가 중요한 이유

INVITE는 한 번 forward하고 끝나지 않는다. 이후 다음 이벤트를 처리해야 한다.

- provisional response
- final response
- ACK 생성
- CANCEL 생성
- Timer C timeout

이 모든 후속 처리의 문맥이 `PendingInvite` 안에 들어 있다.

### `origRequest`와 `callerRequest`를 둘 다 저장하는 이유

이 부분은 책에서 꼭 설명할 가치가 있다.

- `origRequest`: 프록시 Via가 추가된 실제 포워딩 버전
- `callerRequest`: caller가 보낸 원본

이 둘을 분리해야 ACK/CANCEL 생성과 caller용 응답 생성에서 각각 적절한 원본을 사용할 수 있다.

## 6.8 `Subscription`

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L654)의 `Subscription`은 RFC 6665 관련 상태 저장소다.

필드:

- `subscriberAor`
- `targetAor`
- `event`
- `callId`
- `fromTag`
- `toTag`
- `subscriberIp`, `subscriberPort`
- `subscriberTransport`
- `contact`
- `cseq`
- `expiresAt`
- `state`

### 왜 transport가 중요한가

이 프로젝트에서 subscription은 단순 논리 구독이 아니다. 실제 NOTIFY를 어디로 어떤 transport로 보낼지 알아야 한다. 그래서 subscriber transport가 별도 보존된다.

이 부분은 테스트로도 검증된다. subscription 만료 후 `terminated` NOTIFY가 subscriber의 TLS transport를 유지하는지 확인하는 코드가 [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L805)에 있다.

## 6.9 저장소와 mutex

`SipCore`는 상태 저장소마다 mutex를 분리한다.

주요 항목:

- `regMutex_` / `regs_`
- `authMutex_` / `registerNonces_`
- `callMutex_` / `activeCalls_`
- `pendingInvMutex_` / `pendingInvites_`
- `dlgMutex_` / `dialogs_`
- `subMutex_` / `subscriptions_`

이 구조는 coarse lock 하나로 전체를 막는 대신 상태 종류별로 보호 범위를 나누려는 설계다.

### 락 순서가 문서화되어 있는 이유

`cleanupStaleCalls()`나 `cleanupStaleTransactions()` 코드를 보면 "올바른 뮤텍스 순서" 주석이 있다. 이는 실제로 교착 상태를 한 번 이상 의식하며 보강한 코드라는 뜻이다.

책에서는 이를 "상태 모델이 커지면서 동시성 문제도 함께 등장했다"는 맥락에서 설명하면 좋다.

## 6.10 cleanup 함수가 말해주는 상태 수명

상태 모델은 생성 함수보다 cleanup 함수를 보면 더 잘 보일 때가 많다.

### registration 수명

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L375)의 `cleanupExpiredRegistrations()`는 정적 등록과 동적 등록의 수명을 다르게 처리한다.

### call 수명

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L410)의 `cleanupStaleCalls()`는 `confirmed`, `byeReceived`, 경과 시간 등을 기준으로 정리한다.

### transaction 수명

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L473)의 `cleanupStaleTransactions()`는 `COMPLETED` 상태와 비완료 상태를 다르게 다룬다.

### Timer C

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L535)의 `cleanupTimerC()`는 pending INVITE를 별도 RFC 개념으로 다룬다.

### subscription 수명

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L682)의 `cleanupExpiredSubscriptions()`는 단순 삭제가 아니라 종료 NOTIFY까지 포함한다.

즉 이 상태 모델은 단순 자료 저장이 아니라 "각 상태마다 별도 수명 규칙"을 갖는다.

## 6.11 로컬 transport 주소 모델

상태 모델에는 원격 peer 상태만 있는 것이 아니다. 서버 자신에 대한 transport별 주소 모델도 있다.

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L1167)의 `TransportLocalAddress`와 아래의 `udpLocal_`, `tcpLocal_`, `tlsLocal_`가 그것이다.

이 구조는 다음 이유로 중요하다.

- `Via` 생성
- `Record-Route` 생성
- `Contact` 생성

즉 이 데이터는 상태 모델이자 헤더 생성 모델이다.

## 6.12 통계 모델

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L800)의 `ServerStats`는 운영 관점에서 의미가 있다.

제공 값:

- 전체 등록 수
- 활성 등록 수
- 로그인된 등록 수
- 전체 통화 수
- 확정 통화 수
- pending 통화 수

책을 쓸 때는 이 구조를 바탕으로 "운영자가 어떤 상태를 관찰할 수 있는가"를 설명하는 장으로 확장할 수 있다.

## 6.13 테스트가 뒷받침하는 상태 모델

상태 모델의 의도는 테스트에서 더 선명하게 드러난다.

예를 들어:

- TLS 등록 후 `Registration.transport == TLS` 검증: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L654)
- full `user@domain` 기준 등록 조회 검증: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L672)
- cleanup 경로 검증: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L723), [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L751), [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L781)

이 테스트들은 상태 구조가 단순 설계 메모가 아니라 실제 동작 규칙으로 쓰이고 있음을 보여준다.

## 6.14 이 장의 핵심 정리

SIPLite의 상태 모델은 이 프로젝트를 "단순 메시지 포워더"와 구분해주는 핵심이다.

- `Registration`은 위치와 transport를 기억한다.
- `PendingInvite`는 stateful INVITE 흐름을 지탱한다.
- `ActiveCall`과 `Dialog`는 확정 통화와 in-dialog routing을 지탱한다.
- `Subscription`은 NOTIFY 경로를 기억한다.
- cleanup 함수는 각 상태의 수명을 통제한다.

다음 장에서는 이러한 구조가 테스트에서 어떻게 검증되고 있는지 본다.
