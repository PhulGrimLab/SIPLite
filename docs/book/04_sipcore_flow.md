# 4. SipCore 중심 흐름

## 4.1 왜 `SipCore`를 따로 장으로 다뤄야 하는가

`SipCore`는 이 프로젝트의 가장 중요한 클래스다. `main.cpp`가 시스템을 조립하고 각 transport 서버가 네트워크를 담당한다면, `SipCore`는 실제 SIP 의미 처리와 상태 전이를 담당한다.

코드 기준으로 보면 `SipCore`는 다음 두 파일에 걸쳐 있다.

- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)

이 장에서는 `SipCore`를 "메서드 모음"이 아니라 "SIP 상태 머신의 중심"으로 읽는다.

## 4.2 진입점: `handlePacket()`

요청의 일반 진입점은 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L174)의 `SipCore::handlePacket()`이다.

이 함수는 크게 보면 다음 순서로 동작한다.

1. 요청인지 확인
2. 필수 SIP 헤더 검증
3. `Max-Forwards` 검증
4. `Content-Length` 검증
5. `Require` 등 추가 제약 검증
6. 메서드명을 보고 세부 핸들러로 분기

즉 `handlePacket()`은 단순 dispatcher가 아니라, 세부 처리 전에 공통 RFC 수준 검증을 담당하는 정문 역할을 한다.

## 4.3 요청 검증의 의미

`handlePacket()` 초반부의 검증은 이 프로젝트가 단순 "문자열 중계기"가 아님을 보여준다.

### 필수 헤더 검증

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L185) 이후에서 `Via`, `From`, `To`, `Call-ID`, `CSeq`가 모두 있는지 확인한다. 없으면 `400 Bad Request`를 돌려준다.

### `Max-Forwards`

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L203) 이후에서 `Max-Forwards` 값을 검사하고, 0이면 `483 Too Many Hops`를 반환한다.

### `Content-Length`

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L230) 이후에서 헤더 값과 실제 body 길이가 맞는지 재검증한다. 파서 단계에서도 검증하지만, 코어 단계에서 방어를 한 번 더 하는 셈이다.

이런 중복 방어는 책에서 "실용적인 방어 설계"로 설명할 수 있다.

## 4.4 핵심 데이터 구조

`SipCore`가 흥미로운 이유는 단순히 메서드 핸들러가 많아서가 아니라, 상태 구조체가 꽤 풍부하기 때문이다.

대표 구조는 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)에 있다.

### `Registration`

- AoR
- Contact
- 실제 source IP/port
- transport
- 인증 비밀번호
- expiresAt
- loggedIn
- isStatic

### `ActiveCall`

- callId
- caller / callee 주소와 태그
- caller / callee IP, port, transport
- startTime
- confirmed
- BYE 관련 상태
- 마지막 SDP

### `Dialog`

- callId
- caller/callee tag
- 각 측 주소와 transport
- remote target
- callerContact
- cseq
- confirmed 여부

### `PendingInvite`

- caller / callee 주소와 transport
- 원본 요청과 포워딩된 요청
- 마지막 응답
- 상태
- expiry
- timerCExpiry

### `Subscription`

- subscriberAor
- targetAor
- event
- callId
- subscriber 주소와 transport
- expiresAt
- state

이 구조들만 봐도 프로젝트가 "몇 가지 메서드만 처리하는 샘플"을 넘어 실제 상태를 유지하는 SIP 서버라는 점이 드러난다.

## 4.5 `setSender()`와 `SipCore`의 역할 분리

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L223)의 `SenderFn`은 `SipCore`의 핵심 설계 포인트다.

```cpp
using SenderFn = std::function<bool(const std::string&, uint16_t, const std::string&, TransportType)>;
```

이 설계의 의미는 다음과 같다.

- `SipCore`는 네트워크 API를 몰라도 된다.
- `SipCore`는 "어디로, 무엇을, 어떤 transport로" 보낼지만 결정한다.
- 실제 전송은 외부에서 주입된다.

이 분리는 테스트에도 유리하다. 실제로 테스트에서는 sender를 가짜 함수로 주입해 전송 결과를 캡처한다.

## 4.6 등록 흐름

REGISTER 처리의 세부 구현은 `handleRegister()`에 있지만, 책에서는 먼저 개념 흐름을 잡아주는 것이 좋다.

등록 흐름은 대략 다음과 같다.

1. REGISTER 요청 수신
2. 필요 시 Digest 인증 검사
3. AoR와 Contact 추출
4. 실제 source IP/port 저장
5. 만료 시간 계산
6. `Registration` 저장 또는 갱신
7. `200 OK` 또는 `401 Unauthorized` 반환
8. 필요하면 구독자에게 등록 상태 NOTIFY

이때 중요한 점은 단순히 `Contact`만 저장하지 않는다는 것이다. 실제 수신 `ip`, `port`, `transport`도 함께 저장한다. NAT, TCP/TLS 연결 유지, transport-aware 라우팅을 위해 필수적이다.

## 4.7 INVITE 흐름

INVITE는 이 프로젝트에서 가장 복잡한 흐름 중 하나다.

대략 순서는 다음과 같다.

1. 목적 AoR로 등록 정보 검색
2. caller에게 provisional 응답 전송 가능
3. 원본 요청에 프록시 `Via` 추가
4. `Record-Route` 추가
5. `Max-Forwards` 감소
6. Request-URI를 실제 Contact 기준으로 재작성
7. `PendingInvite`, `ActiveCall`, `Dialog` 일부 상태 생성
8. 상대 단말로 포워딩
9. 이후 응답은 `handleResponse()`에서 caller에게 역전달

이 과정은 `SipCore`가 proxy 역할을 강하게 띤다는 점을 보여준다.

## 4.8 응답 흐름

응답은 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L297)의 `handleResponse()`가 처리한다.

핵심 개념은 다음과 같다.

- callee에서 온 응답을 pending INVITE에 매칭
- 프록시가 추가한 top `Via` 제거
- caller에게 응답 전달
- provisional 응답이면 Timer C 연장
- final 응답이면 상태를 COMPLETED로 전이하거나 dialog를 확정
- 2xx 이후 ACK 흐름 처리

즉 이 함수는 "응답 포워딩" 이상의 역할을 한다. 트랜잭션 수명과 dialog 수명을 함께 관리한다.

## 4.9 ACK, BYE, CANCEL

세 메서드는 모두 dialog/call 상태와 강하게 묶인다.

### ACK

- pending INVITE나 확정 dialog와 연동
- in-dialog routing에 필요
- confirmed 상태 전이에 관여

### BYE

- 누가 BYE를 보냈는지 판단
- 반대편으로 중계
- active call / dialog 정리 조건에 영향

### CANCEL

- 아직 최종 응답이 오지 않은 INVITE를 취소
- 원본 INVITE와 동일 transaction key를 맞춰야 함
- 경우에 따라 INVITE보다 먼저 도착하는 상황도 고려

이 세 메서드는 stateful proxy 성격이 강한 부분이다.

## 4.10 MESSAGE, SUBSCRIBE, NOTIFY

이 프로젝트는 단순 call control만 하는 것이 아니라 MESSAGE와 subscription 계열도 처리한다.

### MESSAGE

- 목적 단말 등록 조회
- 적절한 transport로 포워딩
- 응답 중계

### SUBSCRIBE

- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L654)의 `Subscription` 상태 저장
- `Event`, `Expires`, `Contact` 등 해석
- subscriber의 transport 저장
- 초기 NOTIFY 전송
- `200 OK` 반환

### NOTIFY

- 구독자 방향으로 전달
- `Subscription-State`와 `Event`를 바탕으로 처리
- 필요 시 transport 유지

이 구현은 이 프로젝트가 단순 호 설정 서버를 넘어서 presence/event routing 성격도 일부 가진다는 뜻이다.

## 4.11 Timer C와 cleanup

`SipCore`에는 "시간이 흐르며 상태를 정리하는 함수"가 다수 있다. 이것이 이 클래스를 단순 request handler가 아니라 state manager로 보게 만드는 이유다.

### `cleanupTimerC()`

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L535)에 구현돼 있다.

이 함수는 다음을 한다.

- 오래된 pending INVITE 탐색
- caller에게 `408 Request Timeout`
- callee에게 `CANCEL`
- 관련 `ActiveCall`, `Dialog`, `PendingInvite` 제거

특히 transport 정보까지 저장하고 있어 caller/callee 각각 원래 transport로 응답과 CANCEL을 보낼 수 있다.

### `cleanupExpiredRegistrations()`

- 만료된 registration 정리
- 정적 등록은 삭제하지 않고 `loggedIn`만 해제

### `cleanupExpiredSubscriptions()`

- 만료된 subscription 정리
- `terminated;reason=timeout` NOTIFY 전송
- subscriber transport 유지

### `cleanupStaleCalls()`

- 오래된 미확립 통화 제거
- BYE 이후 정리 대상 제거

### `cleanupStaleTransactions()`

- 오래 남은 pending transaction 제거
- 연결된 call/dialog 상태도 함께 정리

이 함수 집합은 운영 서버의 수명 관리 계층으로 이해해야 한다.

## 4.12 transport-aware 헤더 생성

`SipCore`는 메시지를 단순 포워딩만 하지 않고 여러 SIP 헤더를 재작성한다.

핵심 함수:

- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2223) `addProxyVia()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2295) `addRecordRoute()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2342) `stripOwnRoute()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2653) `buildLocalContactHeader()`

이 함수들이 중요한 이유는 transport에 따라 생성되는 헤더가 달라지기 때문이다.

예를 들어:

- UDP면 `Via: SIP/2.0/UDP`
- TCP면 `Via: SIP/2.0/TCP`
- TLS면 `Via: SIP/2.0/TLS`

또한 TLS는 `Record-Route: <sips:...>`를 사용한다.

즉 `SipCore`는 application logic만 처리하는 것이 아니라 SIP header semantics도 transport별로 책임진다.

## 4.13 파서와의 관계

`SipCore`는 파서를 전적으로 신뢰하지 않는다. 이 점도 중요하다.

[src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp)에서 이미 많은 검증을 수행하지만, `SipCore::handlePacket()`은 다시 필수 헤더와 `Content-Length`, `Max-Forwards` 등을 확인한다.

이 중복은 설계상 낭비라기보다 방어 계층으로 읽는 편이 맞다.

## 4.14 테스트가 보여주는 구현 의도

[tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp)는 이 코어가 무엇을 보장하려는지 보여준다.

대표 예시:

- TLS registration 후 INVITE가 TLS로 전달되는지 검증: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L638)
- full AoR 기준 라우팅 검증: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L672)
- subscription 만료 시 TLS transport 유지 검증: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L805)

이 테스트들은 `SipCore`가 현재 단순 기능 구현을 넘어서 transport-aware state machine으로 진화했음을 보여준다.

## 4.15 이 장의 핵심 정리

`SipCore`는 이 프로젝트의 엔진이다.

- 요청을 검증하고
- 상태를 저장하며
- 적절한 헤더를 생성하고
- transport를 선택하고
- 시간 흐름에 따라 상태를 정리한다

즉 이 프로젝트를 이해한다는 것은 결국 `SipCore`를 이해하는 것이다.

다음 장에서는 이 `SipCore`가 TLS와 만날 때 정확히 어떤 일이 벌어지는지 더 집중해서 본다.
