# 12. SUBSCRIBE / NOTIFY 흐름

## 12.1 이 장의 목적

SIPLite는 단순 call control 서버를 넘어서 subscription 이벤트 흐름도 다룬다. 현재 구현은 RFC 6665 전체를 완벽히 포괄하는 거대한 프레임워크는 아니지만, 핵심 상태 저장과 NOTIFY 전달 흐름은 실제 코드로 들어 있다.

관련 코드:

- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1712) `handleSubscribe()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1924) `handleNotify()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2008) `buildNotify()`
- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L654) `Subscription`
- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L682) `cleanupExpiredSubscriptions()`
- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L755) `notifySubscribers()`

## 12.2 `Subscription` 상태 구조

subscription의 핵심 저장 구조는 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L654)에 있다.

중요 필드:

- `subscriberAor`
- `targetAor`
- `event`
- `callId`
- `fromTag`, `toTag`
- `subscriberIp`, `subscriberPort`
- `subscriberTransport`
- `contact`
- `cseq`
- `expiresAt`
- `state`

이 구조를 보면 이 프로젝트의 subscription은 단순 논리 구독이 아니라, 실제 subscriber에게 NOTIFY를 보내기 위한 네트워크 상태까지 포함한다.

## 12.3 SUBSCRIBE의 기본 흐름

`handleSubscribe()`의 큰 흐름은 다음과 같다.

1. 필수 헤더 확인
2. `Event` 헤더 확인
3. 지원 이벤트 패키지인지 검사
4. `Expires` 해석
5. `From`/`To` URI, tag, Contact 추출
6. `Expires: 0`이면 구독 해지
7. 아니면 신규 구독 생성 또는 refresh
8. `200 OK` 반환
9. initial NOTIFY 전송

즉 SUBSCRIBE는 단순 "구독 등록" 하나로 끝나지 않고, 즉시 NOTIFY까지 연결되는 흐름이다.

## 12.4 지원 이벤트 패키지

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1735) 이후를 보면 현재 지원 패키지는 다음으로 제한된다.

- `presence`
- `dialog`
- `message-summary`

지원되지 않는 이벤트는 `489 Bad Event`를 반환한다.

이 설계는 보수적이지만 합리적이다. 구현하지 않은 이벤트를 묵인하지 않고 명시적으로 거절한다.

## 12.5 `Expires`와 수명

SUBSCRIBE의 수명은 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1751) 이후에서 처리된다.

특징:

- 기본값 사용 가능
- 숫자가 아니면 `400 Bad Request - Invalid Expires`
- 최대값 clamp
- `0`이면 unsubscribe

즉 REGISTER와 비슷한 lease 개념이지만, subscription 전용 상수와 상태 모델을 쓴다.

## 12.6 unsubscribe (`Expires: 0`)

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1787) 이후는 구독 해지 경로다.

동작:

- subscription lookup
- 있으면 state를 `TERMINATED`
- `terminated;reason=deactivated` NOTIFY 생성
- subscription 삭제
- subscriber에게 NOTIFY 전송
- `Expires: 0`이 포함된 `200 OK` 응답

이 구현은 해지를 조용히 처리하지 않고 명시적 종료 통지까지 포함한다.

## 12.7 신규 구독과 refresh

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1832) 이후에서 두 경우를 구분한다.

### 기존 subscription 존재

- IP/port 갱신
- transport 갱신
- Contact 갱신
- expires 갱신
- `cseq` 갱신
- `ACTIVE` 유지

### 신규 subscription

- `Subscription` 구조 생성
- `toTag` 생성
- subscriber transport 저장
- `subscriptions_[callId]`에 저장

이 흐름은 subscription이 stateless request가 아니라 refresh 가능한 장기 상태임을 잘 보여준다.

## 12.8 initial NOTIFY

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1906) 이후에서 SUBSCRIBE 성공 직후 initial NOTIFY를 보낸다.

이 점은 중요하다. RFC 6665 관점에서도 SUBSCRIBE는 즉시 NOTIFY를 동반하는 것이 핵심이다.

여기서 현재 구현의 의미는 다음과 같다.

- 서버는 단지 구독을 저장만 하지 않는다.
- 구독 수락 직후 상태 전달을 시도한다.
- subscriber가 기대하는 notifier 행동을 최소한 기본 경로에서 만족시킨다.

## 12.9 NOTIFY 생성

NOTIFY 생성은 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2008)의 `buildNotify()`와 `buildNotifyUnlocked_()`가 담당한다.

생성 요소:

- Request-Line `NOTIFY <targetUri> SIP/2.0`
- `Via`
- `From`
- `To`
- `Call-ID`
- `CSeq`
- `Event`
- `Subscription-State`
- `Content-Type`
- `Content-Length`

### 눈여겨볼 점

현재 `buildNotifyUnlocked_()`는 `Via: SIP/2.0/UDP ...`를 고정 생성한다. subscriber transport는 실제 전송 채널 선택에는 반영되지만, 생성되는 NOTIFY의 top Via는 아직 transport-aware가 아니다.

즉 문서에는 이 점을 현재 한계 또는 향후 개선 주제로 남겨두는 것이 정확하다.

## 12.10 NOTIFY 처리

NOTIFY 수신은 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1924)의 `handleNotify()`가 담당한다.

흐름:

1. 필수 헤더 확인
2. `Event` 존재 확인
3. `Subscription-State` 존재 확인
4. 해당 subscription 존재 확인
5. `terminated`면 subscription 제거
6. notifier가 subscriber와 다른 노드면 subscriber에게 포워딩
7. `200 OK` 반환

즉 `handleNotify()`는 서버 자체 notifier 역할도 할 수 있고, 외부 notifier에서 온 NOTIFY를 subscriber에게 전달하는 프록시 역할도 한다.

## 12.11 subscriber transport 유지

현재 구현의 중요한 강점은 subscriber transport를 상태에 저장하고, 실제 전송 시 그 transport를 유지한다는 점이다.

예를 들어:

- `cleanupExpiredSubscriptions()`는 subscriber transport로 terminated NOTIFY를 보냄
- `notifySubscribers()`도 subscriber transport를 유지
- `handleNotify()` 포워딩도 subscriber transport를 사용

테스트 근거:

- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L805)

이 점은 TLS subscription 환경에서 특히 중요하다.

## 12.12 만료 cleanup

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L682)의 `cleanupExpiredSubscriptions()`는 subscription 수명 관리를 담당한다.

동작:

- 만료된 subscription 탐색
- `terminated;reason=timeout` NOTIFY 생성
- subscription 삭제
- subscriber transport로 전송

즉 subscription도 REGISTER처럼 시간이 흐르면 정리된다. 단, REGISTER보다 한 단계 더 나아가 종료 이벤트 통지까지 수행한다.

## 12.13 `notifySubscribers()`

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L755)의 `notifySubscribers()`는 특정 AoR 상태 변경 시 모든 구독자에게 NOTIFY를 보낼 수 있게 한다.

이 함수의 의미는 크다.

- subscription 저장소를 단순 수동 데이터로 두지 않는다.
- 서버 내부 이벤트를 구독자에게 fan-out할 수 있다.
- 향후 presence state engine으로 확장할 수 있는 구조적 출발점이 된다.

## 12.14 관련 테스트

중요 테스트:

- subscription 만료 transport 유지: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L805)
- NOTIFY with existing subscription: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L2484)
- NOTIFY without subscription → 481: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L2537)
- NOTIFY missing Event → 489: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L2569)
- NOTIFY missing Subscription-State → 400: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L2596)
- NOTIFY terminated removes subscription: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L2634)
- `notifySubscribers()` fan-out: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L2678)

즉 subscription 흐름도 현재 코드에서 비교적 폭넓게 회귀 검증되고 있다.

## 12.15 현재 한계와 관찰 포인트

현재 구조는 충분히 의미 있지만, 책에는 다음도 같이 적어두는 편이 좋다.

- `buildNotify()`의 `Via`는 아직 UDP 고정
- notifier role과 proxy role이 한 코드 안에 섞여 있다
- event package별 body 생성은 아직 제한적이다
- RFC 6665 전체 범위를 포괄하는 거대한 프레임워크는 아니다

이 점을 분명히 적어두면 과장 없는 설명이 된다.

## 12.16 이 장의 핵심 정리

SIPLite의 SUBSCRIBE/NOTIFY는 부가 기능이 아니라 실제 상태 모델을 가진 구현이다.

- subscription 저장
- refresh
- unsubscribe
- initial NOTIFY
- terminated NOTIFY
- subscriber transport 유지

까지 포함한다.

다음 장에서는 별도로 분리할 가치가 큰 주제인 Digest 인증이나 XML 설정, 운영 흐름으로 확장할 수 있다.
