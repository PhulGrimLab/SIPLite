# 8. 남은 리스크와 다음 작업

## 8.1 왜 마지막 장에 리스크를 남겨야 하는가

코드 분석서나 기술서는 구현된 내용만 적으면 읽는 사람에게 잘못된 확신을 준다. 특히 SIP 같은 프로토콜 서버는 "코드가 있다"와 "운영에서 충분히 검증됐다" 사이의 간격이 크다.

따라서 마지막 장은 요약이 아니라 경계선 정리 역할을 해야 한다.

- 무엇이 구현되었는가
- 무엇이 아직 약한가
- 무엇을 다음 집필 대상으로 삼을 것인가

이 세 가지를 분명히 남겨야 다음 독자나 다음 작성자가 문서를 이어받기 쉽다.

## 8.2 현재 코드의 강한 지점

먼저 강점을 정리해 두는 것이 좋다.

### 1. 구조가 완전히 뒤엉키지는 않았다

transport 서버와 `SipCore`가 분리되어 있고, `setSender()`로 접점을 만드는 구조는 설명 가능하고 유지보수 가능한 편이다.

### 2. TLS가 실제 구현이다

문서용 장식이 아니라 OpenSSL과 transport-aware routing이 실제로 코드에 들어 있다.

### 3. 상태 모델이 꽤 성숙했다

Registration, PendingInvite, ActiveCall, Dialog, Subscription, cleanup 함수까지 갖추고 있어 단순 toy project 수준을 넘어선다.

### 4. 테스트가 있다

특히 extended test가 존재해 최근 변경 의도를 추적하기 쉽다.

이 네 가지는 책을 쓰는 입장에서 상당한 장점이다. 단순 소스 나열이 아니라 구조적 설명이 가능하기 때문이다.

## 8.3 현재 코드의 눈에 띄는 리스크

다음 항목들은 문서에 명시적으로 남겨둘 가치가 있다.

### 1. 코드 중복

TCP와 TLS 서버는 구조가 매우 비슷하다. 이벤트 루프, 연결 관리, SIP message extraction, worker 분배 로직에 상당한 중복이 있을 가능성이 높다.

이 중복은 당장 버그를 뜻하지는 않지만, 다음 문제를 만든다.

- 수정이 한쪽만 반영될 위험
- transport 간 미세한 동작 차이 발생
- 테스트 비용 증가

장기적으로는 공통 connection-oriented base 계층으로 추출할 여지가 있다.

### 2. 이름과 역할의 어긋남

`UdpPacket`은 실제로 UDP 전용이 아니고, `UdpServer`는 사실상 중앙 `SipCore`의 보유자 역할까지 한다. 이 이름 충돌은 처음 읽는 독자에게 혼란을 준다.

책에서는 이 점을 미리 밝혀주면 되지만, 코드 자체는 장기적으로 이름 정리가 도움이 될 수 있다.

### 3. `SipCore`의 규모 증가

현재 `SipCore`는 너무 많은 책임을 갖고 있다.

- 검증
- 라우팅
- 헤더 재작성
- 상태 저장
- 타이머 정리
- Digest 인증
- subscription 처리

이 정도면 이미 "하나의 클래스"라기보다 여러 하위 모듈의 집합에 가깝다. 지금은 읽을 수 있지만, 계속 기능이 늘면 분해가 필요해질 가능성이 높다.

### 4. 운영 검증과 코드 존재는 다르다

TLS, dialog, subscription, cleanup이 코드상 존재하더라도 실제 SIP UA와의 상호운용성은 별도 문제다.

예를 들어 다음은 코드만으로 보장되지 않는다.

- 다양한 SIP 클라이언트와의 실제 REGISTER/INVITE/ACK/BYE 호환성
- TLS peer 검증 정책의 운영 적합성
- 장시간 연결 유지 시 안정성
- NAT 환경에서의 실전 동작

즉 이 분석서는 "현재 코드 이해"에는 강하지만, "현장 검증 완료 선언"으로 읽혀서는 안 된다.

## 8.4 TLS 관련 후속 검토 항목

TLS는 이미 구현되어 있지만, 책에는 다음 후속 주제를 별도 정리할 가치가 있다.

### 인증서 검증 정책

- IP 기반 검증이 어떤 범위까지 되는지
- DNS hostname verification이 어떤 형태로 보강되어야 하는지
- self-signed 개발 모드와 운영 모드를 어떻게 분리할지

### 연결 수명

- outbound TLS 연결 재사용 정책
- 실패 후 재연결 정책
- half-closed connection 처리
- peer disconnect 처리

### 상호운용성

- Linphone
- PJSIP 기반 UA
- SIPS URI 처리
- transport fallback 정책

이 항목들은 별도 장으로 확장할 수 있다.

## 8.5 `SipCore` 분해 후보

지금 당장 리팩터링하자는 뜻은 아니다. 다만 책의 마지막에 "이 클래스는 장기적으로 어떻게 분해될 수 있는가"를 적어두면 좋다.

가능한 분리 후보:

- `RegistrationService`
- `InviteProxyService`
- `DialogManager`
- `SubscriptionService`
- `DigestAuthService`
- `SipHeaderRewriter`
- `SipCleanupScheduler`

이 분해안은 구현 지시서가 아니라 독해 보조용 관점이다. 독자에게 "현재 한 파일에 모여 있지만 개념적으로는 이미 나뉘어 있다"는 점을 전달해 준다.

## 8.6 책 집필용 다음 장 후보

현재 `docs/book`은 구조 장 위주다. 실제 책으로 가려면 이후 장을 더 분화하는 것이 좋다.

권장 확장 순서:

1. `09_register_flow.md`
2. `10_invite_call_flow.md`
3. `11_bye_cancel_ack.md`
4. `12_subscribe_notify.md`
5. `13_digest_auth.md`
6. `14_xml_configuration.md`
7. `15_console_and_operations.md`
8. `16_packet_examples.md`

특히 `REGISTER`, `INVITE`, `TLS`, `Digest 인증`은 독립 장으로 분리할 가치가 충분하다.

## 8.7 실제 집필 방식 제안

책 품질을 높이려면 아래 방식이 좋다.

### 1. 개념 설명

먼저 SIP 개념을 설명한다.

### 2. 코드 위치 제시

그 개념이 코드 어디에 있는지 제시한다.

### 3. 시퀀스 설명

패킷이 어떤 순서로 흐르는지 설명한다.

### 4. 테스트 근거 제시

어떤 테스트가 이 동작을 검증하는지 적는다.

### 5. 한계 적시

현재 코드가 어디까지고 어디부터가 과제인지 적는다.

이 패턴을 모든 장에 반복 적용하면 문서 품질이 일정해진다.

## 8.8 다음 분석 작업 제안

책 집필과 별개로, 코드 분석 자체를 더 깊게 하려면 아래 작업이 효과적이다.

### 함수 호출 그래프 작성

- `main -> server -> SipCore`
- `INVITE -> pending -> response -> ACK`
- `SUBSCRIBE -> notify -> cleanup`

### 상태 관계도 작성

- Registration
- ActiveCall
- Dialog
- PendingInvite
- Subscription

### 패킷 예제 수집

- 실제 REGISTER 예제
- INVITE / 180 / 200 / ACK 예제
- TLS `Via` / `Record-Route` 예제
- terminated NOTIFY 예제

### 실제 로그 기반 보정

`logs/` 디렉터리와 테스트 출력을 이용해 문장을 실제 실행 결과에 맞춰 다듬을 수 있다.

## 8.9 이 장의 핵심 정리

SIPLite는 충분히 책으로 남길 가치가 있는 프로젝트다. 이유는 단순하다.

- 구조가 설명 가능하고
- 상태 모델이 분명하며
- TLS까지 실제로 구현되어 있고
- 테스트가 뒷받침되기 때문이다

동시에 이 코드는 아직 "계속 살아 있는 작업물"이기도 하다.

- 구조 중복이 있고
- `SipCore`가 비대해지고 있으며
- 운영 검증은 계속 필요하다

이 마지막 장은 그래서 비판이 아니라 경계 설정이다. 현재 코드를 정확히 이해하고, 다음 집필과 다음 개선을 어디서 시작할지 정해 주는 역할을 한다.
