# 18. 코드 읽기 가이드

## 18.1 이 장의 목적

이 책은 코드 설명서이기도 하다. 따라서 독자가 실제 코드로 들어갈 때 어디서부터 어떻게 읽어야 하는지 가이드가 필요하다.

SIPLite는 파일 수가 매우 많은 프로젝트는 아니지만, 개념적으로는 transport, parser, core, state, config, tests가 나뉘어 있어 처음 읽을 때 길을 잃기 쉽다.

이 장은 그 문제를 줄이기 위한 실전 독해 순서를 제공한다.

## 18.2 가장 먼저 볼 파일

가장 먼저 읽을 파일은 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)다.

이유:

- 시스템이 어떻게 조립되는지 보여준다.
- `UdpServer`, `TcpServer`, `TlsServer`, `ConsoleInterface`가 어떻게 연결되는지 나온다.
- `SipCore::setSender()`와 cleanup 루프가 드러난다.

즉 `main.cpp`를 먼저 읽지 않으면, 나머지 클래스들이 서로 어떤 관계인지 맥락 없이 보게 된다.

## 18.3 그 다음은 `UdpPacket.h`

[include/UdpPacket.h](/home/windmorning/projects/SIPWorks/SIPLite/include/UdpPacket.h)를 바로 읽는 것을 권한다.

여기서 중요한 개념은 하나다.

- `TransportType`

이 프로젝트는 transport-aware 구조이므로, 이 enum을 일찍 이해하지 않으면 이후 TLS/TCP/UDP 경로를 계속 혼동하게 된다.

## 18.4 `SipCore.h`를 먼저 보고 `SipCore.cpp`로 들어가기

코드 읽기에서 자주 하는 실수는 `.cpp`부터 보는 것이다. SIPLite에서는 먼저 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)를 훑는 편이 훨씬 낫다.

왜냐하면 여기서 다음을 한 번에 볼 수 있기 때문이다.

- `Registration`
- `ActiveCall`
- `Dialog`
- `PendingInvite`
- `Subscription`
- `SenderFn`
- cleanup 함수

즉 header만 읽어도 이 클래스가 무엇을 기억하고 어떤 공개 기능을 제공하는지 큰 그림이 잡힌다.

그 다음에 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)로 들어가야 구현이 덜 산만하게 느껴진다.

## 18.5 `SipCore.cpp`는 한 번에 다 읽지 말 것

`SipCore.cpp`는 길고 책임이 많다. 한 번에 처음부터 끝까지 읽으면 정보량이 너무 많다. 아래 순서를 추천한다.

### 1단계: 진입과 공통 검증

- `handlePacket()`
- `handleResponse()`

### 2단계: 위치 등록

- `handleRegister()`
- `buildRegisterOk()`
- `buildRegisterAuthChallenge()`

### 3단계: 통화 시작

- `handleInvite()`
- `addProxyVia()`
- `addRecordRoute()`
- `rewriteRequestUri()`

### 4단계: 통화 확정/종료

- `handleAck()`
- `handleBye()`
- `handleCancel()`
- `buildAckForPending()`
- `buildCancelForPending()`

### 5단계: 메시지와 구독

- `handleMessage()`
- `handleSubscribe()`
- `handleNotify()`
- `buildNotify()`

### 6단계: 시간 기반 정리

- `cleanupTimerC()`
- `cleanupExpiredRegistrations()`
- `cleanupExpiredSubscriptions()`
- `cleanupStaleCalls()`
- `cleanupStaleTransactions()`

이 순서로 읽으면 코어를 "기능군" 단위로 이해할 수 있다.

## 18.6 transport 서버 읽기 순서

transport 서버는 다음 순서가 좋다.

1. [src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp)
2. [src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp)
3. [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)

이 순서를 권하는 이유:

- UDP가 가장 단순하다.
- TCP는 UDP에 스트림 처리와 연결 관리가 추가된 형태다.
- TLS는 TCP에 보안 계층이 더해진 형태다.

즉 난이도가 점점 올라간다.

## 18.7 parser는 언제 읽는가

파서는 너무 일찍 읽으면 전체 구조 감각 없이 세부 문법에 빠질 수 있다. 따라서 [src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp)는 `SipCore` 흐름을 한 번 보고 나서 읽는 편이 좋다.

읽을 때 집중할 포인트:

- request / response 구분
- compact header 확장
- header continuation
- `Content-Length` 검증
- 크기 제한

즉 파서는 "메시지의 문법 계층"으로 읽어야 한다.

## 18.8 XML 로더는 언제 읽는가

[include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)는 REGISTER와 초기화 구조를 어느 정도 이해한 뒤 읽는 것이 좋다.

먼저 REGISTER를 이해하지 않고 XML 로더를 보면 `<aor>`, `<contact>`, `<transport>`, `<password>`의 의미가 피상적으로만 보일 수 있다.

추천 시점:

- `main.cpp`
- `SipCore`
- 이후 `XmlConfigLoader.h`

## 18.9 테스트는 마지막이 아니라 중간중간 읽기

테스트는 프로젝트 끝에 참고용으로 읽는 것이 아니라, 각 기능군을 읽은 직후 확인하는 편이 훨씬 효과적이다.

예시:

- REGISTER를 읽은 뒤 [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp)
- INVITE를 읽은 뒤 [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp)
- XML 로더를 읽은 뒤 [tests/test_xmlconfig.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_xmlconfig.cpp)

이렇게 해야 코드의 의도와 검증 범위를 바로 연결할 수 있다.

## 18.10 리딩 목표별 권장 경로

### 목표 1: 전체 구조 빨리 파악

1. `main.cpp`
2. `UdpPacket.h`
3. `SipCore.h`
4. `README`와 `docs/book`

### 목표 2: 통화 흐름 이해

1. `handleInvite()`
2. `handleResponse()`
3. `handleAck()`
4. `handleBye()`
5. `handleCancel()`
6. 관련 테스트

### 목표 3: TLS 이해

1. `main.cpp`의 TLS 시작 부분
2. `TlsServer.cpp`
3. `SipCore`의 transport-aware 헤더 생성 함수
4. TLS 관련 테스트

### 목표 4: 설정과 운영 이해

1. `XmlConfigLoader.h`
2. `ConsoleInterface.*`
3. `Logger.*`

## 18.11 코드를 읽을 때 자주 놓치는 포인트

### `UdpPacket` 이름에 속지 말 것

이 타입은 UDP만 위한 것이 아니다.

### `UdpServer`가 곧 중앙 코어 보유자임을 기억할 것

TCP와 TLS는 독립 코어가 아니라 `udpServer.sipCore()`를 공유한다.

### transport는 부가정보가 아니다

이 값은 실제 송신 경로와 SIP 헤더 모양을 결정한다.

### `PendingInvite`를 반드시 이해할 것

INVITE, 응답, ACK, CANCEL, Timer C를 연결하는 핵심 상태다.

### cleanup 함수를 건너뛰지 말 것

이 함수들을 봐야 상태 수명을 이해할 수 있다.

## 18.12 책과 코드를 병행해서 읽는 방법

가장 좋은 방법은 아래 패턴이다.

1. `docs/book`의 해당 장을 먼저 읽는다.
2. 거기서 언급한 코드 위치를 연다.
3. 같은 주제의 테스트를 확인한다.
4. 필요하면 시퀀스 다이어그램 장을 다시 본다.

예를 들어 INVITE를 이해하려면:

1. [10_invite_call_flow.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/10_invite_call_flow.md)
2. [17_sequence_diagrams.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/17_sequence_diagrams.md)
3. [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L900)
4. [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L132)

이 순서가 가장 효율적이다.

## 18.13 다음에 더 추가하면 좋은 자료

이 가이드를 더 강화하려면 다음 자료를 추가할 수 있다.

- 함수 호출 그래프
- 클래스 관계도
- transport별 상태 전이 표
- 실제 로그를 따라가는 디버깅 가이드

이 자료들이 붙으면 이 문서는 책을 넘어서 onboarding manual 역할도 할 수 있다.

## 18.14 이 장의 핵심 정리

SIPLite는 코드량 자체는 감당 가능한 수준이지만, 개념 밀도가 높다. 따라서 읽는 순서가 중요하다.

가장 추천하는 한 줄 요약 순서는 이렇다.

`main.cpp -> UdpPacket.h -> SipCore.h -> SipCore.cpp 기능군별 -> transport 서버 -> parser -> XML/console -> tests`

이 순서를 지키면 이 프로젝트는 생각보다 훨씬 빠르게 구조가 잡힌다.
