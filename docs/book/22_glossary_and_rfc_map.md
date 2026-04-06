# 22장. 용어집과 RFC 관점 정리

이 장은 앞선 장들에서 반복적으로 등장한 SIP 용어를 정리하고, 현재 구현이 RFC 관점에서 어디에 걸쳐 있는지 큰 지도를 제공한다. 목적은 두 가지다.

1. 독자가 코드 용어와 프로토콜 용어를 혼동하지 않게 한다.
2. 구현 범위와 미완성 범위를 RFC 문맥에서 설명한다.

기준이 되는 코드는 다음 파일들이다.

- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)
- [src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp)
- [include/UdpPacket.h](/home/windmorning/projects/SIPWorks/SIPLite/include/UdpPacket.h)
- [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)

## 22.1 SIPLite 문맥에서 자주 나오는 핵심 용어

### User Agent

SIP에서 요청을 보내거나 응답을 받는 단말 측 개체를 뜻한다. 이 프로젝트에서는 XML에 정의된 단말, 실제 네트워크에서 REGISTER/INVITE를 보내는 클라이언트, 테스트 코드에서 모의로 구성된 발신자와 수신자가 모두 이 범주에 들어간다.

코드에서는 별도 `UserAgent` 클래스가 없다. 대신 등록 정보, 다이얼로그, 구독, 패킷 송수신 정보가 여러 구조체로 나뉘어 표현된다.

### Proxy

프록시는 SIP 요청을 받아 적절한 다음 홉으로 전달하고, 필요하면 헤더를 수정한다. 이 프로젝트의 핵심 역할은 프록시에 가깝다. 특히 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)의 `addProxyVia()`, `addRecordRoute()`, `stripOwnRoute()` 같은 함수가 그 성격을 잘 보여 준다.

### Registrar

`REGISTER`를 받아 위치 정보를 저장하는 역할이다. SIPLite는 프록시이면서 동시에 registrar 역할도 수행한다. 이 점은 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)의 `handleRegister()`와 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)의 `Registration` 구조체에서 확인할 수 있다.

### Location Service

등록된 사용자와 현재 연락 가능한 주소를 연결하는 저장소다. 이 프로젝트에서는 독립 서비스가 아니라 `SipCore` 내부의 등록 맵이 그 역할을 맡는다. 즉 구조적으로는 인메모리 location service다.

### Transaction

SIP 요청과 그에 대응하는 응답 집합을 묶는 단위다. 일반적으로 `Via branch`, `CSeq`, 메서드 조합으로 식별한다. 이 프로젝트는 transaction 상태 머신 전체를 범용 엔진으로 구현한 수준은 아니지만, pending INVITE, 응답 전달, stale transaction cleanup 등을 통해 핵심 개념을 일부 반영하고 있다.

### Dialog

호출 참여자 사이의 더 긴 수명 상태를 뜻한다. `Call-ID`, 로컬 태그, 원격 태그 조합으로 식별된다. 현재 코드에서는 `ActiveCall`, `Dialog` 성격의 구조와 BYE/ACK 라우팅 로직이 이에 해당한다.

### Registration

사용자 AOR(Address of Record)와 현재 연락 가능한 Contact 주소를 일정 시간 동안 묶는 상태다. `REGISTER` 처리 후 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)의 등록 구조체로 보관되고, 만료 시 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)의 cleanup 함수가 제거한다.

### Subscription

이벤트 구독 상태를 의미한다. 현재 프로젝트는 `SUBSCRIBE`와 `NOTIFY`를 지원하고, 구독 만료 정리도 메인 루프에서 수행한다. 이는 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)의 `cleanupExpiredSubscriptions()` 호출과 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)의 `handleSubscribe()`, `handleNotify()`에서 확인된다.

### Transport

SIP 메시지를 실어 나르는 실제 전송 프로토콜이다. 이 프로젝트는 [include/UdpPacket.h](/home/windmorning/projects/SIPWorks/SIPLite/include/UdpPacket.h)에서 `TransportType::UDP`, `TransportType::TCP`, `TransportType::TLS`를 정의한다. 이름은 `UdpPacket`이지만, 실질적으로는 transport-agnostic 패킷 컨테이너로 확장되어 있다.

### Timer C

프록시가 INVITE 진행 상황을 무한정 기다리지 않도록 하는 타이머다. 이 프로젝트는 메인 루프에서 주기적으로 `cleanupTimerC()`를 호출해 timeout된 INVITE를 정리한다. 구현 세부는 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)의 pending INVITE 처리와 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)의 관련 구조체에서 확인할 수 있다.

## 22.2 SIP 헤더 용어 정리

### Via

메시지가 지나온 경로를 추적하는 헤더다. 프록시는 자기 자신을 `Via`에 추가한다. 이 프로젝트에서는 `addProxyVia()`가 이 작업을 맡는다. 전송 프로토콜이 UDP/TCP/TLS인지에 따라 `SIP/2.0/UDP`, `SIP/2.0/TCP`, `SIP/2.0/TLS` 값을 다르게 만든다.

### Record-Route

향후 다이얼로그 내 요청도 다시 프록시를 경유하게 만들기 위한 헤더다. 이 프로젝트는 `addRecordRoute()`로 경로를 삽입하고, 이후 `stripOwnRoute()`로 자기 자신 route를 제거하면서 다음 홉을 계산한다.

### Contact

상대가 직접 연락할 수 있는 구체 주소다. `REGISTER`에서는 등록 주소로, `INVITE` 응답에서는 통화 중 직접 참조 가능한 주소로 사용된다. 이 프로젝트는 transport에 맞춘 로컬 Contact를 구성하기 위해 `buildLocalContactHeader()`를 제공한다.

### Call-ID

호 세션을 식별하는 핵심 값이다. 워커 큐 라우팅, active call 조회, ACK/BYE/CANCEL 흐름 추적에서 매우 중요하다.

### CSeq

같은 다이얼로그 안에서 요청 순서를 관리하는 번호다. 현재 구현은 완전한 UAC/UAS 시퀀스 엔진을 제공하는 수준은 아니지만, 메서드 구분과 응답 매칭에 핵심적으로 사용된다.

### Max-Forwards

프록시 홉 수 제한용 헤더다. 현재 프로젝트는 프록시 전달 시 이를 감소시킨다. 이는 루프 방지의 가장 기본적인 구현이다.

### Content-Length

메시지 본문 길이를 명시한다. [src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp)는 이 값을 실제 본문 길이와 비교해 불일치 시 파싱 실패로 처리한다. 이는 parser robustness 측면에서 중요한 방어선이다.

## 22.3 이 프로젝트가 걸쳐 있는 RFC 범위

### RFC 3261

가장 중심이 되는 SIP 기본 RFC다. 이 프로젝트의 거의 모든 주제가 여기에 닿아 있다.

- `REGISTER`
- `INVITE`
- `ACK`
- `BYE`
- `CANCEL`
- 응답 코드 처리
- `Via`, `Record-Route`, `Contact`, `Call-ID`, `CSeq`
- transaction/dialog 개념

다만 "RFC 3261 전체 구현"으로 보기는 어렵다. 현재 코드는 실용적인 서버 코어에 가깝고, 모든 예외 상태 머신과 모든 타이머를 완전 구현한 범용 SIP 스택은 아니다.

### RFC 3265

`SUBSCRIBE`와 `NOTIFY`의 기본 이벤트 프레임워크를 다룬다. 현재 구현된 subscription 기능은 이 RFC 계열 맥락에서 이해하는 것이 맞다. 다만 특정 이벤트 패키지 전체를 깊게 구현했다기보다, 기본 구독/알림 메커니즘을 지원하는 수준으로 보는 편이 정확하다.

### RFC 5922 및 SIP over TLS 관련 문맥

정확한 세부 준수 여부를 떠나, 이 프로젝트의 TLS 기능은 SIP over TLS 운용 문맥에서 읽어야 한다. [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)는 TLS 1.2 이상, 인증서 로딩, peer verification, client cert requirement를 다룬다. 반면 hostname verification 미구현처럼 아직 남은 부분도 명시되어 있다.

즉 TLS는 "있다/없다"보다 "어디까지 구현되었는가"로 읽어야 한다.

## 22.4 구현된 것과 구현되지 않은 것을 구분하는 법

이 프로젝트를 문서화할 때 가장 중요한 태도 중 하나는 "SIP 용어를 안다고 해서 그 기능이 완전 구현되었다고 쓰지 않는 것"이다.

예를 들어 다음은 구현된 것으로 볼 수 있다.

- UDP/TCP/TLS transport 수신 및 송신
- `REGISTER`, `INVITE`, `ACK`, `BYE`, `CANCEL` 기본 처리
- `SUBSCRIBE`, `NOTIFY` 기본 처리
- Digest 인증 처리
- `Content-Length` 검증
- Timer C cleanup

반면 다음은 신중하게 표현해야 한다.

- 모든 RFC 타이머 완전 구현
- 완전한 transaction state machine
- 완전한 dialog state machine
- TLS hostname verification
- 대규모 production hardening

책을 쓸 때는 이 차이를 문장 안에서 분명히 드러내는 것이 중요하다. 예를 들면 "지원한다"와 "완전 준수한다"는 전혀 다른 표현이다.

## 22.5 코드 구조와 SIP 개념의 대응표

아래 표는 독자가 코드를 읽을 때 개념을 빠르게 대응시키기 위한 것이다.

| SIP 개념 | 코드 중심 위치 | 설명 |
|---|---|---|
| Registrar | [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp) `handleRegister()` | REGISTER 수신, 인증, 등록 저장 |
| Location Service | [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h) 등록 저장 구조 | 메모리 기반 단말 위치 저장 |
| Proxy | [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp) `handleInvite()`, `handleResponse()`, `addProxyVia()` | 요청/응답 중계와 헤더 수정 |
| Dialog | [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h) call/dialog 관련 구조 | 통화 지속 상태 보관 |
| Subscription | [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp) `handleSubscribe()`, `handleNotify()` | 구독 생성, 갱신, 종료 |
| Transport Layer | [src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp), [src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp), [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp) | 실제 네트워크 수신/송신 |
| Parser | [src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp) | raw 메시지 파싱 |
| Runtime Control | [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp), [src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp) | 서버 시작, 종료, 상태 조회 |

## 22.6 집필 시 유용한 표현 규칙

이 분석서를 실제 책으로 발전시킬 때는 용어를 일정하게 쓰는 것이 중요하다. 다음 규칙을 추천한다.

1. "단말"과 "user agent"를 혼용하되, 처음 등장 시 둘을 연결해서 설명한다.
2. "등록", "구독", "호"는 상태 수명이 다르므로 같은 범주처럼 쓰지 않는다.
3. "프록시", "레지스트라", "로케이션 서비스"는 역할이 다르지만 이 프로젝트 안에서는 `SipCore`가 함께 수행한다고 명시한다.
4. "TLS 지원"이라고 쓸 때는 인증서 검증 범위를 같이 적는다.
5. "RFC 준수"라는 표현은 피하고, "RFC 3261의 어떤 개념을 구현한다"처럼 더 구체적으로 쓴다.

이 규칙을 지키면 독자는 과장 없는 설명을 신뢰할 수 있고, 나중에 코드가 바뀌어도 문서를 유지보수하기 쉬워진다.

## 22.7 이 장의 핵심 정리

이 프로젝트를 이해할 때 가장 중요한 것은 용어를 많이 아는 것이 아니라, 용어와 코드 위치를 정확히 연결하는 것이다.

- `REGISTER`는 registrar와 location service 문맥으로 읽는다.
- `INVITE/ACK/BYE/CANCEL`은 proxy와 dialog 문맥으로 읽는다.
- `SUBSCRIBE/NOTIFY`는 subscription 문맥으로 읽는다.
- UDP/TCP/TLS는 transport 문맥으로 읽는다.
- TLS는 "구현 존재"와 "보안 완성"을 분리해서 읽는다.

이 장을 기준점으로 삼으면, 앞의 장들을 다시 읽을 때도 "이 코드는 SIP에서 무슨 역할인가"를 훨씬 빠르게 이해할 수 있다.
