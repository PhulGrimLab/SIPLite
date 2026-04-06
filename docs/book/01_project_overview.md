# 1. 프로젝트 개요

## 1.1 이 프로젝트를 어떻게 봐야 하는가

SIPLite는 단순한 UDP 에코 서버나 예제 수준 파서가 아니다. 현재 코드 기준으로 보면 이 프로젝트는 다음 성격을 동시에 가진다.

- SIP 요청과 응답을 파싱하는 메시지 처리기
- 등록 상태를 유지하는 registrar 성격의 상태 저장소
- INVITE, ACK, BYE, CANCEL을 중계하는 stateful proxy 성격의 라우터
- SUBSCRIBE/NOTIFY를 처리하는 이벤트 구독 관리자
- UDP, TCP, TLS 세 가지 transport를 동시에 다루는 멀티 트랜스포트 서버

이 성격을 한 문장으로 줄이면 다음과 같다.

`SIPLite는 하나의 SipCore를 중심으로 여러 transport 계층이 붙는 경량 SIP 상태 서버다.`

이 한 문장을 먼저 이해하면 이후 구조가 훨씬 잘 보인다.

## 1.2 코드 구조의 핵심 아이디어

그림 1은 이 프로젝트를 가장 짧게 보여 주는 구조도다.

```text
                         +----------------------+
                         |      main.cpp        |
                         | bootstrap / wiring   |
                         +----------+-----------+
                                    |
        +---------------------------+---------------------------+
        |                           |                           |
        v                           v                           v
+---------------+         +----------------+         +----------------+
|   UdpServer   |         |   TcpServer    |         |   TlsServer    |
| recv/send     |         | recv/send      |         | recv/send+SSL  |
+-------+-------+         +--------+-------+         +--------+-------+
        \                          |                          /
         \                         |                         /
          +------------------------+------------------------+
                                   |
                                   v
                        +------------------------+
                        |        SipCore         |
                        | routing / state / SIP  |
                        +-----+-----+-----+------+
                              |     |     |
                              v     v     v
                    +-----------+ +------+ +--------------+
                    | Registrar | | Call | | Subscription |
                    | state     | | state| | state        |
                    +-----------+ +------+ +--------------+
```

이 프로젝트의 가장 중요한 설계 선택은 "네트워크 입출력"과 "SIP 의미 처리"를 분리한 것이다.

네트워크 계층은 다음 파일이 맡는다.

- [src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp)
- [src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp)
- [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)

SIP 의미 처리와 상태 관리는 다음 파일이 맡는다.

- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)

문자열 파싱은 다음 파일이 맡는다.

- [include/SipParser.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipParser.h)
- [src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp)

즉 이 프로젝트는 "소켓별로 SIP 처리 로직이 흩어진 구조"가 아니라, transport 서버들이 공통 `SipCore`로 입력을 넘기고 `SipCore`가 다시 적절한 transport로 송신을 위임하는 구조다.

## 1.3 가장 먼저 봐야 할 파일

코드 전체를 이해하고 싶다면 읽는 순서는 아래가 가장 효율적이다.

1. [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)
2. [include/UdpPacket.h](/home/windmorning/projects/SIPWorks/SIPLite/include/UdpPacket.h)
3. [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)
4. [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)
5. [src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp)
6. [src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp)
7. [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)
8. [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp)

이 순서를 권하는 이유는 명확하다.

- `main.cpp`는 프로그램의 실제 조립 순서를 보여준다.
- `UdpPacket.h`는 transport 추적 모델이 어떻게 표현되는지 보여준다.
- `SipCore.h`는 상태 구조체와 핵심 API를 보여준다.
- `SipCore.cpp`는 실제 동작 의미를 보여준다.
- 각 서버 구현은 transport별 세부사항을 보여준다.
- 테스트는 구현 의도와 회귀 조건을 보여준다.

## 1.4 이 프로젝트의 중심 객체: `SipCore`

이 프로젝트를 제대로 설명하려면 `SipCore`를 중심축으로 잡아야 한다.

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)와 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)를 보면 `SipCore`는 단순 메서드 집합이 아니라 다음 책임을 동시에 가진다.

- SIP 요청 유효성 검증
- 메서드 분기
- 등록 상태 저장
- 통화 상태 저장
- 구독 상태 저장
- 트랜잭션 상태 저장
- transport-aware 라우팅
- SIP 헤더 재작성
- 주기적 cleanup 대상 관리

즉 네트워크 서버는 "운반자", `SipCore`는 "의사결정자"다.

## 1.5 transport를 왜 별도 장으로 봐야 하는가

이 프로젝트를 일반 SIP 예제와 구분하는 중요한 지점은 transport가 단순 부가 속성이 아니라 실제 라우팅 의미를 가진다는 점이다.

[include/UdpPacket.h](/home/windmorning/projects/SIPWorks/SIPLite/include/UdpPacket.h#L7)에는 다음 정의가 있다.

```cpp
enum class TransportType { UDP, TCP, TLS };
```

그리고 같은 파일의 [UdpPacket.h](/home/windmorning/projects/SIPWorks/SIPLite/include/UdpPacket.h#L9) 구조체는 이름이 `UdpPacket`이지만, 실제로는 UDP 전용이 아니라 transport 독립 입력 컨테이너처럼 쓰인다.

```cpp
struct UdpPacket
{
    std::string remoteIp;
    uint16_t remotePort = 0;
    std::string data;
    TransportType transport = TransportType::UDP;
};
```

이 설계 때문에 UDP, TCP, TLS 수신 패킷이 모두 동일한 내부 경로로 `SipCore`에 전달될 수 있다. 결과적으로 `SipCore`는 "누가 보냈는가"뿐 아니라 "어떤 transport로 들어왔는가"까지 상태에 반영할 수 있다.

이 점은 TLS 구현을 이해할 때 특히 중요하다. 이 프로젝트의 TLS는 단지 "TLS 소켓이 하나 더 있다" 수준이 아니라, 등록과 라우팅 상태에 transport를 반영하는 방향으로 확장되어 있다.

## 1.6 현재 코드가 지원하는 주요 관심사

표 1은 현재 구현 범위를 한 번에 요약한 것이다.

| 영역 | 현재 구현 | 핵심 위치 |
|---|---|---|
| Registration | 구현됨 | `handleRegister()`, `Registration` |
| Call Proxying | 구현됨 | `handleInvite()`, `handleResponse()` |
| Dialog / Teardown | 구현됨 | `handleAck()`, `handleBye()`, `handleCancel()` |
| Subscription | 구현됨 | `handleSubscribe()`, `handleNotify()` |
| UDP/TCP/TLS | 구현됨 | `UdpServer`, `TcpServer`, `TlsServer` |
| XML bootstrap | 구현됨 | `XmlConfigLoader` |
| Digest auth | 구현됨 | REGISTER auth path |
| Hostname verification | 미구현 | TLS 보안 공백 |

현 시점의 코드와 문서, 테스트를 함께 보면 이 프로젝트의 주요 관심사는 아래와 같다.

- REGISTER 기반 위치 등록
- INVITE 기반 세션 설정
- ACK, BYE, CANCEL 처리
- MESSAGE 중계
- SUBSCRIBE / NOTIFY 처리
- Timer C 기반 INVITE 타임아웃 정리
- UDP/TCP/TLS transport 유지
- XML 기반 정적 단말 등록
- Digest 인증 기반 REGISTER 보호

이 중 어떤 기능은 오래된 예제 성격으로 시작했고, 어떤 기능은 최근에 transport-aware 구조로 보강되었다. 따라서 코드베이스는 "처음부터 완전히 일관된 하나의 설계"라기보다, 핵심 뼈대를 유지한 채 기능을 단계적으로 붙여온 형태로 이해하는 것이 맞다.

## 1.7 이 프로젝트는 proxy인가 registrar인가

이 질문은 책을 쓸 때 반드시 한 번 분리해서 설명해야 한다.

현재 구현을 보면 이 프로젝트는 두 역할을 동시에 가진다.

### registrar 역할

- REGISTER를 받아 AoR와 Contact, 실제 수신 IP/포트, transport, 인증 정보, 만료 시간을 저장한다.
- 관련 상태는 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L131)의 `Registration` 구조체에 모여 있다.
- 정적 단말은 [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)와 `registerTerminal()`을 통해 사전 등록할 수 있다.

### stateful proxy 역할

- INVITE를 목적 단말로 전달한다.
- 최상단 `Via`를 추가한다.
- `Record-Route`를 추가한다.
- 응답을 다시 원래 호출자에게 전달한다.
- 미확립 INVITE를 `PendingInvite`로 저장해 ACK, CANCEL, Timer C를 처리한다.

따라서 독자는 이 프로젝트를 "단순 registrar"로 읽으면 안 되고, "registrar + stateful proxy가 한 프로세스 안에 묶인 형태"로 읽는 편이 정확하다.

## 1.8 TLS는 실제 구현인가, 흔적만 있는가

이 질문도 책의 초반에 분명히 적어둘 필요가 있다.

현재 프로젝트의 TLS는 실구현이다.

근거는 다음과 같다.

- OpenSSL 헤더를 직접 포함한다: [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L5)
- `SSL_CTX_new`, `SSL_accept`, `SSL_connect`, `SSL_read`, `SSL_write` 경로가 있다: [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L189), [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L821), [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L640), [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L898), [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L1063)
- 인증서 파일이 존재한다: [certs/server.crt](/home/windmorning/projects/SIPWorks/SIPLite/certs/server.crt), [certs/server.key](/home/windmorning/projects/SIPWorks/SIPLite/certs/server.key)
- `Makefile`이 OpenSSL을 링크한다: [Makefile](/home/windmorning/projects/SIPWorks/SIPLite/Makefile)
- `SipCore`가 TLS용 `Via`, `Record-Route`, `Contact`를 생성한다: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2223), [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2295), [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2653)
- TLS transport 테스트가 존재한다: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L638)

즉 이 코드는 `sips:` 문자열만 허용하는 형식적 지원이 아니라, transport 계층과 SIP 라우팅 모델이 실제로 연결된 TLS 구현으로 봐야 한다.

## 1.9 이 책에서 독자가 자주 혼동할 부분

집필할 때 아래 항목은 초반부터 명확히 적어두는 것이 좋다.

### `UdpPacket`은 UDP 전용 타입이 아니다

이름은 `UdpPacket`이지만 실제로는 TCP/TLS 입력도 담는다. 이 이름 때문에 구조를 오해하기 쉽다.

### `UdpServer`가 전체 시스템의 기준점이다

`main.cpp`에서는 먼저 `UdpServer`를 만들고, 그 안의 `SipCore`를 TCP와 TLS가 공유한다. 따라서 시스템의 중앙 상태는 `UdpServer`의 멤버에서 시작된다고 보는 편이 맞다.

### TLS는 별도 앱이 아니라 같은 코어를 공유한다

`TlsServer`는 독립 SIP 스택이 아니다. 같은 `SipCore`에 연결된 transport 하나다.

### 프로젝트는 완전히 순수한 RFC 구현체라기보다 실용 지향 구현이다

코드에는 RFC 주석이 많지만, 실제 구현은 테스트 가능성과 운영 편의, 기존 코드 유지라는 현실적 요구가 섞여 있다. 책에서는 이를 숨기기보다 드러내는 편이 정확하다.

## 1.10 이 장의 핵심 정리

이 장의 핵심은 세 가지다.

첫째, SIPLite의 중심은 네트워크 서버가 아니라 `SipCore`다.  
둘째, UDP/TCP/TLS는 서로 분리된 독립 시스템이 아니라 하나의 상태 코어를 공유하는 transport 계층이다.  
셋째, 이 프로젝트는 현재 기준으로 registrar, stateful proxy, subscription 처리기, TLS transport 서버의 성격을 함께 가진다.

이 이해를 바탕으로 다음 장에서는 실제 프로그램이 시작되고 서버들이 어떻게 조립되는지 `main.cpp` 중심으로 본다.
