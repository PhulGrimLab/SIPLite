# 3. 전송 계층 구조

## 3.1 이 장의 목적

표 3은 세 transport의 차이를 가장 빠르게 보여 준다.

| Transport | 장점 | 한계 | 핵심 파일 | 비고 |
|---|---|---|---|---|
| UDP | 단순, 빠른 수신 | 손실/재전송 고려 필요 | `src/UdpServer.cpp` | 기준 transport |
| TCP | 순서 보장, 큰 메시지 유리 | framing/연결 관리 필요 | `src/TcpServer.cpp` | `epoll`, connection map |
| TLS | 보안 채널, 인증서 활용 | handshake/암복호화 비용 | `src/TlsServer.cpp` | OpenSSL 기반 |

SIPLite의 transport 계층은 단순 부가 기능이 아니다. 이 계층은 다음 두 가지 역할을 한다.

- 네트워크에서 SIP 메시지를 받아 `SipCore`로 전달한다.
- `SipCore`가 선택한 transport 정책에 따라 메시지를 다시 송신한다.

따라서 이 장은 "소켓 코드 설명"이 아니라 "transport가 SIP 의미와 어떻게 연결되는가"를 설명하는 장이 되어야 한다.

## 3.2 공통 입력 모델: `UdpPacket`

모든 transport는 최종적으로 [include/UdpPacket.h](/home/windmorning/projects/SIPWorks/SIPLite/include/UdpPacket.h)에 정의된 같은 구조로 `SipCore`에 입력을 전달한다.

```cpp
struct UdpPacket
{
    std::string remoteIp;
    uint16_t remotePort = 0;
    std::string data;
    TransportType transport = TransportType::UDP;
};
```

이 구조의 의미는 분명하다.

- `remoteIp`, `remotePort`는 송신자 식별 정보다.
- `data`는 raw SIP 전문이다.
- `transport`는 의미 있는 라우팅 정보다.

이 설계는 transport 간 공통 처리 경로를 가능하게 한다. UDP, TCP, TLS는 수신 방식은 다르지만, 일단 SIP 메시지가 만들어지면 그 이후 경로는 대부분 같다.

## 3.3 세 transport 서버의 공통 책임

세 서버는 모두 다음 책임을 가진다.

1. 소켓 생성과 바인딩
2. 수신 루프 운영
3. 워커 큐와 스레드 관리
4. 빠른 `Call-ID` 추출로 call-affinity 라우팅
5. SIP 메시지 파싱 전 단계의 raw message 준비
6. `SipCore::handlePacket()` 호출
7. 응답 송신

즉 차이는 존재하지만, 뼈대는 매우 유사하다.

## 3.4 UDP 서버

UDP 구현은 [src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp)에 있다.

### 3.4.1 UDP가 기준 구현인 이유

`main.cpp`가 가장 먼저 `UdpServer`를 시작하고, 초기 `setSender()`도 우선 UDP 기준으로 붙는다. 또한 `UdpServer` 내부에 기본 `SipCore`가 존재한다는 점에서 UDP 서버는 transport 계층의 기준 구현이다.

### 3.4.2 worker 분배

[src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp#L98)에는 `routeToWorker()`가 있다. `Call-ID` 해시 기반으로 워커를 고정한다.

이 방식의 장점은 다음과 같다.

- 같은 통화의 관련 메시지가 같은 워커로 갈 가능성이 높다.
- 상태 접근 locality가 좋아진다.
- 병렬 처리를 하면서도 통화 단위 흐름을 어느 정도 보존할 수 있다.

### 3.4.3 빠른 `Call-ID` 추출

[src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp#L35) 부근의 `extractCallIdQuickImpl()`은 전체 파싱 없이 `Call-ID`만 찾는다.

이 최적화는 실용적이다.

- 전체 SIP 파서는 비용이 더 크다.
- worker 분배에는 완전한 parse tree가 필요 없다.
- compact form `i:`까지 찾는다.

즉 이 단계는 "정확한 SIP 처리"보다 "빠른 워커 라우팅"을 위한 전처리다.

### 3.4.4 로컬 주소 계산

[src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp#L143) 이후에는 `0.0.0.0` 바인딩 시 실제 로컬 IP를 추정하는 코드가 있다.

이 값은 `SipCore::setLocalAddress()`와 `setLocalAddressForTransport()`에 들어간다. 따라서 이 주소는 단순 로그 값이 아니라, 이후 `Via`, `Record-Route`, `Contact` 생성에 쓰이는 중요한 메타데이터다.

### 3.4.5 송신 콜백

[src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp#L138)에서는 기본 `setSender()`를 UDP `sendTo()`로 연결한다. 나중에 `main.cpp`가 transport-aware sender로 덮어쓰지만, 이 기본 연결은 독립 테스트나 단독 실행에서 의미가 있다.

## 3.5 TCP 서버

TCP 구현은 [src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp)에 있다.

### 3.5.1 UDP와 다른 핵심 차이

UDP는 datagram이라 한 번 수신한 버퍼가 하나의 메시지일 가능성이 높지만, TCP는 stream이다. 그래서 TCP 서버의 핵심 문제는 "메시지 framing"이다.

이 때문에 TCP 서버는 다음을 더 신경 써야 한다.

- 연결 수명 관리
- 스트림 버퍼 누적
- `Content-Length` 기반 메시지 분리
- 같은 상대에 대한 재사용 송신 연결 관리

### 3.5.2 `epoll` 기반 수신

[src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp#L142)에서 `epoll_create1()`을 사용한다. 이는 TCP 연결 수가 증가할 수 있는 환경을 고려한 선택이다.

이 구조는 다음을 가능하게 한다.

- 여러 소켓 이벤트를 효율적으로 감시
- listen socket과 client socket을 같은 이벤트 루프에서 관리
- 워커 스레드와 수신 스레드 역할 분리

### 3.5.3 연결 관리

TCP 서버는 `connections_`, `outgoingConns_`를 가진다. 즉 inbound accepted connection과 outbound connection을 모두 관리한다.

이 점은 중요하다. 이 프로젝트의 TCP는 단순 "받기만 하는 서버"가 아니라, 필요 시 outbound TCP 연결을 열어 SIP 메시지를 보내는 모델을 가진다.

### 3.5.4 `TCP_NODELAY`

[src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp#L246)에서 `TCP_NODELAY`를 켠다. SIP 메시지는 일반적으로 지연 누적보다 즉시 전송이 중요하므로 현실적인 선택이다.

## 3.6 TLS 서버

그림 3은 TLS transport가 `SipCore`에 연결되는 실제 경로를 요약한다.

```text
TCP accept/connect
      |
      v
 SSL_accept / SSL_connect
      |
      v
   SSL_read
      |
      v
  recvBuffer 누적
      |
      v
 extractSipMessage()
      |
      v
 UdpPacket { transport = TLS }
      |
      v
 worker queue route(Call-ID)
      |
      v
 SipCore::handlePacket()
      |
      v
 sender callback -> TlsServer::sendTo() -> SSL_write
```

TLS 구현은 [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)에 있다.

### 3.6.1 TLS 서버의 위치

TLS 서버는 구조상 "TLS 위의 TCP SIP 서버"다. 실제로 코드도 TCP 서버와 매우 비슷한 형태를 가진다.

공통점:

- 논블로킹 소켓
- `epoll` 기반 이벤트 루프
- worker 큐와 call-affinity 라우팅
- `extractSipMessage()` 기반 SIP 메시지 분리
- outbound connection 재사용

추가 책임:

- OpenSSL 초기화
- `SSL_CTX` 관리
- 인증서/개인키 로딩
- inbound handshake
- outbound handshake
- 검증 정책 적용

### 3.6.2 환경변수 기반 검증 정책

[src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L109)의 `envEnabled()`와 [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L177)의 `initializeSsl()`을 보면 TLS 검증 정책은 환경변수로 제어된다.

주요 값:

- `SIPLITE_TLS_VERIFY_PEER`
- `SIPLITE_TLS_REQUIRE_CLIENT_CERT`
- `SIPLITE_TLS_CA_FILE`

이 설계는 개발 환경과 운영 환경을 분리하기 좋다. 개발 시에는 느슨한 정책으로 빠르게 띄우고, 운영 시에는 CA/peer 검증을 강화할 수 있다.

### 3.6.3 TLS 입력이 `SipCore`로 가는 방식

[src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L927) 이후를 보면 TLS 수신 버퍼에서 SIP 메시지를 추출한 뒤 `pkt.transport = TransportType::TLS`를 설정해 `SipCore`에 전달한다.

이 한 줄의 의미는 매우 크다.

- TLS 수신 여부가 이후 상태 모델에 남는다.
- 등록 시 `Registration.transport`에 TLS가 들어갈 수 있다.
- 응답/포워딩 시 TLS transport를 유지할 수 있다.

즉 TLS는 단순 소켓 래핑이 아니라, transport semantics를 `SipCore`에 전달하는 실제 구현이다.

## 3.7 세 transport의 차이를 표로 보면

### UDP

- 연결 없음
- 메시지 경계 자연 보존
- 구현 가장 단순
- 기준 transport

### TCP

- 연결 있음
- 스트림 버퍼 필요
- `epoll`과 connection table 필요
- outbound 연결 재사용 필요

### TLS

- TCP의 모든 성격 포함
- OpenSSL handshake 필요
- 인증서/검증 정책 필요
- `TransportType::TLS`에 따른 SIP 헤더 차별화 필요

## 3.8 왜 이름이 약간 어색한가

이 코드베이스는 진화형 구조라 이름과 역할이 완전히 일치하지 않는 부분이 있다.

대표적으로:

- `UdpPacket`은 UDP 전용이 아니다.
- `UdpServer`가 사실상 공통 `SipCore`의 보유자 역할까지 한다.

이 점은 설계 결함이라고 단정할 필요는 없다. 다만 책에서는 독자가 이름에 속지 않도록 초반에 분명히 짚어줘야 한다.

## 3.9 transport와 SIP 의미가 만나는 지점

세 transport 서버는 결국 같은 `SipCore::handlePacket()`을 호출한다. 의미 계층과 transport 계층이 만나는 지점은 아래 세 개다.

1. `UdpPacket.transport`
2. `SipCore::setSender(...)`
3. `SipCore::setLocalAddressForTransport(...)`

이 세 요소 덕분에 `SipCore`는 다음 판단을 할 수 있다.

- 어떤 transport로 들어왔는가
- 어떤 transport로 다시 보내야 하는가
- 어떤 `Via` / `Record-Route` / `Contact`를 써야 하는가

즉 transport 계층은 네트워크 I/O를 넘어 SIP 헤더 의미 형성에도 직접 관여한다.

## 3.10 이 장의 핵심 정리

이 프로젝트의 transport 계층은 "UDP 서버 하나에 TCP/TLS를 덧댄 구조"처럼 보이지만, 실제로는 더 정교하다.

- 입력은 공통 `UdpPacket` 모델로 통일된다.
- 출력은 `setSender()`를 통해 transport-aware 라우팅된다.
- UDP는 기준 구현, TCP는 스트림 기반 연결형 구현, TLS는 TCP 위에 보안과 인증을 얹은 구현이다.

다음 장에서는 이제 transport를 잠시 내려놓고, 시스템의 중심인 `SipCore`가 실제로 어떤 판단을 하는지 본다.
