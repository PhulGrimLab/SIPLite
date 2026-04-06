# 2. 엔트리포인트와 런타임 구조

## 2.1 왜 `main.cpp`를 먼저 읽어야 하는가

규모가 있는 서버 코드는 보통 "구현이 복잡한 클래스"보다 "조립을 담당하는 엔트리포인트"가 전체 구조를 가장 빠르게 보여준다. 이 프로젝트도 마찬가지다.

[src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)는 다음 정보를 한 번에 보여준다.

- 어떤 서버가 존재하는가
- 어떤 순서로 시작하는가
- `SipCore`는 어떻게 공유되는가
- TLS는 어떤 조건에서 시작되는가
- cleanup 루프는 무엇을 정리하는가
- 종료 순서는 어떻게 되는가

즉 `main.cpp`는 단순 bootstrap 파일이 아니라, 시스템 구조를 설명하는 가장 좋은 문서다.

## 2.2 프로그램 시작 순서

그림 2는 `main.cpp`가 실제로 어떤 순서로 시스템을 조립하는지 보여 준다.

```text
main()
  |
  +--> signal handler 등록
  +--> config path 결정
  +--> Logger init
  +--> UdpServer 생성/시작
  +--> XML load
  +--> TcpServer 시작
  +--> [if TLS enabled] TlsServer 시작
  +--> SipCore::setSender(...)
  +--> XML terminal bootstrap 등록
  +--> ConsoleInterface 시작
  +--> main cleanup loop
  +--> shutdown
```

표 2는 시작과 종료 단계를 요약한 것이다.

| 단계 | 위치 | 설명 |
|---|---|---|
| 시그널 등록 | `main.cpp` | `SIGINT`, `SIGTERM` 처리 준비 |
| 로그 초기화 | `main.cpp` | 보존 기간 설정, 로그 파일 준비 |
| UDP 시작 | `main.cpp` | 기본 transport 및 `SipCore` 기준점 |
| TCP 시작 | `main.cpp` | 선택적 연결형 transport |
| TLS 시작 | `main.cpp` | 환경 변수 기반 조건부 시작 |
| sender wiring | `main.cpp` | transport별 송신 분기 |
| bootstrap 등록 | `main.cpp` | XML 단말 선등록 |
| 콘솔 시작 | `main.cpp` | 운영 인터페이스 활성화 |
| cleanup loop | `main.cpp` | 타이머/상태 정리 |
| shutdown | `main.cpp` | console -> tls -> tcp -> udp -> logger |

`main()`의 전체 흐름은 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L56)에서 시작된다. 순서를 단계별로 정리하면 다음과 같다.

1. 시그널 핸들러 등록
2. 설정 파일 경로 결정
3. 배너 출력
4. `Logger` 초기화
5. `UdpServer` 생성
6. XML 설정 로드
7. UDP 서버 시작
8. `SipCore`를 공유하는 TCP 서버 시작
9. 환경변수에 따라 TLS 서버 시작
10. `SipCore::setSender()` 등록
11. XML 기반 정적 단말 등록
12. 콘솔 인터페이스 시작
13. cleanup 메인 루프 진입
14. 종료 시 콘솔, TLS, TCP, UDP 순으로 정리

이 흐름을 보면 시스템은 "수신 루프 중심"이라기보다 "초기화 후 장시간 상태 유지"를 전제로 한 서버임이 분명하다.

## 2.3 시그널 처리

프로그램은 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L27)의 `signalHandler()`를 통해 `SIGINT`, `SIGTERM`을 받는다. 처리 방식은 단순하다.

- 시그널 핸들러는 최소 작업만 한다.
- 실제 종료 플래그 반영은 `checkSignal()`에서 한다.
- 메인 루프가 주기적으로 `checkSignal()`을 호출한다.

이 구조는 시그널 핸들러 안에서 복잡한 작업을 하지 않으려는 전형적인 안전 설계다.

책에서는 이 부분을 "이 서버는 운영 중지 신호를 메인 스레드에서 질서 있게 처리한다"는 관점으로 설명하면 좋다.

## 2.4 로거 초기화

로거 초기화는 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L82) 부근에서 이뤄진다.

특징은 다음과 같다.

- 로그 보존 기간을 환경변수 `SIPLITE_LOG_RETENTION_DAYS`로 받는다.
- 기본 로그 디렉터리는 `logs`
- 시작 시점과 설정값을 로그에 남긴다.

이 프로젝트는 로그를 강하게 의존하는 구조이므로, 책에서는 로깅이 단순 부가 기능이 아니라 운영 관찰성의 핵심이라는 점을 강조할 필요가 있다.

## 2.5 `UdpServer`가 기준점이 되는 이유

[src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L102)에서 가장 먼저 생성되는 네트워크 서버는 `UdpServer`다.

중요한 점은 단지 "UDP를 먼저 켠다"가 아니다. 실제로는 `UdpServer`가 내부에 가진 `SipCore`를 TCP와 TLS 서버가 공유한다는 점이 더 중요하다.

```cpp
UdpServer udpServer;
TcpServer tcpServer(udpServer.sipCore());
TlsServer tlsServer(udpServer.sipCore());
```

이 조립 방식의 의미는 다음과 같다.

- SIP 상태 저장소는 하나다.
- transport별로 등록 상태가 분리되지 않는다.
- INVITE, 응답, 구독, cleanup 로직은 모두 공통 코어에서 수행된다.

즉 이 프로젝트의 진짜 중앙 객체는 `udpServer`가 아니라 `udpServer.sipCore()`라고 보는 편이 맞다.

## 2.6 설정 파일 로드와 정적 단말 등록

설정 파일 경로는 기본적으로 `config/terminals.xml`이고, 명령행 인자로 바꿀 수 있다. 관련 코드는 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L62) 이후에 있다.

설정 파일은 [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)에서 읽고, `main.cpp`는 `loadTerminals()` 결과를 받은 뒤 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L204)에서 `registerTerminals()`를 호출한다.

이 동작의 의미는 아래와 같다.

- 실제 SIP REGISTER가 오기 전에도 단말을 미리 등록할 수 있다.
- 테스트 환경이나 개발 환경에서 신속하게 목적지 라우팅을 구성할 수 있다.
- transport 설정도 XML에 넣을 수 있으므로 UDP/TCP/TLS별 정적 등록이 가능하다.

이 프로젝트를 책으로 설명할 때는 "동적 등록과 정적 등록이 공존한다"는 점을 분명히 적어둘 필요가 있다.

## 2.7 UDP 서버 시작

UDP 서버는 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L118)에서 시작한다. 실패 시 프로그램은 즉시 종료한다.

이 선택은 합리적이다. 현재 구조에서 UDP 서버는 다음 두 역할을 동시에 하기 때문이다.

- 기본 SIP 수신 채널
- `SipCore`를 보유한 기준 서버

즉 UDP 시작 실패는 "transport 하나 실패"가 아니라 "코어를 묶는 기준 서버 실패"에 가깝다.

## 2.8 TCP 서버 시작

TCP 서버는 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L125)에서 시작한다.

여기서 중요한 설계 의도는 "TCP 실패가 치명적이지 않다"는 점이다.

```cpp
if (!tcpServer.start(...))
{
    // TCP 시작 실패는 치명적이지 않음 — UDP만으로 동작
}
```

즉 프로젝트는 UDP를 최소 동작 기반으로 보고, TCP는 확장 transport로 붙인다.

이는 운영 관점에서 다음 의미가 있다.

- TCP 포트 충돌이 있어도 서버 전체는 살아 있을 수 있다.
- 기본 시험은 UDP만으로도 가능하다.
- 복잡한 연결형 transport는 선택적으로 얹는 구조다.

## 2.9 TLS 서버 시작

TLS는 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L138) 이후에서 조건부로 시작한다.

활성화 조건은 다음이다.

- `SIPLITE_TLS_ENABLE=1` 또는 `true`
- 인증서 파일 경로 `SIPLITE_TLS_CERT_FILE`
- 개인키 파일 경로 `SIPLITE_TLS_KEY_FILE`

기본 포트는 `5061`이고, `SIPLITE_TLS_PORT`로 바꿀 수 있다.

TLS 시작이 성공하면 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L175)에서 다음 작업을 한다.

- `SipCore`에 TLS용 로컬 주소 등록
- 콘솔 출력으로 TLS 서버 실행 중 표시

이 등록은 단순 표시용이 아니다. 이후 `SipCore`가 `Via`, `Record-Route`, `Contact`를 만들 때 TLS 로컬 주소를 사용하게 된다.

즉 `main.cpp`에서 TLS 서버를 시작하는 행위는 "포트 하나 더 여는 것"과 "SIP 헤더 생성 규칙을 TLS 기준으로 활성화하는 것" 두 가지 의미를 동시에 가진다.

## 2.10 `setSender()`가 하는 일

이 프로젝트에서 가장 중요한 조립 지점 중 하나는 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L186)의 `setSender()` 등록이다.

```cpp
udpServer.sipCore().setSender(
    [&udpServer, &tcpServer, &tlsServer, &tlsStarted](..., TransportType transport) -> bool {
        if (transport == TransportType::TLS) { ... }
        if (transport == TransportType::TCP) { ... }
        return udpServer.sendTo(...);
    });
```

이 구조의 의미는 매우 크다.

- `SipCore`는 직접 네트워크 API를 호출하지 않는다.
- `SipCore`는 목적지 IP/포트와 원하는 `TransportType`만 결정한다.
- 실제 송신 구현은 각 서버 객체가 담당한다.
- transport 선택 정책은 `main.cpp` 조립 레벨에서 결정된다.

책에서는 이 부분을 "의미 계층과 I/O 계층의 분리"의 대표 مثال로 설명하면 좋다.

## 2.11 콘솔 인터페이스

콘솔 인터페이스는 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L219)에서 시작한다.

```cpp
ConsoleInterface console(udpServer, &tcpServer, tlsStarted ? &tlsServer : nullptr);
```

이 호출은 다음 사실을 보여준다.

- 콘솔은 UDP 상태뿐 아니라 TCP/TLS 상태도 볼 수 있다.
- TLS가 켜지지 않은 경우 nullptr로 전달된다.
- 운영 중 상태 조회와 관리 명령은 네트워크 서버 객체를 직접 참조하는 방식으로 구현되어 있다.

책에서는 이 부분을 "운영 인터페이스" 장으로 분리할 수도 있다.

## 2.12 메인 루프와 cleanup

[src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L223) 이후 메인 루프는 단순 sleep 루프가 아니다. 이 루프는 상태 서버의 수명 관리를 담당한다.

매초 수행되는 작업은 다음과 같다.

- `cleanupTimerC()`
- `cleanupExpiredRegistrations()`
- `cleanupExpiredSubscriptions()`
- `cleanupStaleCalls()`
- `cleanupStaleTransactions()`

각 함수의 의미는 다음과 같다.

### `cleanupTimerC()`

forwarded INVITE가 최종 응답 없이 오래 남아 있을 때 caller에게 `408 Request Timeout`, callee에게 `CANCEL`을 보낸다. RFC 3261의 Timer C 개념을 구현한다.

### `cleanupExpiredRegistrations()`

만료된 등록을 정리한다. 정적 등록은 삭제하지 않고 로그인 상태만 해제한다.

### `cleanupExpiredSubscriptions()`

만료된 subscription을 정리하고, 필요하면 `terminated` NOTIFY를 보낸다.

### `cleanupStaleCalls()`

확립되지 않은 오래된 통화나 BYE 이후 정리 대상 통화를 제거한다.

### `cleanupStaleTransactions()`

오래된 pending INVITE 트랜잭션과 관련 상태를 제거한다.

이 메인 루프 때문에 SIPLite는 "패킷이 올 때만 상태가 변하는 프로그램"이 아니라, 시간의 흐름에 따라 내부 상태를 정리하는 살아 있는 서버다.

## 2.13 종료 순서

종료 순서는 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L250) 이후에 나온다.

- 콘솔 중지
- TLS 서버 중지
- TCP 서버 중지
- UDP 서버 중지
- 종료 로그 남김

이 순서도 의도적이다.

- 먼저 사용자 인터페이스를 멈춘다.
- 그다음 연결형 transport를 닫는다.
- 마지막에 기준 서버인 UDP를 닫는다.

특히 TLS를 `tlsStarted` 조건으로 정리하는 부분은 "조건부 시작된 자원만 조건부 정리"하는 안정적인 패턴이다.

## 2.14 `main.cpp`가 보여주는 설계 철학

이 파일 하나만 읽어도 프로젝트의 설계 철학이 드러난다.

### 1. 단일 코어 공유

여러 transport가 하나의 `SipCore`를 공유한다.

### 2. transport는 확장 계층

UDP가 기준이고, TCP/TLS는 그 위에 얹힌다.

### 3. 조립과 의미 분리

`main.cpp`는 서버를 조립하고, `SipCore`는 SIP 의미를 결정한다.

### 4. 장시간 실행 전제

메인 루프와 cleanup이 있다는 것은 이 코드가 장시간 운용을 염두에 둔 서버라는 뜻이다.

## 2.15 이 장의 핵심 정리

`main.cpp`는 단순히 서버를 시작하는 파일이 아니다. 이 프로젝트의 architecture blueprint다.

이 장에서 기억해야 할 핵심은 다음이다.

- `UdpServer`가 기준 서버이며 `SipCore`를 보유한다.
- `TcpServer`와 `TlsServer`는 같은 `SipCore`를 공유한다.
- `setSender()`는 `SipCore`와 transport 구현 사이의 결정적 접점이다.
- 메인 루프는 타이머 기반 상태 정리를 수행한다.

다음 장에서는 UDP, TCP, TLS 세 transport 서버가 실제로 어떤 차이를 가지는지 본다.
