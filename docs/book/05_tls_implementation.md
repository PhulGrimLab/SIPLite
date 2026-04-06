# 5. TLS 구현 분석

## 5.1 이 장의 목적

SIPLite의 TLS는 프로젝트 이해에서 매우 중요한 주제다. 이유는 간단하다. 많은 SIP 예제 프로젝트는 `sips:` 문자열을 허용하거나 문서상으로만 TLS를 언급하지만, 실제 transport-aware TLS를 끝까지 구현하지는 않는다.

현재 SIPLite는 그보다 한 단계 더 나간다.

- TLS 리스너가 있다.
- OpenSSL 기반 handshake가 있다.
- outbound TLS 연결이 있다.
- 인증서 검증 정책이 있다.
- `SipCore`가 TLS를 transport 의미로 인식한다.
- 테스트에서 TLS registration과 TLS header 처리를 검증한다.

즉 이 장은 "TLS가 있는가"가 아니라 "TLS가 코드 구조와 SIP semantics 안에 어디까지 연결되어 있는가"를 설명하는 장이다.

## 5.2 관련 파일

핵심 파일은 아래 네 개다.

- [include/TlsServer.h](/home/windmorning/projects/SIPWorks/SIPLite/include/TlsServer.h)
- [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)
- [docs/tls/TLS_DESIGN.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/tls/TLS_DESIGN.md)
- [docs/tls/TLS_IMPLEMENTATION_NOTES.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/tls/TLS_IMPLEMENTATION_NOTES.md)

실행과 인증서 준비는 아래 파일이 보조한다.

- [scripts/start_tls.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/start_tls.sh)
- [scripts/ensure_tls_certs.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/ensure_tls_certs.sh)
- [certs/server.crt](/home/windmorning/projects/SIPWorks/SIPLite/certs/server.crt)
- [certs/server.key](/home/windmorning/projects/SIPWorks/SIPLite/certs/server.key)

## 5.3 빌드 관점에서 본 TLS

먼저 TLS는 빌드 시스템 수준에서 실구현임이 드러난다.

[Makefile](/home/windmorning/projects/SIPWorks/SIPLite/Makefile)에는 다음 요소가 있다.

- `pkg-config --cflags openssl`
- `pkg-config --libs openssl`
- `/usr/include/openssl/err.h` 존재 여부 검사

즉 빌드 시점부터 OpenSSL이 필수 의존성으로 묶여 있다. 문서에만 TLS가 있는 프로젝트와 분명히 다른 지점이다.

## 5.4 TLS 서버의 큰 구조

`TlsServer`는 [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L133)에서 시작한다.

개념적으로는 다음 계층으로 나눌 수 있다.

1. OpenSSL 컨텍스트 초기화 계층
2. 리스닝 소켓과 `epoll` 기반 이벤트 계층
3. inbound connection 관리 계층
4. outbound connection 재사용 계층
5. SIP 메시지 framing 계층
6. `SipCore` 전달 계층

즉 `TlsServer`는 "TCP 서버 + 보안 handshake + 검증 정책" 구조로 읽는 것이 가장 정확하다.

## 5.5 OpenSSL 초기화

[src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L177)의 `initializeSsl()`이 시작점이다.

이 함수가 수행하는 작업은 다음과 같다.

- `SSL_load_error_strings()`
- `OpenSSL_add_ssl_algorithms()`
- 환경변수 기반 검증 정책 로딩
- server용 `SSL_CTX`
- client용 `SSL_CTX`
- 최소 TLS 버전 1.2 설정
- 서버 인증서 로딩
- 개인키 로딩
- 인증서/개인키 일치 검증
- verify 정책 적용

여기서 중요한 점은 `serverCtx_`와 `clientCtx_`를 둘 다 가진다는 점이다. 이는 이 TLS 계층이 "수신만 하는 서버"가 아니라, outbound TLS도 수행한다는 뜻이다.

## 5.6 검증 정책

검증 정책은 [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L236)의 `configureVerification()`에 모인다.

기본 구조는 다음과 같다.

- outbound verification: `clientCtx_`
- inbound client certificate requirement: `serverCtx_`

정책 분기는 아래 환경변수로 제어된다.

- `SIPLITE_TLS_VERIFY_PEER`
- `SIPLITE_TLS_REQUIRE_CLIENT_CERT`
- `SIPLITE_TLS_CA_FILE`

### outbound verification

`verifyPeer`가 켜지면:

- CA 파일 또는 시스템 기본 CA 경로를 로드
- `SSL_CTX_set_verify(clientCtx_, SSL_VERIFY_PEER, nullptr)` 적용

### inbound client cert

`requireClientCert`가 켜지면:

- server context에 CA store 로드
- `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT` 적용

이 구조는 개발 모드와 운영 모드를 유연하게 분리하기 위한 선택으로 읽을 수 있다.

## 5.7 hostname / IP 검증의 현재 상태

현재 구현은 certificate chain 검증만 있는 것이 아니라, outbound connect 시 대상 IP 이름 검증도 일부 수행한다.

[src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L630) 부근을 보면 `X509_VERIFY_PARAM_set1_ip_asc(...)`를 사용한다. 즉 최소한 IP 기반 검증 경로는 구현돼 있다.

다만 코드와 기존 문서를 함께 보면 일반적인 DNS hostname 검증은 여전히 제한적이거나 별도 보강 대상로 보는 편이 안전하다. 책에서는 "TLS 검증이 존재한다"와 "운영 수준의 모든 검증 시나리오가 완결되었다"를 구분해서 써야 한다.

## 5.8 TLS 서버 시작

[src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L300)의 `start()`는 다음 단계를 수행한다.

1. 이미 실행 중인지 확인
2. worker 큐 준비
3. `initializeSsl()` 호출
4. `bindSocket()` 호출
5. 수신 스레드 시작
6. 워커 스레드 시작

여기서 핵심은 TLS 소켓 준비 전에 SSL 초기화를 완료한다는 점이다. 실패 시 상태를 되돌리고 `cleanupSsl()`까지 수행한다.

즉 `TlsServer::start()`는 partially initialized state를 최소화하려는 구조다.

## 5.9 inbound TLS handshake

수신 경로에서 가장 중요한 지점은 `SSL_accept()`다. [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L821) 부근에서 실제 handshake가 수행된다.

의미는 다음과 같다.

- TCP accept 이후 곧바로 SSL 객체를 붙인다.
- handshake 성공 시에만 TLS 연결로 인정한다.
- 실패하면 연결을 정리하고 로그를 남긴다.

이 구조는 당연해 보이지만, SIP 계층 관점에서는 중요하다. handshake가 성공한 연결만 `TransportType::TLS`의 의미를 가진다.

## 5.10 TLS 수신 후 SIP 메시지 추출

TLS는 스트림 기반이므로 TCP와 동일하게 메시지 framing이 필요하다.

[src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L682)의 `extractSipMessage()`는 수신 버퍼에서 SIP 메시지를 잘라낸다. 이후 [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L898)에서 `SSL_read()`로 받은 바이트를 누적하고, 반복적으로 메시지를 뽑아낸다.

그리고 가장 중요한 줄이 [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L933)에 있다.

```cpp
pkt.transport = TransportType::TLS;
```

이 줄 때문에 TLS는 단순 수신 채널이 아니라 `SipCore` 상태 모델로 transport 의미를 전달하는 계층이 된다.

## 5.11 outbound TLS 연결

TLS의 진짜 구현 여부를 가르는 기준 중 하나는 outbound connect 경로다.

SIPLite는 [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L640) 부근에서 `SSL_connect()`를 수행한다. 이는 서버가 필요할 때 상대 peer로 TLS 연결을 능동적으로 열 수 있다는 뜻이다.

책에서는 이 부분을 분명히 적어두는 것이 좋다.

- inbound TLS만 지원하는 서버가 아니다.
- outbound TLS 송신 경로도 구현되어 있다.
- 따라서 TLS registration 이후 실제 전달 INVITE나 NOTIFY가 TLS 경로를 탈 수 있다.

## 5.12 `sendTo()`와 연결 재사용

[src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L1030)의 `TlsServer::sendTo()`는 이 transport 계층의 실제 가치가 드러나는 지점이다.

이 함수는 대략 다음 일을 한다.

1. 기존 outbound connection 존재 여부 확인
2. 없으면 새 TCP 소켓 생성
3. TLS client `SSL*` 준비
4. 필요 시 peer 검증 파라미터 설정
5. `SSL_connect()` 수행
6. 연결 테이블에 저장
7. `SSL_write()`로 데이터 전송
8. 실패 시 연결 제거

즉 `TlsServer::sendTo()`는 단순 `send()` wrapper가 아니라, TLS outbound session manager 역할을 한다.

## 5.13 TLS와 `SipCore`의 연결

TLS가 프로젝트 구조 안에서 진짜 의미를 가지는 지점은 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L186)의 sender 등록과 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2223) 이후의 transport-aware 헤더 생성이다.

### `main.cpp`

`TransportType::TLS` 요청이 오면 `TlsServer::sendTo()`를 호출한다.

### `SipCore`

transport가 TLS면:

- `Via: SIP/2.0/TLS ...`
- `Record-Route: <sips:...;lr>`
- `Contact: <sips:server@...>`

를 생성한다.

즉 네트워크 계층과 SIP 헤더 계층이 서로 연결되어 TLS 의미가 완성된다.

## 5.14 테스트가 보여주는 TLS 완성도

TLS 구현을 설명할 때 테스트를 꼭 인용해야 한다. 현재 프로젝트에서는 특히 [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp)가 중요하다.

대표적인 검증:

- TLS registration이 저장 시 `Registration.transport == TLS`인지 확인: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L638)
- 이후 forwarded INVITE가 실제로 `TransportType::TLS`로 전송되는지 확인: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L664)
- 구독 만료 NOTIFY가 subscriber transport를 보존하는지 확인: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L805)

즉 TLS는 단순 실행 가능 수준이 아니라, 상태 저장과 라우팅 일관성까지 테스트로 방어되고 있다.

## 5.15 현재 TLS 구현의 강점

현재 코드 기준 장점은 다음과 같다.

- OpenSSL이 실제로 연결돼 있다.
- inbound / outbound 모두 구현돼 있다.
- 환경변수 기반 검증 정책이 있다.
- SIP 헤더 생성이 TLS transport-aware 하다.
- registration과 subscription transport가 상태 모델에 저장된다.
- 테스트가 존재한다.

이 정도면 "TLS 지원"이라고 문서에 적어도 무리가 없는 수준이다.

## 5.16 현재 TLS 구현의 남은 주제

동시에 책에는 한계도 함께 적는 것이 좋다.

- 운영 환경에서의 상호운용 검증은 코드 존재와 별개 문제다.
- hostname verification 범위는 더 엄밀히 재검토할 필요가 있다.
- TCP와 TLS 코드 중복이 적지 않으므로 구조 정리가 장기적으로 필요하다.
- 장시간 연결 유지, 재연결, half-close, peer 인증서 정책은 실제 운용 로그와 함께 추가 검토할 가치가 있다.

## 5.17 이 장의 핵심 정리

SIPLite의 TLS는 "이름만 TLS"가 아니다.

- 실제 TLS 리스너가 있고
- 실제 handshake가 있고
- 실제 outbound TLS가 있고
- 실제 SIP transport 의미가 TLS에 맞게 바뀐다

즉 이 프로젝트의 TLS는 transport layer, state model, header generation, tests가 서로 연결된 구현이다.

다음 장에서는 이제 TLS만 떼어놓지 말고, 전체 상태 모델이 어떻게 조직되는지 본다.
