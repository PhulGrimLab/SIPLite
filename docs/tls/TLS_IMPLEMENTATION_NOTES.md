# TLS Implementation Notes

작성일: 2026-03-29
대상 경로: `/home/windmorning/projects/SIPWorks/SIPLite`

## 이번 단계에서 구현한 내용

이번 단계는 `TlsServer` 골격만 추가하는 수준에서 한 단계 더 진행해서,
`SipCore`가 `TLS transport`를 인지한 헤더를 만들도록 보완한 작업이다.

즉 지금은 아래 2가지가 들어갔다.

- OpenSSL 기반 `TlsServer` 골격
- TLS 수신 요청에 대해 `Via` / `Record-Route` / `Route stripping`이 transport-aware 하게 동작

## 수정된 주요 파일

- `include/TlsServer.h`
- `src/TlsServer.cpp`
- `include/SipCore.h`
- `src/SipCore.cpp`
- `include/UdpPacket.h`
- `src/UdpServer.cpp`
- `src/main.cpp`
- `Makefile`
- `tests/test_sipcore_extended.cpp`

## 1. TlsServer 골격

`TlsServer`는 `TcpServer`와 유사한 구조를 가진 별도 전송 계층이다.

현재 포함된 기능:

- TLS 리스닝 소켓 생성
- OpenSSL 초기화
- 서버 인증서 / 개인키 로드
- 인바운드 `SSL_accept()`
- 아웃바운드 `SSL_connect()`
- `SSL_read()` / `SSL_write()` 기반 송수신
- `Content-Length` 기반 SIP 메시지 프레이밍
- `SipCore`로 요청/응답 전달
- 활성 TLS 연결 재사용

현재 목표는 “TLS 경로를 빌드 및 실행 가능한 상태로 확보”하는 것이다.

## 2. TransportType 확장

기존 `TransportType`은 아래 2개만 있었다.

- `UDP`
- `TCP`

여기에:

- `TLS`

를 추가했다.

파일:

- `include/UdpPacket.h`

이 값은 `TlsServer`에서 수신한 패킷이 `SipCore`로 들어갈 때 사용된다.

## 3. SipCore의 transport-aware 로컬 주소

기존 `SipCore`는 `localAddr_`, `localPort_` 하나만 가지고 있어서,
수신 transport가 무엇이든 `Via` / `Record-Route` 생성에 같은 주소를 사용했다.

이번 단계에서는 transport별 로컬 주소를 따로 갖도록 바꿨다.

추가된 구조:

- `udpLocal_`
- `tcpLocal_`
- `tlsLocal_`

파일:

- `include/SipCore.h`

추가된 공개 메서드:

- `setLocalAddressForTransport(TransportType transport, const std::string& ip, uint16_t port)`

이 메서드로:

- UDP는 `5060`
- TCP는 `5060`
- TLS는 `5061`

같이 transport별 주소를 분리 저장할 수 있게 했다.

## 4. TLS용 Via 생성

기존 `addProxyVia()`는 항상:

```text
Via: SIP/2.0/UDP ...
```

형태를 만들었다.

이제는 수신 transport에 따라 아래처럼 바뀐다.

- UDP 요청이면 `SIP/2.0/UDP`
- TCP 요청이면 `SIP/2.0/TCP`
- TLS 요청이면 `SIP/2.0/TLS`

파일:

- `src/SipCore.cpp`

변경된 함수:

- `addProxyVia(const std::string&, TransportType)`

## 5. TLS용 Record-Route 생성

기존 `addRecordRoute()`는 항상:

```text
Record-Route: <sip:IP:PORT;lr>
```

를 넣었다.

이제 transport에 따라 아래처럼 동작한다.

- UDP: `Record-Route: <sip:IP:PORT;lr>`
- TCP: `Record-Route: <sip:IP:PORT;transport=tcp;lr>`
- TLS: `Record-Route: <sips:IP:PORT;lr>`

파일:

- `src/SipCore.cpp`

변경된 함수:

- `addRecordRoute(const std::string&, TransportType)`

TLS에서 `sips:`를 사용한 이유는,
후속 in-dialog 요청이 보안 경로를 유지하도록 route set에 반영하기 위해서다.

## 6. Route stripping도 transport-aware 처리

기존 `stripOwnRoute()`는 단일 자기 주소만 보고 `Route`를 제거했다.

이제는 transport별 자기 주소와 함께 아래 패턴도 같이 본다.

- `sip:IP:PORT`
- `sips:IP:PORT`
- `IP:PORT`

즉 TLS 요청에서 자신을 가리키는 `sips:` route가 와도 제거 가능하다.

파일:

- `src/SipCore.cpp`

변경된 함수:

- `stripOwnRoute(const std::string&, TransportType)`

## 7. TLS transport-aware 함수 호출 지점

아래 흐름들에서 transport-aware helper를 쓰도록 바꿨다.

- `INVITE` forwarding
- `ACK` forwarding
- `BYE` forwarding
- in-dialog `MESSAGE` forwarding
- `NOTIFY` forwarding

즉 `pkt.transport`가 `TLS`이면, 동일 dialog의 후속 포워딩에서도 TLS용 헤더 형식이 유지된다.

## 8. main.cpp에서 TLS 로컬 포트 반영

TLS 서버가 성공적으로 시작되면:

- `udpServer.sipCore().setLocalAddressForTransport(TransportType::TLS, ..., tlsPort)`

를 호출하도록 했다.

이 덕분에 TLS 수신 요청을 포워딩할 때 `5061` 기준 헤더를 만들 수 있다.

주의:

- `bindIp`가 `0.0.0.0`이면 기존 transport별 실제 로컬 IP를 유지하고 포트만 바꾸도록 처리했다.

## 9. 테스트 추가

새 테스트를 추가했다.

- `TLS INVITE forwarding uses TLS Via and SIPS Record-Route`

파일:

- `tests/test_sipcore_extended.cpp`

이 테스트는:

- 입력 transport를 `TLS`로 설정한 INVITE를 `SipCore`에 전달
- 포워딩된 INVITE에
  - `Via: SIP/2.0/TLS ...`
  - `Record-Route: <sips:...>`
  가 포함되는지 검증한다.

## 10. 현재 상태의 의미

지금 코드는 “TLS를 인식하는 헤더를 만들기 시작한 상태”다.

즉 아래까지는 됐다.

- TLS 소켓 경로 존재
- TLS 패킷이 `SipCore`로 전달됨
- TLS 요청 포워딩 시 `Via` / `Record-Route`가 TLS-aware

하지만 아직 남은 핵심도 있다.

## 아직 남은 작업

### 1. 응답/Contact 정책 정교화

현재는 주요 forwarding path는 보강됐지만,
모든 응답/Contact 생성이 완전히 transport-aware 한 것은 아니다.

특히 아래는 추가 검토가 필요하다.

- `Contact` 생성 정책
- `NOTIFY`의 Via/route 정책
- 서버가 능동적으로 만드는 일부 요청의 transport 결정

### 2. TLS 연결 우선 정책 검증

현재 sender 라우팅은:

- TLS 연결 있으면 TLS
- 없으면 TCP
- 없으면 UDP

순서다.

이 정책이 모든 dialog에서 올바른지 Linphone 실제 상호운용 테스트가 더 필요하다.

### 3. 인증서 검증 강화

현재 `TlsServer`는 골격 단계이므로:

- client side verify 기본 미적용
- mutual TLS 미지원
- hostname verify 미구현

운영용 보안 수준으로 보기는 이르다.

### 4. keepalive / tiny packet 로그 정리

TLS/TCP에서 작은 패킷이나 keepalive가 들어올 수 있는데,
현재는 일부가 “packet too small” 로그로 남을 수 있다.

향후에는:

- keepalive 감지
- noisy log 완화

를 넣는 편이 좋다.

## 빌드/검증 결과

이번 단계는 아래로 확인했다.

```bash
make all
make test_all
```

2026-03-29 기준 전체 테스트 통과.

## 다음 권장 작업

다음 단계는 아래 순서가 적절하다.

1. Linphone 실제 TLS REGISTER / INVITE / BYE 테스트
2. TLS 응답/Contact 경로 추가 보강
3. 인증서 검증 정책 정리
4. 필요하면 `sips:` 강제 정책 설계
