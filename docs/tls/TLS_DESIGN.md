# SIPLite TLS Design

작성일: 2026-03-29
대상 경로: `/home/windmorning/projects/SIPWorks/SIPLite`

## 목적

현재 SIPLite는 `UDP(5060)`와 `TCP(5060)` 기반 SIP만 처리한다.
이 문서는 `SIP over TLS`를 `별도 전송 계층`으로 추가하기 위한 설계 초안을 정리한 것이다.

목표는 아래와 같다.

- `TLS(기본 5061)` 리스너 추가
- 기존 `SipCore`는 최대한 재사용
- `UDP/TCP/TLS`를 병행 운영 가능하게 유지
- Linphone 같은 클라이언트가 `transport=tls` 또는 `sips:`로 접속 가능하게 만들기

## 현재 코드 상태

이미 구현된 부분:

- `UdpServer`가 UDP 수신/송신 처리
- `TcpServer`가 TCP 수신/송신 처리
- `SipCore`가 전송 계층 위에서 SIP 로직 처리
- `main.cpp`에서 송신 콜백으로 UDP/TCP 중 적절한 전송 선택

즉 구조상 `TlsServer`를 추가하기 좋은 상태다.

## 권장 아키텍처

전송 계층을 아래처럼 병행한다.

- UDP: `5060`
- TCP: `5060`
- TLS: `5061`

`TlsServer`는 `TcpServer`와 유사한 책임을 가진다.

- TLS 리스닝 소켓 생성
- TLS handshake 수행
- TLS 연결별 수신 버퍼 관리
- `Content-Length` 기반 SIP 메시지 프레이밍
- `SipCore`로 요청/응답 전달
- 활성 TLS 연결이 있으면 해당 연결로 송신

## 데이터 흐름

### 수신

1. 클라이언트가 `TLS`로 접속
2. 서버가 `SSL_accept()` 수행
3. 수신 버퍼에서 완전한 SIP 메시지 추출
4. `UdpPacket` 형태로 변환
5. `pkt.transport = TLS`
6. `SipCore::handlePacket()` 또는 `handleResponse()` 호출

### 송신

1. `SipCore`가 sender 콜백 호출
2. 메인 라우터가 목적지의 활성 연결을 탐색
3. 우선순위:
   - TLS 연결 있으면 `TlsServer::sendTo()`
   - 없으면 TCP 연결 있으면 `TcpServer::sendTo()`
   - 둘 다 없으면 UDP `sendTo()`

## 왜 별도 `TlsServer`인가

`TcpServer` 안에 TLS 모드를 억지로 넣을 수도 있지만, 초기 구현에서는 별도 클래스로 두는 편이 낫다.

이유:

- 평문 TCP와 TLS 상태가 다름
- 연결별로 `SSL*` 관리가 필요함
- handshake, certificate, verification 정책이 TCP와 다름
- 디버깅과 롤백이 쉬움

즉 1차 구현은:

- `TcpServer` 유지
- `TlsServer` 신규 추가

방식이 가장 안전하다.

## OpenSSL 적용 방식

필수 구성요소:

- `SSL_CTX* serverCtx`
- `SSL_CTX* clientCtx`
- 연결별 `SSL*`
- certificate / private key 로드

기본 동작:

- 인바운드 TLS 연결: `SSL_accept()`
- 아웃바운드 TLS 연결: `SSL_connect()`
- 수신: `SSL_read()`
- 송신: `SSL_write()`

## 설정 방식

1차 구현에서는 환경 변수 기반 설정이 가장 단순하다.

권장 변수:

- `SIPLITE_TLS_ENABLE=1`
- `SIPLITE_TLS_PORT=5061`
- `SIPLITE_TLS_CERT_FILE=/path/to/server.crt`
- `SIPLITE_TLS_KEY_FILE=/path/to/server.key`

추가 후보:

- `SIPLITE_TLS_CA_FILE`
- `SIPLITE_TLS_VERIFY_PEER=0|1`
- `SIPLITE_TLS_REQUIRE_CLIENT_CERT=0|1`

## 1차 구현 범위

이번 골격 단계에서 포함할 범위:

- `TlsServer` 클래스 추가
- OpenSSL 초기화 및 인증서 로드
- TLS 리스너 / accept / recv / send 골격
- `main.cpp`에서 선택적으로 TLS 서버 시작
- sender 라우팅에 TLS 우선순위 추가

이번 단계에서 의도적으로 제외하는 범위:

- mutual TLS
- peer certificate 강제 검증
- hostname verification
- certificate hot reload
- OCSP / CRL
- `Record-Route` / `Contact`의 transport 정책 완전 정교화
- TLS 전용 콘솔 관리 명령

## 중요한 설계 이슈

### 1. `SipCore`의 local address 표현

현재 `SipCore`는 사실상 단일 로컬 주소/포트를 기준으로 `Via` / `Record-Route`를 만든다.

문제:

- UDP/TCP/TLS가 동시에 있을 때 transport별 local route를 구분해야 함
- TLS 응답/포워딩에서는 `transport=tls` 또는 `sips:` 정책을 반영해야 함

1차 골격에서는 이 문제를 완전히 해결하지 않는다.
즉 “TLS 수신/송신 골격”까지 넣고, route header 정교화는 2차 작업으로 둔다.

### 2. 인바운드/아웃바운드 TLS 연결 재사용

이상적인 방향:

- 같은 원격 `IP:port`에 대한 기존 TLS 연결 재사용
- 없으면 새 TLS 연결 생성

이는 `TcpServer`와 동일한 방향이지만, TLS는 `SSL*` 상태가 있어 연결 정리가 더 중요하다.

### 3. keepalive / 작은 패킷 처리

현재 TCP 로그에서 보이는 `4 bytes`는 SIP keepalive일 가능성이 있다.
TLS에서도 유사한 패턴이 있을 수 있다.

1차 구현에서는:

- malformed / tiny packet을 조용히 무시
- 추후 keepalive 전용 로깅 완화

방식이 적절하다.

## Linphone 관점 사용 방식

목표 예시:

- Identity: `sip:1001@server`
- Server/Proxy: `sip:server:5061;transport=tls`
- 또는 `sips:1001@server`

Linphone과의 실제 연동을 위해 필요한 조건:

- 서버 인증서가 Linphone에서 신뢰되거나
- 테스트용으로 verification을 완화
- `Record-Route` / `Contact`가 TLS 흐름을 깨지 않도록 정리

## 구현 단계 제안

### Phase 1

- `TlsServer` 골격 구현
- OpenSSL 링크
- 선택적 TLS 리스너 시작
- sender 우선순위에 TLS 추가

### Phase 2

- `SipCore`의 local transport awareness 추가
- `Record-Route` / `Via` / `Contact`에 `transport=tls` 반영
- `sips:` 정책 명확화

### Phase 3

- peer verification
- client certificate 옵션
- 운영용 인증서 관리
- 로그/모니터링 보강

## 위험요소

- 현재 `SipCore`가 transport-aware header 생성 구조가 아님
- TLS outbound connect 정책이 단순하면 일부 UA와 상호운용성이 떨어질 수 있음
- OpenSSL non-blocking I/O 처리에서 `WANT_READ/WANT_WRITE` 처리가 중요함
- 인증서 검증 정책을 느슨하게 시작하면 운영 환경으로 바로 쓰면 안 됨

## 이번 구현 골격의 의미

이번에 추가할 코드는 “운영 완성판 TLS”가 아니라 아래를 위한 기반이다.

- 코드 구조 정착
- 빌드 / 실행 경로 확보
- 인증서 로딩과 handshake 경로 확보
- 이후 `SipCore` transport awareness 보강의 발판 마련

## 수정 대상 파일

예상 대상:

- `docs/tls/TLS_DESIGN.md`
- `include/TlsServer.h`
- `src/TlsServer.cpp`
- `include/UdpPacket.h`
- `src/main.cpp`
- `Makefile`

## 다음 단계

이 문서 다음 작업은 아래 순서가 적절하다.

1. `TlsServer` 골격 클래스 추가
2. `main.cpp`에서 env 기반 선택적 TLS 시작
3. OpenSSL 링크 설정
4. 빌드 확인
5. 그 다음 `SipCore` transport-aware route header 보강
