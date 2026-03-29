# SIPLite Work Progress

작성일: 2026-03-29
대상 경로: `/home/windmorning/projects/SIPWorks/SIPLite`

## 목적

이 문서는 2026-03-29까지 진행한 구현과 확인 결과를 한 번에 이어서 볼 수 있도록 남긴 작업 기록이다.
다음 작업 시 이 문서와 `REVIEW.md`, `docs/tls/` 문서를 같이 보면 된다.

## 이번까지 완료한 작업

### 1. 기존 코드 상태 점검

- `REVIEW.md` 기준으로 SIPLite의 현재 범위를 다시 확인했다.
- 초기 상태는 `UDP SIP 프록시/레지스트라` 중심 구현이었고, 운영 관점에서 인증/다이얼로그 검증/TLS가 부족한 상태였다.

관련 문서:

- `REVIEW.md`

### 2. REGISTER Digest 인증 추가

구현 내용:

- `REGISTER`에 선택적 SIP Digest 인증 추가
- 단말에 비밀번호가 설정된 경우만 `401 Unauthorized` + `WWW-Authenticate` 챌린지 수행
- `Authorization: Digest ...` 검증 성공 시에만 등록 허용
- XML에서 단말별 `<password>` 로드 지원

동작 정책:

- 비밀번호 없음: 기존처럼 인증 없이 `REGISTER`
- 비밀번호 있음: Digest 인증 필수

관련 파일:

- `include/SipCore.h`
- `src/SipCore.cpp`
- `include/SipUtils.h`
- `src/SipUtils.cpp`
- `include/XmlConfigLoader.h`
- `tests/test_sipcore.cpp`
- `REGISTER_DIGEST_AUTH.md`

### 3. 혼합 전송(UDP/TCP) 다이얼로그 처리 보완

발견한 문제:

- 한 단말이 `REGISTER`는 TCP, `ACK/BYE`는 UDP처럼 섞어서 보내면
  기존 로직이 `IP:port`만 보고 caller/callee를 판별해서 BYE를 잘못된 방향으로 전달했다.
- 그 결과 상대방이 통화 종료 알림을 받지 못하고 `481`이 발생할 수 있었다.

수정 내용:

- `ACK`, `BYE`, in-dialog `MESSAGE` 발신자 판별을 `IP:port` 단독 기준이 아니라
  `Call-ID + From/To tag`를 우선으로 보도록 보완
- caller 소스 포트가 바뀌거나 transport가 달라져도 동일 dialog로 인식하도록 개선

관련 파일:

- `include/SipCore.h`
- `src/SipCore.cpp`
- `tests/test_sipcore_extended.cpp`

결과:

- Linphone 간 통화에서 `1002 종료 -> 1001이 종료 인지 못함` 현상 원인이 이 취약점과 일치함을 확인
- 수정 후 정상 동작하는 것으로 재확인

### 4. TLS 설계 문서 작성

작성 내용:

- `UDP 5060`, `TCP 5060`, `TLS 5061` 병행 구조 제안
- 별도 `TlsServer` 도입 이유
- OpenSSL 적용 방식
- 환경 변수 기반 실행 방식
- 단계별 구현 계획

관련 문서:

- `docs/tls/TLS_DESIGN.md`

### 5. OpenSSL 기반 TlsServer 골격 구현

구현 내용:

- `TlsServer` 클래스 추가
- OpenSSL 초기화
- 인증서/개인키 로드
- TLS 리스너 및 `SSL_accept()`
- outbound `SSL_connect()`
- `SSL_read()` / `SSL_write()` 기반 송수신
- SIP `Content-Length` 기반 메시지 프레이밍
- 활성 TLS 연결 재사용
- `main.cpp`에서 선택적으로 TLS 서버 시작
- 송신 우선순위를 `TLS -> TCP -> UDP`로 설정

관련 파일:

- `include/TlsServer.h`
- `src/TlsServer.cpp`
- `src/main.cpp`
- `Makefile`
- `include/UdpPacket.h`

주의:

- 현재 단계는 운영 완성판이 아니라 `TLS 동작 경로를 확보한 골격`이다.

### 6. TLS transport-aware 헤더 처리 구현

구현 내용:

- `TransportType`에 `TLS` 추가
- `SipCore`가 transport별 로컬 주소를 따로 보관하도록 구조 변경
- TLS 수신 요청 포워딩 시:
  - `Via: SIP/2.0/TLS ...`
  - `Record-Route: <sips:IP:PORT;lr>`
  생성
- self route 제거 시 `sip:` / `sips:` 패턴 둘 다 처리
- `INVITE`, `ACK`, `BYE`, in-dialog `MESSAGE`, `NOTIFY` 경로에서 transport-aware helper 사용

관련 파일:

- `include/SipCore.h`
- `src/SipCore.cpp`
- `src/UdpServer.cpp`
- `src/main.cpp`
- `tests/test_sipcore_extended.cpp`

관련 문서:

- `docs/tls/TLS_IMPLEMENTATION_NOTES.md`

### 7. TLS 실행용 설정 파일과 시작 스크립트 추가

추가한 파일:

- `certs/openssl-san.cnf`
- `scripts/start_tls.sh`

역할:

- `openssl-san.cnf`
  - self-signed 테스트 인증서 생성용 OpenSSL 설정
  - `subjectAltName`에 IP/DNS를 넣을 수 있게 구성
- `start_tls.sh`
  - TLS 환경변수를 자동 설정
  - 기본 인증서 경로와 포트를 적용
  - 바이너리/인증서/키 존재 여부 확인 후 서버 시작

## 현재 실행 방법

### 1. 인증서 생성

`certs/openssl-san.cnf`의 `CN`, `IP.1`, `DNS.1` 값을 실제 서버 주소에 맞춘 후:

```bash
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout /home/windmorning/projects/SIPWorks/SIPLite/certs/server.key \
  -out /home/windmorning/projects/SIPWorks/SIPLite/certs/server.crt \
  -days 365 \
  -config /home/windmorning/projects/SIPWorks/SIPLite/certs/openssl-san.cnf \
  -extensions v3_req
```

### 2. TLS 서버 시작

```bash
cd /home/windmorning/projects/SIPWorks/SIPLite
./scripts/start_tls.sh
```

기본값:

- 인증서: `certs/server.crt`
- 개인키: `certs/server.key`
- TLS 포트: `5061`

필요시 아래처럼 덮어쓸 수 있다.

```bash
SIPLITE_TLS_PORT=5071 \
SIPLITE_TLS_CERT_FILE=/path/to/other.crt \
SIPLITE_TLS_KEY_FILE=/path/to/other.key \
./scripts/start_tls.sh
```

### 3. Linphone 설정 기준

권장 예시:

- Identity: `sip:1001@192.168.0.23`
- Proxy: `sip:192.168.0.23:5061;transport=tls`
- Transport: `TLS`
- Password: XML에 설정한 `<password>`

주의:

- self-signed 인증서 사용 시 Linphone 쪽에서 인증서 신뢰 설정이 필요할 수 있다.

## 검증 결과

확인한 항목:

- `make all` 통과
- `make test_all` 통과
- mixed UDP/TCP dialog 관련 회귀 테스트 추가 후 통과
- TLS `Via` / `Record-Route` 헤더 테스트 추가 후 통과

## 현재 남아 있는 작업

우선순위 기준:

1. `Contact` 및 일부 응답 생성 로직을 transport-aware 하게 더 정교화
2. Linphone 실제 TLS 등록/호 설정/종료 시나리오 검증
3. TLS 인증서 검증 정책 정리
4. AoR 조회를 전체 `user@domain` 기준으로 변경
5. `cleanupExpiredSubscriptions()` 메인 루프 연결
6. `Via/Route/Contact` 파서 구조화

## 다음에 다시 시작할 때 먼저 볼 것

1. `docs/WORK_PROGRESS_2026-03-29.md`
2. `docs/tls/TLS_IMPLEMENTATION_NOTES.md`
3. `docs/tls/TLS_DESIGN.md`
4. `REVIEW.md`

## 메모

- 현재 TLS는 "기본 경로 확보 + transport-aware header 1차 반영" 상태다.
- Linphone 테스트는 `UDP/TCP/TLS`를 섞지 말고 먼저 `TLS only`로 보는 것이 안전하다.
- self-signed 인증서는 테스트용으로만 적합하다.
