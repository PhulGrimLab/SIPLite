# SIPLite Work Progress

작성일: 2026-04-05
대상 경로: `/home/windmorning/projects/SIPWorks/SIPLite`

## 이번 점검 목적

TLS가 "코드가 존재하는 수준"인지, 아니면 실제 SIP 라우팅에 끝까지 반영되는 수준인지 점검했다.

## 점검 결과 요약

- `TlsServer` 자체는 구현되어 있다.
- TLS 리스너 시작, `SSL_accept()`, `SSL_read()`, `SSL_write()` 경로가 존재한다.
- TLS 수신 패킷은 `TransportType::TLS`로 `SipCore`까지 전달된다.
- `Via: SIP/2.0/TLS ...`, `Record-Route: <sips:...;lr>` 생성도 구현돼 있다.

즉, "TLS 서버 및 기본 SIP 처리 경로"는 붙어 있다.

## 발견한 한계

핵심 문제는 transport 상태가 등록/라우팅 모델에 충분히 저장되지 않는 점이었다.

- `Registration`이 `ip`, `port`, `contact`만 저장하고 transport를 저장하지 않음
- `INVITE`/`MESSAGE` 등 포워딩 시 등록 대상이 TLS 단말인지 명시적으로 알 수 없음
- 실제 송신은 `ip:port`에 대해 현재 활성 연결이 있는지만 보고 TLS/TCP/UDP를 선택함
- 따라서 TLS 단말이라도 연결 상태에 따라 UDP/TCP로 떨어질 수 있는 구조임
- outbound TLS 연결 생성 기능은 `TlsServer::sendTo()`에 있으나, 메인 sender가 이를 transport 우선으로 사용하지 않음

정리하면, 기존 상태는 "TLS 수신은 가능하지만 transport-aware 라우팅 모델은 미완성"이었다.

## 이번에 이어서 진행할 구현 방향

1. `Registration`에 transport 저장
2. `PendingInvite`, `ActiveCall`, `Dialog`, `Subscription`에도 상대 transport 저장
3. `SipCore::setSender()` 콜백이 preferred transport를 받도록 확장
4. 메인 sender가 `preferred transport`를 우선 사용하도록 변경
5. TLS 등록 후 INVITE/MESSAGE/NOTIFY/CANCEL/ACK/BYE 라우팅이 transport-aware 하게 유지되도록 보완

## 2026-04-05 추가 진행 사항

- 위 transport-aware 라우팅 모델 구현 완료
- TLS 등록 후 전달 INVITE가 TLS 선호 transport로 송신되는 테스트 추가
- 메인 루프에 `cleanupExpiredSubscriptions()` 연결
- 구독 만료 시 `terminated` NOTIFY도 subscriber transport를 유지하도록 검증 추가
- `buildInviteResponse()`의 고정 `Contact: <sip:server@0.0.0.0:5060>` 제거
- 로컬 transport에 맞춰
  - UDP: `sip:server@IP:PORT`
  - TCP: `sip:server@IP:PORT;transport=tcp`
  - TLS: `sips:server@IP:PORT`
  형식으로 Contact를 생성하도록 보완

## 2026-04-05 AoR 조회 보완

- 등록 조회 로직을 `user` 단독 비교에서 정규화된 `user@domain` 비교로 변경
- 같은 user라도 domain이 다르면 서로 다른 등록으로 취급하도록 수정
- `INVITE`/`MESSAGE`의 등록 조회뿐 아니라 구독 대상 조회와 `notifySubscribers()`도 같은 AoR 기준으로 통일
- 멀티도메인 회귀 테스트 추가:
  - `sip:1001@alpha.example`
  - `sip:1001@beta.example`
  가 동시에 존재할 때 목적지 domain에 맞는 단말로 라우팅되는지 확인
- 존재하지 않는 domain은 같은 user가 다른 domain에 있어도 `404 Not Found`가 유지되는지 확인

## 2026-04-05 TLS 검증 정책 보완

- `TlsServer`에 환경변수 기반 TLS 검증 정책 추가
- 새 환경변수:
  - `SIPLITE_TLS_VERIFY_PEER=0|1`
  - `SIPLITE_TLS_CA_FILE=/path/to/ca.pem`
  - `SIPLITE_TLS_REQUIRE_CLIENT_CERT=0|1`
- outbound TLS는 `verify peer`가 켜진 경우 CA 파일 또는 시스템 CA store 기반으로 certificate chain 검증 수행
- inbound TLS는 `require client cert`가 켜진 경우 client certificate를 필수로 요구
- 기본값은 기존 호환성을 위해 느슨한 정책 유지:
  - peer verify `off`
  - client cert requirement `off`
- 현재 한계도 문서에 명시:
  - hostname verification은 아직 미구현
- `scripts/start_tls.sh`도 새 환경변수를 전달하고 실행 시 표시하도록 갱신

## 2026-04-05 TLS 기본 실행 경로 정리

- `make run`이 기본적으로 TLS 실행 경로를 타도록 변경
- 평문 실행은 `make run_plain`으로 분리
- `scripts/start_tls.sh`가 인증서 파일 부재 시 바로 실패하지 않고 `scripts/ensure_tls_certs.sh`를 통해 self-signed 인증서를 자동 생성
- 기본 자동 생성 값:
  - `CN=127.0.0.1`
  - `SAN IP=127.0.0.1`
  - `SAN DNS=localhost`
- 필요 시 환경변수로 인증서 subject/SAN을 조정 가능:
  - `SIPLITE_TLS_CERT_CN`
  - `SIPLITE_TLS_CERT_SAN_IP`
  - `SIPLITE_TLS_CERT_SAN_DNS`
  - `SIPLITE_TLS_CERT_DAYS`
- 결과적으로 개발 환경에서는 `make all && make run`만으로 TLS 리스너가 바로 올라오는 흐름 확보

## 2026-04-05 XML transport 설정 반영

- `config/terminals.xml`에서 `<transport>` 태그를 읽도록 확장
- 지원 값:
  - `udp`
  - `tcp`
  - `tls`
- `XmlConfigLoader`가 파싱한 transport를 `SipCore::registerTerminal()`에 전달하도록 수정
- 따라서 실제 REGISTER 없이도 XML 기반 정적 등록 단말을 TLS/TCP/UDP로 명시 가능
- 기본 샘플 `config/terminals.xml`은 TLS 테스트 흐름에 맞춰 각 단말을 `tls`로 표기
- 회귀 테스트 추가:
  - transport 파싱 성공
  - 잘못된 transport 값 거부
  - `registerTerminals()` 이후 `Registration.transport` 반영 확인

## 별도 확인 필요 항목

- hostname verification 미구현
- Linphone 실제 TLS 등록/호 설정/종료 상호운용 검증 필요
