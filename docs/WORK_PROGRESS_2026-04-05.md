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

## 별도 확인 필요 항목

- `buildInviteResponse()`의 `Contact`는 아직 `sip:server@0.0.0.0:5060` 고정 값이므로 추후 transport-aware 보완 필요
- TLS 클라이언트 인증서 검증은 아직 `SSL_VERIFY_NONE` 상태
- 메인 루프에 `cleanupExpiredSubscriptions()` 연결은 여전히 필요
