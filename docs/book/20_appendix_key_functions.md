# 20. 부록: 핵심 함수 인덱스

## 20.1 이 장의 목적

책을 읽고 실제 코드로 들어갈 때, 결국 자주 다시 찾게 되는 함수들이 있다. 이 장은 그 함수들을 "역할별 빠른 인덱스"로 정리한 부록이다.

이 장은 설명보다 참조용 성격이 강하다. 즉 독자가 "그 함수가 어디 있었지?"라고 생각할 때 가장 먼저 보는 장이 되도록 구성한다.

## 20.2 프로그램 시작과 조립

### `main`

- 위치: [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L56)
- 역할: 전체 서버 조립, TLS 조건부 시작, sender 등록, cleanup 루프

### `checkSignal`

- 위치: [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L35)
- 역할: 시그널 수신 상태를 메인 루프 종료 플래그로 반영

## 20.3 transport 서버 시작점

### `UdpServer::start`

- 위치: [src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp#L112)
- 역할: UDP 소켓 준비, 워커 큐 생성, 로컬 주소 추정, recv/worker 스레드 시작

### `TcpServer::start`

- 위치: [src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp#L115)
- 역할: TCP 리스닝 소켓, epoll, worker 스레드 시작

### `TlsServer::start`

- 위치: [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L300)
- 역할: OpenSSL 초기화, 인증서 로딩, TLS 리스너 시작, worker 스레드 시작

### `TlsServer::sendTo`

- 위치: [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L1030)
- 역할: outbound TLS 연결 생성/재사용, `SSL_write()` 기반 송신

## 20.4 파싱 계층

### `parseSipMessage`

- 위치: [src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp#L9)
- 역할: raw SIP 문자열을 `SipMessage`로 변환

중요 포인트:

- request/response 판별
- compact header 확장
- `Content-Length` 검증
- 크기 제한 검사

## 20.5 `SipCore` 진입점

### `SipCore::handlePacket`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L174)
- 역할: 요청 공통 검증 후 메서드별 분기

### `SipCore::handleResponse`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L343)
- 역할: callee 응답을 caller 방향으로 전달하고 transaction/dialog 상태 갱신

## 20.6 REGISTER 관련

### `SipCore::handleRegister`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L623)
- 역할: REGISTER 처리, XML 허용 단말 확인, Digest 인증, registration 갱신

### `SipCore::buildRegisterOk`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2628)
- 역할: REGISTER 성공 응답 생성

### `SipCore::buildRegisterAuthChallenge`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2679)
- 역할: `401 Unauthorized` + `WWW-Authenticate` 생성

## 20.7 INVITE / 통화 제어 관련

### `SipCore::handleInvite`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L900)
- 역할: 등록 조회, `100 Trying`, INVITE 포워딩, `ActiveCall`/`PendingInvite` 생성

### `SipCore::handleAck`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1152)
- 역할: 통화 confirmed 처리, ACK 포워딩

### `SipCore::handleBye`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1247)
- 역할: BYE 포워딩, cross-BYE 처리, call/dialog 정리

### `SipCore::handleCancel`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1433)
- 역할: pending INVITE 취소, callee 방향 CANCEL 생성/전달

### `SipCore::buildAckForPending`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2474)
- 역할: pending INVITE 문맥을 기반으로 ACK 생성

### `SipCore::buildCancelForPending`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2539)
- 역할: pending INVITE 문맥을 기반으로 CANCEL 생성

## 20.8 MESSAGE / 구독 관련

### `SipCore::handleMessage`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1583)
- 역할: out-of-dialog / in-dialog MESSAGE 포워딩

### `SipCore::handleSubscribe`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1712)
- 역할: subscription 생성/refresh/unsubscribe, initial NOTIFY

### `SipCore::handleNotify`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1924)
- 역할: NOTIFY 검증, subscription 상태 갱신, subscriber 방향 포워딩

### `SipCore::buildNotify`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2008)
- 역할: 서버가 생성하는 NOTIFY 메시지 구성

## 20.9 SIP 헤더 재작성 관련

### `SipCore::addProxyVia`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2226)
- 역할: 프록시 top Via 추가

### `SipCore::addRecordRoute`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2300)
- 역할: in-dialog 요청이 프록시를 경유하도록 `Record-Route` 추가

### `SipCore::stripOwnRoute`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2345)
- 역할: 자신을 가리키는 Route 제거

### `SipCore::rewriteRequestUri`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp) 내부 구현
- 역할: 목적 Contact로 Request-URI 재작성

### `SipCore::buildLocalContactHeader`

- 위치: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2653)
- 역할: transport-aware Contact 헤더 생성

## 20.10 타이머와 정리 함수

### `cleanupTimerC`

- 위치: [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L535)
- 역할: INVITE timeout 시 `408` + `CANCEL`

### `cleanupExpiredRegistrations`

- 위치: [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L375)
- 역할: registration 만료 정리

### `cleanupExpiredSubscriptions`

- 위치: [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L682)
- 역할: subscription 만료 정리 + terminated NOTIFY

### `cleanupStaleCalls`

- 위치: [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L410)
- 역할: 오래된 미확정 call / BYE 후 call 정리

### `cleanupStaleTransactions`

- 위치: [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L473)
- 역할: 오래된 pending INVITE transaction 정리

## 20.11 설정과 운영 관련

### `XmlConfigLoader::loadTerminals`

- 위치: [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h#L50)
- 역할: XML 설정 파일을 읽어 `TerminalConfig` 목록 생성

### `XmlConfigLoader::registerTerminals`

- 위치: [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h#L209)
- 역할: 설정 목록을 `SipCore` 정적 등록 상태로 반영

### `ConsoleInterface::showServerStatus`

- 위치: [src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp#L266)
- 역할: 운영자가 보는 서버 상태 요약 출력

### `ConsoleInterface::showRegisteredTerminals`

- 위치: [src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp#L331)
- 역할: 등록 단말과 상태 목록 출력

## 20.12 TLS 디버깅에 중요한 함수

### `TlsServer::initializeSsl`

- 위치: [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L177)
- 역할: OpenSSL 컨텍스트 초기화, 인증서/키 로딩

### `TlsServer::configureVerification`

- 위치: [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L236)
- 역할: peer verification, client cert requirement 설정

### `TlsServer::extractSipMessage`

- 위치: [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L682)
- 역할: TLS stream에서 SIP 메시지 단위 추출

## 20.13 최소 독해 세트

시간이 없을 때 최소한 읽어야 할 함수 세트는 다음이다.

1. [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L56)
2. [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L174)
3. [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L623)
4. [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L900)
5. [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L343)
6. [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp#L300)
7. [src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp#L9)

이 정도만 읽어도 이 프로젝트의 중심 구조는 거의 파악할 수 있다.

## 20.14 이 장의 핵심 정리

이 부록은 책의 마지막에 두지만, 실제 사용 빈도는 높을 가능성이 크다.

코드를 읽다가 길을 잃으면, 이 장에서 함수 이름과 역할을 먼저 다시 확인한 뒤 해당 파일로 돌아가는 방식이 가장 효율적이다.
