# 19. 로그와 디버깅

## 19.1 이 장의 목적

SIPLite를 실제로 다루다 보면, 가장 먼저 보게 되는 것은 코드가 아니라 로그다. 따라서 이 장은 "코드를 이해한 뒤 로그를 읽는 법"이 아니라, "로그를 통해 코드를 역으로 추적하는 법"을 설명한다.

관련 자료:

- [logs/siplite_20260405_23.txt](/home/windmorning/projects/SIPWorks/SIPLite/logs/siplite_20260405_23.txt)
- [src/Logger.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/Logger.cpp)
- [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L82)

## 19.2 로그는 어디서 시작되는가

[src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L99)에서 `Logger::instance().init("logs", retentionDays)`가 호출된다.

즉 로그는 다음 정보를 기본적으로 갖는다.

- 날짜/시간
- 로그 레벨
- 메시지 본문

그리고 프로젝트 곳곳에서 `Logger::instance().info(...)`, `error(...)`를 통해 각 계층의 이벤트를 기록한다.

## 19.3 로그를 읽을 때 먼저 해야 할 구분

이 프로젝트의 로그는 대략 네 종류로 나눠 읽는 것이 좋다.

### 1. 서버 라이프사이클 로그

- `[UdpServer]`
- `[TcpServer]`
- `[TlsServer]`
- `[Logger]`

### 2. SIP 흐름 로그

- `[handleInvite]`
- `[handleBye]`
- `[handleCancel]`
- `[handleSubscribe]`
- `[handleNotify]`

### 3. 타이머/정리 로그

- `[Timer C]`
- `[Subscription]`

### 4. 오류 로그

- malformed SIP
- socket / SSL / verification 실패
- worker queue overflow

이 네 갈래로 나눠 보면 로그가 훨씬 읽기 쉬워진다.

## 19.4 실제 로그 예제: CANCEL 전달

[logs/siplite_20260405_23.txt](/home/windmorning/projects/SIPWorks/SIPLite/logs/siplite_20260405_23.txt#L1)에는 다음 로그가 보인다.

```text
[handleCancel] CANCEL forwarded to callee: 10.0.0.1:5060 key=inv1:1
```

이 한 줄로 다음 사실을 유추할 수 있다.

- caller의 CANCEL이 정상적으로 transaction에 매칭됐다
- `PendingInvite`가 존재했다
- callee 주소는 `10.0.0.1:5060`
- transaction key는 `Call-ID: inv1`, `CSeq: 1`

즉 이 한 줄은 `handleCancel()`의 정상 경로가 실행됐다는 뜻이다.

## 19.5 실제 로그 예제: BYE 전달

로그 예:

```text
[handleBye] Forwarding BYE: callId=call-bye to=10.0.0.1:5060 contactUri=(none)
```

이 메시지는 다음을 뜻한다.

- 해당 `callId`에 대한 dialog/call 상태가 존재했다
- 상대편에게 BYE가 실제로 포워딩되었다
- Request-URI 재작성에 쓸 Contact URI는 없었다

즉 `contactUri=(none)`는 무조건 오류는 아니다. 단지 dialog에 저장된 remote target이나 callerContact가 비어 있었음을 보여준다.

## 19.6 실제 로그 예제: ACK 상태 확인

로그 예:

```text
[handleAck] ActiveCall found: callId=bye-fwd callerIp=10.0.0.2:5060 calleeIp=10.0.0.1:5060 pktFrom=10.0.0.2:5060
```

이 로그는 디버깅 시 매우 유용하다.

이유:

- ACK가 어떤 call에 매칭됐는지 보여준다
- caller/callee 주소를 보여준다
- 실제 패킷 발신자 주소를 같이 보여준다

즉 ACK source mismatch나 NAT/transport 혼선을 진단할 때 단서가 된다.

## 19.7 실제 로그 예제: subscription 생성과 만료

로그 예:

```text
[handleSubscribe] Subscribed: callId=sub-expire event=presence subscriber=sip:1002@client target=sip:1001@server expires=1
[Subscription] Expired: key=sub-expire
```

이 두 줄을 함께 보면 다음 시퀀스를 재구성할 수 있다.

1. SUBSCRIBE 수신
2. `presence` 이벤트로 subscription 생성
3. `expires=1`로 매우 짧게 저장
4. cleanup 루프에서 만료 탐지

즉 로그만으로도 subscription 수명 주기를 따라갈 수 있다.

## 19.8 실제 로그 예제: NOTIFY 전달

로그 예:

```text
[handleNotify] Forwarded NOTIFY: callId=notify-call to=10.0.0.2:5060
```

이 로그는 다음을 보여준다.

- 해당 `callId`에 subscription이 있었다
- 서버가 notifier와 subscriber를 연결하는 프록시 역할을 수행했다
- NOTIFY가 subscriber 주소로 실제 전달됐다

즉 NOTIFY가 200 OK만 받고 끝난 것이 아니라 실제 fan-out되었는지 확인할 수 있다.

## 19.9 로그와 코드의 매핑

이 프로젝트는 다행히 로그 prefix가 함수 이름과 꽤 잘 대응된다.

예시:

- `[handleBye]` → [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1247)
- `[handleCancel]` → [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1433)
- `[handleSubscribe]` → [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1712)
- `[handleNotify]` → [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L1924)
- `[Timer C]` → [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L535)
- `[Subscription]` → [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L682)

즉 로그를 보고 바로 코드 위치를 역추적할 수 있다. 이는 디버깅 경험을 크게 개선한다.

## 19.10 transport 계층 로그

transport 서버는 각각 자신의 prefix를 가진다.

### UDP

- `[UdpServer] started`
- `[UdpServer] recvLoop started`
- `[UdpServer] Worker N started`
- malformed SIP drop

### TCP

- `[TcpServer] started`
- `[TcpServer] New connection from ...`
- `[TcpServer] Outbound connection to ...`
- buffer overflow / send failure

### TLS

- `[TlsServer] started`
- `[TlsServer] Verification policy: ...`
- `[TlsServer] New TLS connection from ...`
- `SSL_accept failed`
- `SSL_connect failed`
- `SSL_write failed`

즉 transport 문제를 볼 때는 먼저 prefix별로 grep하는 것이 좋다.

## 19.11 TLS 디버깅 포인트

TLS 디버깅은 일반 SIP 로그보다 한 단계 더 복잡하다. 아래 순서로 보는 것이 좋다.

1. `[TlsServer] started`가 있는지
2. verification policy 로그가 어떤지
3. `bind TLS ... 성공`이 있는지
4. inbound connection 로그가 있는지
5. `SSL_accept failed` 여부
6. outbound `SSL_connect failed` 여부
7. `Peer certificate verification failed` 여부

즉 TLS 문제는 SIP routing 이전에 transport/handshake 계층에서 먼저 판별해야 한다.

## 19.12 로그 기반 디버깅 절차

실제 문제를 디버깅할 때 추천하는 절차는 다음과 같다.

### 1. 문제 종류를 정한다

- 등록 문제
- 통화 성립 문제
- 종료 문제
- subscription 문제
- TLS 연결 문제

### 2. 관련 prefix로 로그를 좁힌다

예:

- REGISTER → `handleRegister`
- INVITE → `handleInvite`, `handleResponse`, `Timer C`
- SUBSCRIBE → `handleSubscribe`, `handleNotify`, `Subscription`
- TLS → `TlsServer`

### 3. 로그와 코드 위치를 연결한다

각 prefix는 함수 위치로 거의 바로 이어진다.

### 4. 필요하면 테스트 시나리오와 비교한다

같은 흐름이 [tests](/home/windmorning/projects/SIPWorks/SIPLite/tests)에 있는지 확인하면 좋다.

## 19.13 로그의 현재 한계

현재 로그가 유용하긴 하지만, 다음 한계도 있다.

- `callId`가 없는 로그는 상관관계 추적이 어렵다
- transport 정보가 모든 SIP 로그에 다 들어가 있지는 않다
- transaction key와 dialog state를 더 일관되게 찍을 수 있다
- packet dump는 기본적으로 제한적이다

즉 지금도 충분히 디버깅 가능하지만, 더 structured logging으로 가면 훨씬 좋아질 여지가 있다.

## 19.14 이 장의 핵심 정리

SIPLite의 로그는 단순 출력이 아니라 코드 탐색 도구다.

- prefix가 함수와 잘 연결되고
- 상태 전이와 transport 이벤트가 로그에 남으며
- 실제 문제를 재현했을 때 코드보다 먼저 단서를 준다

즉 이 프로젝트를 이해하고 운영하려면 로그 읽기를 반드시 익혀야 한다.

다음 장에서는 실제로 자주 참조하게 되는 핵심 함수들을 부록 형태로 정리한다.
