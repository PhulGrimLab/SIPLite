# 17. 시퀀스 다이어그램

## 17.1 이 장의 목적

앞선 장들에서 구조와 코드를 자세히 설명했지만, SIP는 결국 "누가 누구에게 어떤 순서로 무엇을 보냈는가"가 중요하다. 이 장은 그 흐름을 텍스트 기반 시퀀스 다이어그램으로 정리한다.

등장 주체는 주로 아래와 같다.

- `Caller`
- `Proxy(SIPLite)`
- `Callee`
- 필요 시 `Subscriber`, `Notifier`

여기서 `Proxy(SIPLite)`는 내부적으로는 `UdpServer/TcpServer/TlsServer + SipCore` 조합이지만, 시퀀스 이해를 위해 하나의 논리 주체로 묶어서 표현한다.

## 17.2 REGISTER 기본 흐름

이 장의 시퀀스 다이어그램은 "전체 흐름을 빠르게 보는 것"을 목표로 한다. 따라서 각 다이어그램은 세부 예외 분기보다 핵심 메시지 순서에 집중하고, 코드 참조는 관련 handler와 helper 몇 개만 붙이는 편이 가장 읽기 좋다.

```text
Client                         Proxy(SIPLite)
  |                                  |
  | REGISTER                         |
  |--------------------------------->|
  |                                  | To/Contact 확인
  |                                  | XML 사전 등록 단말 확인
  |                                  | Expires 파싱
  |                                  | Registration 저장/갱신
  |                                  |
  | 200 OK                           |
  |<---------------------------------|
```

핵심 포인트:

- REGISTER는 `SipCore::handleRegister()`에서 처리된다.
- 성공 시 `Registration` 상태가 갱신된다.
- 이 상태가 이후 INVITE 라우팅의 출발점이 된다.

## 17.3 REGISTER with Digest 인증

```text
Client                         Proxy(SIPLite)
  |                                  |
  | REGISTER (no Authorization)      |
  |--------------------------------->|
  |                                  | authPassword 존재 확인
  |                                  | nonce 생성
  |                                  |
  | 401 Unauthorized                 |
  | WWW-Authenticate: Digest ...     |
  |<---------------------------------|
  |                                  |
  | REGISTER + Authorization         |
  |--------------------------------->|
  |                                  | Digest 파라미터 파싱
  |                                  | nonce / nc 검증
  |                                  | response 계산 비교
  |                                  | Registration 저장
  |                                  |
  | 200 OK                           |
  |<---------------------------------|
```

핵심 포인트:

- 인증은 REGISTER 시점에 수행된다.
- nonce와 nonce-count를 사용해 replay를 일부 방어한다.
- 인증 성공 후에야 `loggedIn` 상태가 활성화된다.

## 17.4 INVITE 기본 흐름

```text
Caller                         Proxy(SIPLite)                       Callee
  |                                  |                                |
  | INVITE sip:1001@server           |                                |
  |--------------------------------->|                                |
  |                                  | 등록 조회                      |
  |                                  | 100 Trying 생성                |
  | 100 Trying                       |                                |
  |<---------------------------------|                                |
  |                                  | Via 추가                       |
  |                                  | Record-Route 추가              |
  |                                  | Max-Forwards 감소              |
  |                                  | Request-URI -> Contact 재작성  |
  |                                  | ActiveCall 생성                |
  |                                  | PendingInvite 생성             |
  |                                  | INVITE 전달                    |
  |                                  |------------------------------->|
  |                                  |                                |
```

핵심 포인트:

- 호출자는 AoR로 INVITE를 보내지만, 프록시는 Contact 기준으로 실제 목적지를 정한다.
- 프록시는 stateful proxy처럼 transaction 상태를 보관한다.
- 응답이 오기 전까지는 `PendingInvite`가 중심 상태다.

## 17.5 INVITE 응답과 통화 성립

```text
Caller                         Proxy(SIPLite)                       Callee
  |                                  |                                |
  |                                  | <------- 180 Ringing ----------|
  |                                  | top Via 제거                   |
  | <--------- 180 Ringing ----------| caller로 전달                  |
  |                                  |                                |
  |                                  | <--------- 200 OK -------------|
  |                                  | Dialog 생성                    |
  | <----------- 200 OK -------------| caller로 전달                  |
  |                                  |                                |
  | ACK                              |                                |
  |--------------------------------->|                                |
  |                                  | call/dialog confirmed          |
  |                                  | ACK 전달                       |
  |                                  |------------------------------->|
```

핵심 포인트:

- provisional response는 Timer C를 연장한다.
- 2xx 응답은 dialog 생성을 유도한다.
- ACK가 와야 최종적으로 `confirmed` 상태가 된다.

## 17.6 INVITE 재전송 흐름

```text
Caller                         Proxy(SIPLite)
  |                                  |
  | INVITE (same Call-ID/CSeq)       |
  |--------------------------------->|
  |                                  | pendingInvites_ 조회
  |                                  | 기존 transaction 발견
  |                                  | lastResponse 또는 100 Trying 재사용
  |                                  |
  | cached response                  |
  |<---------------------------------|
```

핵심 포인트:

- 재전송은 새 통화로 취급하지 않는다.
- 기존 transaction 상태를 그대로 재사용한다.

## 17.7 CANCEL 흐름

```text
Caller                         Proxy(SIPLite)                       Callee
  |                                  |                                |
  | CANCEL                           |                                |
  |--------------------------------->|                                |
  |                                  | pendingInvites_ 조회           |
  |                                  | 200 OK 생성                    |
  | 200 OK                           |                                |
  |<---------------------------------|                                |
  |                                  | CANCEL 생성                    |
  |                                  |------------------------------->|
  |                                  |                                |
  |                                  | <---- 487 Request Terminated --|
  |                                  | ACK 생성                       |
  | <--- 487 Request Terminated -----|                                |
  |                                  |-------------- ACK -----------> |
```

핵심 포인트:

- CANCEL 자체에 대한 응답과 원래 INVITE에 대한 종료 응답은 별개다.
- 프록시는 callee의 487을 caller에게 그대로 전달한다.
- 필요 시 프록시가 ACK도 생성한다.

## 17.8 deferred CANCEL 흐름

```text
Caller                         Proxy(SIPLite)
  |                                  |
  | CANCEL (INVITE보다 먼저 도착)    |
  |--------------------------------->|
  |                                  | matching INVITE 없음
  |                                  | pendingCancels_에 key 저장
  | 481 or local handling            |
  |<---------------------------------|
  |                                  |
  | INVITE (same Call-ID/CSeq)       |
  |--------------------------------->|
  |                                  | deferred CANCEL 발견
  |                                  | PendingInvite 즉시 제거
  | 487 Request Terminated           |
  |<---------------------------------|
```

핵심 포인트:

- UDP 재정렬과 멀티 워커 환경을 고려한 흐름이다.
- 이 프로젝트가 순서 역전을 실제 문제로 보고 있다는 증거다.

## 17.9 BYE 흐름

```text
Caller                         Proxy(SIPLite)                       Callee
  |                                  |                                |
  | BYE                              |                                |
  |--------------------------------->|                                |
  |                                  | Dialog / ActiveCall 조회       |
  |                                  | 200 OK 생성                    |
  | 200 OK                           |                                |
  |<---------------------------------|                                |
  |                                  | Route 제거                     |
  |                                  | Request-URI -> Contact 재작성  |
  |                                  |------------------------------->|
```

핵심 포인트:

- BYE는 caller와 callee 어느 쪽에서도 올 수 있다.
- 첫 번째 BYE 이후 상태를 즉시 지우지 않고 cross-BYE를 기다릴 수 있다.

## 17.10 cross-BYE 흐름

```text
Caller                         Proxy(SIPLite)                       Callee
  |                                  |                                |
  | BYE                              |                                |
  |--------------------------------->|                                |
  | 200 OK                           |                                |
  |<---------------------------------|                                |
  |                                  |-------------- BYE -----------> |
  |                                  |                                |
  |                                  | <----------- BYE ------------- |
  |                                  | cross-BYE 감지                |
  |                                  | Dialog / ActiveCall 제거      |
  |                                  |----------- 200 OK -----------> |
```

핵심 포인트:

- 양쪽 종료 요청이 겹치는 상황을 따로 다룬다.
- 이 경우 call/dialog 상태가 실제로 정리된다.

## 17.11 SUBSCRIBE + initial NOTIFY 흐름

```text
Subscriber                     Proxy(SIPLite)
  |                                  |
  | SUBSCRIBE                        |
  |--------------------------------->|
  |                                  | Event 검증
  |                                  | Subscription 저장
  | 200 OK                           |
  |<---------------------------------|
  |                                  | initial NOTIFY 생성
  | NOTIFY                           |
  |<---------------------------------|
```

핵심 포인트:

- SUBSCRIBE 성공 직후 initial NOTIFY를 보낸다.
- subscription은 장기 상태로 저장된다.

## 17.12 NOTIFY 프록시 전달 흐름

```text
Notifier                       Proxy(SIPLite)                    Subscriber
  |                                  |                                |
  | NOTIFY                           |                                |
  |--------------------------------->|                                |
  |                                  | subscription 조회              |
  |                                  | Subscription-State 처리        |
  |                                  | Proxy Via 추가                |
  |                                  |------------------------------->|
  | 200 OK                           |                                |
  |<---------------------------------|                                |
```

핵심 포인트:

- 서버가 외부 notifier와 subscriber 사이의 프록시가 될 수 있다.
- terminated NOTIFY는 subscription 제거를 동반할 수 있다.

## 17.13 subscription 만료 흐름

```text
Timer Loop                      SipCore                        Subscriber
   |                              |                                |
   | cleanupExpiredSubscriptions  |                                |
   |----------------------------->| 만료 subscription 탐색         |
   |                              | terminated NOTIFY 생성         |
   |                              |------------------------------->|
   |                              | subscription 제거              |
```

핵심 포인트:

- subscription은 요청 기반 상태일 뿐 아니라 timer 기반 수명도 가진다.
- 만료 시 단순 삭제가 아니라 종료 통지까지 수행한다.

## 17.14 TLS 연결 생성 흐름

```text
Proxy(SIPLite)                                            Remote TLS Peer
      |                                                          |
      | TCP connect                                              |
      |--------------------------------------------------------->|
      |                                                          |
      | SSL_connect()                                            |
      |--------------------------------------------------------->|
      |                                                          |
      | TLS session established                                  |
      |<-------------------------------------------------------->|
      |                                                          |
      | SIP over TLS (SSL_write / SSL_read)                      |
      |<========================================================>|
```

핵심 포인트:

- TLS는 실제로 outbound connection도 가진다.
- transport가 TLS면 SIPLite는 `TlsServer::sendTo()`를 통해 연결을 열고 재사용할 수 있다.

## 17.15 이 장의 핵심 정리

이 장의 다이어그램은 앞선 장들의 요약이 아니다. 오히려 각 장을 연결하는 "전체 그림"이다.

독자가 이 프로젝트를 이해할 때 가장 좋은 방법은 다음 순서다.

1. 시퀀스 다이어그램으로 흐름 감각을 잡는다.
2. 해당 장의 상세 설명을 읽는다.
3. 마지막으로 코드 위치를 따라 들어간다.

다음 장에서는 바로 그 코드 읽기 순서를 정리한다.
