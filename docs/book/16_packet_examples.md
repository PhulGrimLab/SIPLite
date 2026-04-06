# 16. 실제 패킷 예제

## 16.1 이 장의 목적

구조와 흐름 설명만으로는 SIP를 처음 읽는 독자에게 체감이 부족할 수 있다. 그래서 이 장에서는 테스트 코드에 등장하는 실제 raw SIP 문자열을 바탕으로, SIPLite가 어떤 메시지를 받고 어떤 메시지를 생성하는지 예제로 정리한다.

중요 근거 파일:

- [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp)
- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L64)

## 16.2 기본 REGISTER 요청

[tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L38)에는 가장 기본적인 REGISTER 예제가 있다.

```text
REGISTER sip:server SIP/2.0
Via: SIP/2.0/UDP client.example.com:5060
From: <sip:1001@server>;tag=123
To: <sip:1001@server>
Call-ID: reg1
CSeq: 1 REGISTER
Contact: <sip:1001@10.0.0.1:5060>
Expires: 3600
Content-Length: 0
```

이 패킷이 의미하는 것:

- 사용자 `1001@server`가
- 자신의 현재 Contact를 `10.0.0.1:5060`으로 제시하며
- 1시간 등록을 요청한다

SIPLite는 이를 받아 `Registration` 상태를 갱신한다.

## 16.3 Digest challenge가 필요한 REGISTER

[tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L73)에는 인증 전 REGISTER가 있다.

```text
REGISTER sip:server SIP/2.0
Via: SIP/2.0/UDP auth.example.com:5062
From: <sip:2001@server>;tag=auth1
To: <sip:2001@server>
Call-ID: reg-auth-1
CSeq: 1 REGISTER
Contact: <sip:2001@10.0.0.9:5060>
Expires: 3600
Content-Length: 0
```

이 요청에는 `Authorization` 헤더가 없으므로 서버는 `401 Unauthorized`와 `WWW-Authenticate: Digest ...`를 돌려준다.

## 16.4 Digest 인증이 포함된 REGISTER

이어지는 예제는 [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L102)에 있다.

핵심 부분:

```text
Authorization: Digest username="2001", realm="SIPLite",
 nonce="...",
 uri="sip:server",
 response="...",
 algorithm=MD5, qop=auth, nc=00000001,
 cnonce="abcdef1234567890"
```

이 요청이 성공하면 REGISTER는 `200 OK`를 받는다. 책에서는 이 예제를 사용해 Digest 장과 REGISTER 장을 연결할 수 있다.

## 16.5 기본 INVITE 요청

[tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L132)의 기본 INVITE는 다음과 같다.

```text
INVITE sip:1001@server SIP/2.0
Via: SIP/2.0/UDP caller.example.com:5060
From: <sip:1002@client>;tag=abc
To: <sip:1001@server>
Call-ID: inv1
CSeq: 1 INVITE
Content-Length: 0
```

SIPLite는 이 요청을 받으면 먼저 caller에게 `100 Trying`을 보내고, 이후 callee의 Contact 기준으로 Request-URI를 재작성한 INVITE를 전달한다.

## 16.6 포워딩된 INVITE의 핵심 변화

테스트는 [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L157)에서 포워딩된 INVITE에 다음 변화가 있음을 확인한다.

- Request-URI가 `sip:1001@10.0.0.1:5060`으로 바뀜
- 프록시 `Via` 추가
- `Record-Route` 추가 가능
- `Max-Forwards` 감소

즉 INVITE는 원문 그대로 전달되지 않고, proxy routing semantics에 맞게 수정된다.

## 16.7 CANCEL 요청 예제

[tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L168)의 예제:

```text
CANCEL sip:1001@server SIP/2.0
Via: SIP/2.0/UDP caller.example.com:5060
From: <sip:1002@client>;tag=abc
To: <sip:1001@server>
Call-ID: inv1
CSeq: 1 CANCEL
Content-Length: 0
```

이 요청의 의미:

- 아직 최종 응답이 오지 않은 동일 transaction의 INVITE를 취소

SIPLite는 caller에게 `200 OK`를 주고, 내부 `PendingInvite`를 기반으로 callee 방향 CANCEL을 만든다.

## 16.8 487 응답과 프록시 ACK

[tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L200)의 예제는 callee가 보낸 `487 Request Terminated` 응답이다.

핵심 구조:

```text
SIP/2.0 487 Request Terminated
Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-proxy-test;rport
Via: SIP/2.0/UDP caller.example.com:5060
From: <sip:1002@client>;tag=abc
To: <sip:1001@server>;tag=callee-tag
Call-ID: inv1
CSeq: 1 INVITE
Content-Length: 0
```

이 응답이 오면 SIPLite는:

- top proxy Via 제거 후 caller에게 487 전달
- callee에게 ACK 생성 후 전송

즉 에러 응답도 stateful proxy semantics를 따른다.

## 16.9 BYE 예제

[tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L104)의 helper `makeBye()`는 기본 BYE 형식을 보여준다.

```text
BYE sip:1001@server SIP/2.0
Via: SIP/2.0/UDP caller:5060
From: <sip:1002@client>;tag=bye-tag
To: <sip:1001@server>;tag=...
Call-ID: ...
CSeq: ... BYE
Content-Length: 0
```

실제 전달 시 SIPLite는 상대편 Contact URI로 Request-URI를 다시 쓸 수 있다. 이 점이 단순 `Call-ID` 기반 상태 삭제와 다른 부분이다.

## 16.10 TLS REGISTER 예제

[tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L65)의 `makeRegister()`는 transport를 인자로 받아 `Via: SIP/2.0/TLS ...` 형태를 만들 수 있다.

예를 들면 TLS REGISTER는 대략 이런 모양이다.

```text
REGISTER sip:server SIP/2.0
Via: SIP/2.0/TLS client:5060
From: <sip:tls1@server>;tag=tls-tag
To: <sip:tls1@server>
Call-ID: tls-reg
CSeq: 1 REGISTER
Contact: <sips:tls1@10.0.0.10:5061>
Expires: 3600
Content-Length: 0
```

이 요청이 성공하면 등록 상태의 transport가 TLS로 저장되고, 후속 INVITE도 TLS로 나갈 수 있다.

## 16.11 SUBSCRIBE 예제

[tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L811)에는 TLS subscriber 예제가 있다.

```text
SUBSCRIBE sip:1001@server SIP/2.0
Via: SIP/2.0/TLS subscriber:5061
From: <sip:1002@client>;tag=subexp
To: <sip:1001@server>
Call-ID: sub-expire
CSeq: 1 SUBSCRIBE
Event: presence
Contact: <sips:1002@10.0.0.2:5061>
Expires: 1
Content-Length: 0
```

이 예제는 세 가지를 동시에 보여준다.

- subscription도 TLS transport를 탈 수 있다
- `Event` 헤더가 필수다
- subscriber Contact가 이후 NOTIFY 목적지로 쓰인다

## 16.12 NOTIFY 예제

[tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L2502)의 NOTIFY 예제:

```text
NOTIFY sip:1002@client SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1:5060
From: <sip:1001@server>;tag=server-tag
To: <sip:1002@client>;tag=n-tag
Call-ID: notify-call
CSeq: 2 NOTIFY
Event: presence
Subscription-State: active
Content-Type: application/pidf+xml
Content-Length: 5

open
```

이 예제는 NOTIFY가 단순 제어 메시지가 아니라 body와 content-type을 실을 수 있는 상태 통지 메시지라는 점을 보여준다.

## 16.13 OPTIONS 예제

[tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L122)의 helper `makeOptions()`는 OPTIONS 패킷 형식을 보여준다.

SIPLite는 OPTIONS 응답에서 `Allow` 헤더를 통해 자신이 다룰 수 있는 메서드 집합을 알려준다. 이는 기능 탐색용으로 유용하다.

## 16.14 이 장을 어떻게 활용할 것인가

이 패킷 예제 장은 두 가지 목적으로 활용할 수 있다.

### 코드 독해용

각 메서드 장을 읽다가 실제 패킷 모양이 궁금할 때 이 장을 참조한다.

### 책/강의 자료용

시퀀스 다이어그램 옆에 실제 SIP 전문 일부를 붙이면 독자 이해가 훨씬 빨라진다.

특히 다음 조합이 좋다.

- REGISTER + 401 + REGISTER(with Authorization)
- INVITE + 100 Trying + forwarded INVITE
- CANCEL + 487 + ACK
- SUBSCRIBE + initial NOTIFY

## 16.15 이 장의 핵심 정리

실제 SIP 서버를 이해하려면 함수 이름만 보는 것으로는 부족하다. 결국 네트워크에 오가는 것은 패킷 전문이다.

SIPLite는 테스트 코드 안에 좋은 raw SIP 예제를 이미 많이 가지고 있다. 이 장은 그 예제를 문서 자산으로 끌어오는 출발점이다.
