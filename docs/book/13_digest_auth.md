# 13. Digest 인증

## 13.1 이 장의 목적

SIPLite의 REGISTER는 단순 `Contact` 저장 절차가 아니다. 현재 구현은 SIP Digest 인증을 포함하고 있으며, 이 부분은 프로젝트의 보안 모델을 이해하는 데 중요하다.

관련 코드:

- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L12)
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L45) `parseDigestParameters()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L154) `makeDigestResponse()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L623) `handleRegister()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2679) `buildRegisterAuthChallenge()`
- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L1088) `DigestNonceState`

테스트 근거:

- [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L68)

## 13.2 어디에 적용되는가

현재 Digest 인증은 REGISTER에 적용된다. 다시 말해, 이 프로젝트의 인증 모델은 "등록 시점의 신원 검증"에 집중되어 있다.

이 설계는 현실적이다.

- INVITE, MESSAGE 라우팅보다 먼저 신뢰 가능한 등록 상태가 필요하다.
- REGISTER를 통과한 단말만 이후 위치 정보 갱신과 로그인 상태를 얻는다.
- 정적 단말 목록과 비밀번호를 결합해 controlled environment를 구성할 수 있다.

즉 인증은 아직 전체 SIP 메서드 공통 계층이 아니라, registrar 보호 계층이다.

## 13.3 사전 조건: 비밀번호 저장

Digest 인증이 가능하려면 서버는 사용자 비밀번호를 알고 있어야 한다. 이 프로젝트에서는 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L138)의 `Registration.authPassword`가 그 역할을 한다.

이 값은 주로 두 경로에서 들어온다.

- XML 설정 파일의 `<password>`
- `registerTerminal()` 호출 인자

즉 SIPLite의 인증 모델은 현재 "사전 정의된 단말 + 서버가 알고 있는 shared secret" 구조다.

## 13.4 realm과 nonce

Digest 인증 구현의 기본 상수는 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L12)에 있다.

- realm: `SIPLite`
- nonce TTL: 5분

`generateRegisterNonce()`는 32자리 hex nonce를 만든다. 이 nonce는 챌린지 응답형 인증에서 replay를 줄이는 핵심 요소다.

## 13.5 인증 파라미터 파싱

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L45)의 `parseDigestParameters()`는 `Authorization: Digest ...` 헤더를 key/value로 분해한다.

이 함수가 처리하는 요소:

- `username`
- `realm`
- `nonce`
- `uri`
- `response`
- `qop`
- `nc`
- `cnonce`

구현상 특징:

- quoted string 처리
- escaped character 처리
- 쉼표 구분 파싱
- 키를 소문자로 정규화

즉 이 함수는 단순 split이 아니라 Digest 헤더 문법을 실제로 해석하는 최소 파서다.

## 13.6 응답 해시 계산

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L154)의 `makeDigestResponse()`는 Digest 응답값을 계산한다.

구조는 표준적인 HA1/HA2 기반이다.

- `HA1 = MD5(username:realm:password)`
- `HA2 = MD5(method:uri)`
- qop가 있으면 `HA1:nonce:nc:cnonce:qop:HA2`
- 없으면 `HA1:nonce:HA2`

현재 구현은 `MD5` 기반이고, REGISTER 경로에서는 method가 `REGISTER`, uri가 요청 URI가 된다.

## 13.7 `handleRegister()` 안의 인증 흐름

REGISTER 처리 안에서 인증은 대략 다음 순서로 진행된다.

1. 해당 단말에 `authPassword`가 설정돼 있는지 확인
2. 있으면 `Authorization` 헤더 요구
3. 헤더가 없거나 잘못됐으면 챌린지 발급
4. nonce 유효성 검사
5. qop / nc / cnonce에 따라 응답 검증
6. 성공 시 REGISTER 허용

즉 비밀번호가 없는 정적 단말은 인증 없이도 통과할 수 있지만, 비밀번호가 있는 단말은 Digest 응답이 필요하다.

## 13.8 nonce 저장소

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L1088)의 `DigestNonceState`는 두 값을 기억한다.

- `expiresAt`
- `lastNonceCount`

그리고 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L1097)의 `registerNonces_`가 nonce 저장소다.

이 구조는 두 가지 방어를 가능하게 한다.

- 만료된 nonce 거부
- 같은 nonce를 써도 `nc`가 증가하지 않으면 거부

즉 구현은 단순 challenge generation을 넘어 replay 방어를 일부 고려한다.

## 13.9 qop와 nonce-count

현재 구현은 qop가 없을 때와 있을 때를 분리해서 다룬다.

### qop 없음

- nonce가 살아 있으면 기본 응답 검증

### qop 있음

- `nc`, `cnonce` 필요
- `parseNonceCount()`로 `nc`를 파싱
- 이전 `lastNonceCount`보다 커야 허용

이 흐름은 SIPLite의 Digest 인증이 최소한의 nonce-count 기반 순서 검증까지 포함한다는 뜻이다.

## 13.10 stale nonce

nonce가 만료되면 코드에서 `staleNonce = true`를 설정하고, 새 챌린지를 발급한다. 이 정보는 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2679)의 `buildRegisterAuthChallenge()`에서 `stale=true` 파라미터로 응답에 반영된다.

이 설계는 클라이언트가 "자격 증명이 틀렸다"와 "nonce가 오래됐다"를 구분할 수 있게 한다.

## 13.11 챌린지 응답

`buildRegisterAuthChallenge()`는 `401 Unauthorized` 응답을 만든다.

핵심 헤더:

- `WWW-Authenticate: Digest realm="SIPLite", nonce="...", algorithm=MD5, qop="auth"`

즉 이 프로젝트의 챌린지 응답은 단지 `401` 상태 코드만 주는 것이 아니라, 실제 Digest handshake에 필요한 파라미터를 제공한다.

## 13.12 테스트가 보여주는 실제 흐름

[tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L68)에는 Digest 인증 성공 시나리오가 비교적 명확하게 들어 있다.

흐름:

1. 인증 없이 REGISTER 전송
2. `401 Unauthorized` 수신
3. `realm`, `nonce` 추출
4. 클라이언트 쪽 digest 응답 계산
5. `Authorization: Digest ...` 포함한 두 번째 REGISTER 전송
6. `200 OK` 수신

이 테스트는 문서에 매우 좋은 예제가 된다. 실제로 책에서 Digest 인증 장을 쓸 때 거의 그대로 시퀀스로 바꿔 적을 수 있다.

## 13.13 현재 구현의 장점

- REGISTER 보호 경로가 실제 코드로 존재
- nonce TTL이 있음
- stale nonce 처리 있음
- qop/auth 경로 지원
- nonce-count 증가 검증 포함
- 테스트로 기본 성공 경로 검증

즉 toy 수준 "비밀번호 비교"보다 훨씬 나은 구조다.

## 13.14 현재 구현의 한계

동시에 문서에는 현재 한계도 적어둘 필요가 있다.

- REGISTER 외 메서드 공통 인증 계층은 아님
- password 저장 모델이 더 정교한 credential backend와 연결돼 있지는 않음
- MD5 기반이라는 점은 현대적 보안 기준에서는 보수적으로 볼 필요가 있음
- rate limiting, 계정 잠금, audit trail 같은 운영 보안 기능은 별개 주제

즉 이 Digest 구현은 SIP REGISTER 보호에 충분한 구조를 갖추고 있지만, 계정 관리 시스템 전체를 대체하는 보안 프레임워크는 아니다.

## 13.15 이 장의 핵심 정리

SIPLite의 Digest 인증은 "있다" 수준이 아니라 실제로 동작하는 REGISTER 보호 메커니즘이다.

- nonce 생성
- 파라미터 파싱
- digest 계산
- stale 처리
- nonce-count 검증
- 챌린지/응답 테스트

까지 구현되어 있다.

다음 장에서는 인증된 단말 목록이 어디서 오는지, 그리고 XML 설정이 서버 구조에서 어떤 의미를 가지는지 본다.
