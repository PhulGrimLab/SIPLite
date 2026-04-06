# 9. REGISTER 흐름

## 9.1 이 장의 목적

REGISTER는 SIPLite에서 가장 먼저 이해해야 할 메서드다. 이유는 간단하다. 이 프로젝트의 대부분 라우팅은 결국 등록 상태에 의존하기 때문이다.

INVITE, MESSAGE, SUBSCRIBE 같은 후속 흐름도 목적 AoR에 대한 등록 상태가 없으면 제대로 동작할 수 없다. 따라서 REGISTER를 이해하는 것은 단순히 로그인 기능을 이해하는 것이 아니라, `SipCore`의 위치 서비스 모델을 이해하는 일이다.

## 9.2 관련 코드

핵심 코드는 다음 위치에 있다.

- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L623) `handleRegister()`
- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L131) `Registration`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2628) `buildRegisterOk()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2679) `buildRegisterAuthChallenge()`
- [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)

테스트 근거는 다음이 중요하다.

- [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp)
- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L156)
- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L200)
- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L241)
- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L270)

## 9.3 REGISTER의 기본 처리 흐름

그림 4는 REGISTER의 기본 분기 구조를 보여 준다.

```text
REGISTER 수신
   |
   +--> To / Contact 확인 실패? ---- yes ---> 400 Bad Request
   |
   +--> AoR 추출
   +--> XML 사전 등록 단말 확인
   |         +--> unknown user ---> 404 Not Found
   |         +--> not allowed ----> 403 Forbidden
   |
   +--> Authorization 필요?
   |         +--> yes, 실패 ------> 401 Unauthorized
   |
   +--> Expires 파싱 실패? ---- yes ---> 400 Bad Request
   |
   +--> Expires == 0 ?
   |         +--> yes --> deregistration --> 200 OK
   |
   +--> Registration 갱신
   +--> 200 OK
```

정리 상자:
이 프로젝트의 REGISTER는 공개 registrar라기보다, XML에 사전 정의된 단말을 실제 로그인 상태로 전환하는 경로에 가깝다.
즉 "새 사용자를 만드는 요청"보다 "허용된 사용자를 활성화하는 요청"으로 읽는 것이 정확하다.

`handleRegister()`의 큰 흐름은 다음과 같다.

1. `To`, `Contact` 헤더 확인
2. `To`에서 AoR 추출
3. XML로 미리 등록된 단말인지 확인
4. 필요 시 Digest 인증 검사
5. `Expires` 해석
6. `Expires: 0`이면 해지 처리
7. 아니면 `Registration` 갱신
8. `200 OK` 또는 `401 Unauthorized` 반환

이 순서를 보면 이 프로젝트의 REGISTER는 "누구나 자유롭게 자기 AoR을 등록하는 공개 registrar"가 아니다. 사전 등록된 단말만 실제 REGISTER를 통해 로그인 상태로 전환하는 구조다.

## 9.4 `To`와 `Contact`가 왜 둘 다 필요한가

`handleRegister()`는 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L627)에서 `To`와 `Contact`를 읽고, 둘 중 하나라도 비어 있으면 `400 Bad Request`를 반환한다.

이 판단은 자연스럽다.

- `To`는 등록하려는 논리 사용자, 즉 AoR를 가리킨다.
- `Contact`는 현재 도달 가능한 실주소를 가리킨다.

즉 REGISTER는 "누가"와 "어디로 보낼지"를 같이 제출해야 의미가 있다.

## 9.5 XML 사전 등록 기반 정책

이 프로젝트의 REGISTER 정책에서 중요한 부분은 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L643) 이후의 분기다.

핵심 정책:

- XML에 없는 AoR이면 `404 Not Found`
- XML에 있더라도 정적 단말이 아니면 `403 Forbidden`

이 정책의 의미는 다음과 같다.

- 서버가 허용한 단말만 로그인할 수 있다.
- REGISTER는 "새 사용자를 만드는 요청"이 아니라 "이미 정의된 사용자를 활성화하는 요청"에 가깝다.

즉 SIPLite는 개방형 public registrar보다 사전 정의된 단말 목록을 가진 controlled environment 쪽에 더 가깝다.

## 9.6 AoR 매칭 방식

매칭은 단순 문자열 비교가 아니라 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L1099)의 `findByUser_()`를 통해 수행된다. 내부적으로는 `extractAorKeyFromUri()` 기반 정규화가 개입한다.

이것이 중요한 이유는 다음과 같다.

- `user@domain` 기준 식별이 가능하다.
- 같은 user라도 다른 domain이면 다른 단말로 취급할 수 있다.
- 후속 INVITE 라우팅과 REGISTER가 같은 식별 규칙을 공유한다.

즉 REGISTER는 단순 위치 등록이 아니라 이후 라우팅 키를 확정하는 단계이기도 하다.

## 9.7 Digest 인증 흐름

이 프로젝트의 REGISTER는 평문 허용만 있는 구조가 아니다. [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L706) 이후를 보면 Digest 인증 검증이 들어 있다.

구조는 다음과 같다.

1. `Authorization` 헤더 파싱
2. `username`, `realm`, `nonce`, `uri`, `response`, `qop`, `nc`, `cnonce` 추출
3. nonce 유효성 검사
4. 필요 시 nonce count 증가 검증
5. 예상 digest 계산
6. 일치하면 인증 성공
7. 실패하면 새 nonce를 발급하고 `401 Unauthorized`

핵심 유틸:

- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L45) `parseDigestParameters()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L154) `makeDigestResponse()`
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2679) `buildRegisterAuthChallenge()`

책에서는 이 부분을 별도 장으로 더 확장해도 충분한 분량이 나온다.

## 9.8 nonce 저장소와 재사용 방지

Digest 인증의 핵심은 단순 해시 계산이 아니라 nonce 수명 관리다.

[include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L1088)의 `DigestNonceState`는 다음을 저장한다.

- `expiresAt`
- `lastNonceCount`

즉 이 구현은 다음 위험을 줄이려 한다.

- 만료된 nonce 재사용
- 동일 nonce에서 nonce-count를 되감는 replay 시도

이는 toy 수준 구현을 넘어선 방어 의도를 보여준다.

## 9.9 `Expires` 처리

REGISTER의 수명 관리는 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L795) 이후에서 이뤄진다.

현재 구현 특징:

- 기본값은 `SipConstants::DEFAULT_EXPIRES_SEC`
- 숫자가 아니면 `400 Bad Request - Invalid Expires`
- 최대값을 넘으면 clamp
- `0`이면 deregistration

테스트도 이 흐름을 검증한다.

- invalid `Expires` → 400: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L200)
- 음수/비정상 값 처리: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L218)
- 최대값 clamp: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L1077)

## 9.10 `Expires: 0` 해지

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L852) 이후는 deregistration 경로다.

동작:

- 등록 항목 조회
- 정적 등록이면 엔트리 삭제 대신 `loggedIn = false`
- 동적 등록이면 엔트리 제거
- `200 OK` 반환

이 정책은 정적 단말 목록을 유지하면서도 실제 로그인 상태만 해제할 수 있게 한다. 즉 "정의된 단말"과 "현재 활성 단말"을 분리한 설계다.

## 9.11 실제 저장되는 등록 정보

REGISTER 성공 시 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L872) 이후에서 새로운 `Registration`을 구성한다.

중요 포인트:

- `aor`는 XML에 등록된 원래 AoR 유지
- `contact`는 REGISTER가 제시한 값 사용
- `ip`, `port`는 실제 패킷 source 사용
- `transport`는 `pkt.transport`
- `loggedIn = true`

여기서 가장 중요한 줄은 transport 저장이다.

```cpp
reg.transport = pkt.transport;
```

이 한 줄 때문에 REGISTER는 단순 로그인 절차를 넘어서 후속 INVITE/MESSAGE/NOTIFY 라우팅의 transport 기준을 확정하게 된다.

## 9.12 REGISTER 응답 생성

성공 응답은 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp#L2628)의 `buildRegisterOk()`가 만든다.

응답 구성 요소:

- `Via`
- `From`
- `To` with tag
- `Call-ID`
- `CSeq`
- `Contact`
- `Server`
- `Content-Length: 0`

즉 REGISTER 응답도 단순 문자열 반환이 아니라, 요청의 핵심 문맥을 유지한 표준 응답 구조를 따른다.

## 9.13 REGISTER와 테스트

표 4는 REGISTER 관련 테스트가 어떤 실패 경로까지 다루는지 보여 준다.

| 시나리오 | 기대 결과 | 근거 테스트 |
|---|---|---|
| 정상 REGISTER | `200 OK` | `test_sipcore.cpp` |
| Digest challenge | `401 Unauthorized` 후 재시도 | `test_sipcore.cpp` |
| deregistration | `loggedIn=false` 또는 제거 | `test_sipcore_extended.cpp` |
| invalid Expires | `400 Bad Request` | `test_sipcore_extended.cpp` |
| missing To/Contact | `400 Bad Request` | `test_sipcore_extended.cpp` |
| unknown user | `404 Not Found` | `test_sipcore_extended.cpp` |

REGISTER 관련 테스트는 상당히 풍부하다.

대표 시나리오:

- 정상 REGISTER: [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L38)
- Digest challenge/response: [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp#L68)
- deregistration: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L156)
- 잘못된 `Expires`: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L200)
- `To`/`Contact` 누락: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L241)
- 미등록 사용자 REGISTER: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L270)

즉 REGISTER는 이 프로젝트에서 가장 단단하게 검증된 흐름 중 하나다.

## 9.14 REGISTER 흐름의 의미 정리

SIPLite에서 REGISTER는 아래 의미를 가진다.

- 단말의 신원 확인
- 단말의 실제 도달 주소 갱신
- transport 확정
- 로그인 상태 전환
- 후속 라우팅 가능 상태 생성

따라서 REGISTER는 이 프로젝트의 "입구"라고 불러도 무리가 없다.

## 9.15 이 장의 핵심 정리

이 프로젝트의 REGISTER는 단순 상태 저장이 아니다.

- XML 기반 허용 단말 정책
- Digest 인증
- `Expires` 수명 관리
- transport-aware 등록
- 정적/동적 등록 구분

까지 포함한 비교적 성숙한 registrar 흐름이다.

다음 장에서는 이 등록 상태를 바탕으로 실제 통화가 어떻게 시작되는지, 즉 INVITE 흐름을 본다.
