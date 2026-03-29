# REGISTER Digest Authentication

작성일: 2026-03-29
대상 경로: `/home/windmorning/projects/SIPWorks/SIPLite`

## 목적

기존 SIPLite는 `REGISTER` 요청에서 사용자 존재 여부만 확인하고 등록을 허용했다.
이번 변경은 사전 등록된 단말에 대해 선택적으로 SIP Digest 인증을 요구하도록 보완한 것이다.

핵심 목표는 아래 2가지다.

- 아무나 사용자 번호만 알고 `REGISTER`를 탈취하지 못하게 하기
- 기존 동작을 최대한 깨지 않으면서 인증이 필요한 단말만 보호하기

## 무엇이 바뀌었나

### 1. 단말 등록 정보에 인증 비밀번호 추가

`Registration` 구조체에 `authPassword` 필드가 추가됐다.

- 파일: `include/SipCore.h`
- 의미: 해당 AoR이 `REGISTER` 시 Digest 인증을 요구할 때 사용할 비밀번호

`registerTerminal(...)`도 마지막 인자로 선택적 비밀번호를 받을 수 있게 바뀌었다.

- 비밀번호가 비어 있으면 기존처럼 인증 없이 `REGISTER` 가능
- 비밀번호가 있으면 Digest 인증 필요

## 2. XML 설정에서 `<password>` 지원

XML 로더가 단말 설정에서 선택적 `<password>` 태그를 읽는다.

- 파일: `include/XmlConfigLoader.h`

예시:

```xml
<terminal>
    <aor>sip:1001@192.168.0.23</aor>
    <password>secret1001</password>
    <expires>3600</expires>
</terminal>
```

이 값은 내부적으로 `registerTerminal(..., authPassword)`로 전달된다.

## 3. REGISTER 처리에 401 챌린지 추가

`handleRegister()`에 Digest 인증 검증 로직이 추가됐다.

- 파일: `src/SipCore.cpp`

인증 비밀번호가 설정된 단말에 대해:

1. `Authorization` 헤더가 없으면 `401 Unauthorized` 반환
2. 응답에 `WWW-Authenticate: Digest ...` 헤더 포함
3. 클라이언트가 nonce를 사용해 다시 `REGISTER`하면 응답 해시 검증
4. 검증 성공 시에만 기존 등록 처리 수행

## 4. nonce 상태 저장

서버가 발급한 nonce를 임시 저장하는 상태가 추가됐다.

- 파일: `include/SipCore.h`
- 사용 위치: `src/SipCore.cpp`

저장 정보:

- nonce 만료 시각
- 마지막 `nc` 값

현재 nonce TTL은 5분이다.

## 5. MD5 해시 계산 함수 추가

Digest 검증에 필요한 MD5 계산 함수 `md5Hex()`가 추가됐다.

- 선언: `include/SipUtils.h`
- 구현: `src/SipUtils.cpp`

이 함수는 아래 계산에 사용된다.

- `HA1 = MD5(username:realm:password)`
- `HA2 = MD5(method:uri)`
- `response = MD5(HA1:nonce:nc:cnonce:qop:HA2)` 또는 qop 없는 변형

## 동작 흐름

### 인증이 없는 단말

기존과 동일하다.

- `REGISTER` 수신
- 사용자 존재 및 정적 등록 여부 확인
- `Expires` 처리
- 등록 저장
- `200 OK`

### 인증이 있는 단말

첫 번째 요청:

- `REGISTER` 수신
- 비밀번호가 설정된 단말인지 확인
- `Authorization`이 없거나 유효하지 않으면 `401 Unauthorized`
- `WWW-Authenticate`에 `realm`, `nonce`, `algorithm=MD5`, `qop="auth"` 포함

두 번째 요청:

- 클라이언트가 `Authorization: Digest ...` 포함해서 재시도
- 서버가 username, realm, uri, nonce, nc, cnonce, response 검증
- 해시가 맞으면 등록 진행
- 성공 시 `200 OK`

## 검증하는 값

현재 구현은 아래를 검증한다.

- `username`
- `realm`
- `nonce`
- `uri`
- `response`
- `algorithm=MD5` 또는 algorithm 생략
- `qop=auth` 또는 qop 생략
- `nc` 증가 여부
- nonce 만료 여부

## 응답 형식

인증 실패 또는 미제공 시:

```text
SIP/2.0 401 Unauthorized
WWW-Authenticate: Digest realm="SIPLite", nonce="...", algorithm=MD5, qop="auth"
```

인증 성공 시:

```text
SIP/2.0 200 OK
```

## 테스트 추가 내용

기본 SIP 코어 테스트에 인증 흐름 검증이 추가됐다.

- 파일: `tests/test_sipcore.cpp`

추가된 검증:

- 인증 비밀번호가 있는 단말은 첫 `REGISTER`에 `401 Unauthorized`
- 응답에서 `nonce`, `realm` 추출 가능
- 올바른 Digest 응답으로 재요청 시 `200 OK`
- 등록 상태가 실제로 `loggedIn=true`로 갱신됨

전체 회귀 확인:

```bash
make clean
make test_all
```

2026-03-29 기준 전체 테스트 통과.

## 이번 구현의 의도적 범위

이번 변경은 `REGISTER` 보호에 집중한 1차 보완이다.
즉, 인증 없는 모든 문제를 한 번에 끝내는 구현은 아니다.

아직 남아 있는 범위:

- `ACK` 인다이얼로그 검증 강화
- `BYE` / in-dialog `MESSAGE` 송신자 검증 강화
- AoR 전체 기준 조회로 개선
- XML 평문 비밀번호 저장 방식 개선

## 현재 한계

### 1. 비밀번호가 평문이다

XML의 `<password>`는 평문으로 저장된다.
운영 환경에서는 해시 저장 또는 별도 credential 저장소가 더 적절하다.

### 2. realm 고정

현재 realm은 `SIPLite`로 고정되어 있다.
멀티도메인 또는 운영 설정 기반 realm 분리는 아직 없다.

### 3. 알고리즘 범위 제한

현재는 `MD5`만 처리한다.
`MD5-sess`, `SHA-256` 계열은 아직 미지원이다.

### 4. qop 범위 제한

현재는 사실상 `auth`만 지원한다.
`auth-int`는 처리하지 않는다.

### 5. REGISTER 외 메서드는 이번 범위 밖이다

이번 변경은 `REGISTER` 인증만 넣었다.
`INVITE`, `BYE`, `MESSAGE` 등에 대한 별도 인증/권한 검사는 아직 없다.

## 수정된 주요 파일

- `include/SipCore.h`
- `src/SipCore.cpp`
- `include/SipUtils.h`
- `src/SipUtils.cpp`
- `include/XmlConfigLoader.h`
- `tests/test_sipcore.cpp`

## 다음 권장 작업

우선순위는 아래 순서가 적절하다.

1. `ACK`, `BYE`, `MESSAGE` dialog 검증 강화
2. AoR 매칭을 user part 기준에서 전체 AoR 기준으로 변경
3. 구독 만료 cleanup 연결
4. XML 평문 비밀번호를 대체할 credential 구조 설계
