# SIPLite Review

작성일: 2026-03-14
대상 경로: `/home/windmorning/projects/SIPWorks/SIPLite`

## 요약

SIPLite는 현재 "경량 UDP SIP 프록시/레지스트라" 수준까지는 구현되어 있다.

- 지원 메서드: `REGISTER`, `INVITE`, `ACK`, `BYE`, `CANCEL`, `OPTIONS`, `MESSAGE`, `SUBSCRIBE`, `NOTIFY`
- 구현 요소: UDP 수신/송신, `Via` 추가/제거, `Record-Route`, `Max-Forwards`, `Timer C`, 등록/통화/구독 저장소
- 테스트 상태: `make test_all` 기준 전체 통과

테스트는 모두 통과하지만, 운영 환경 기준으로는 인증/세션 검증/만료 관리 측면에서 중요한 보완이 필요하다.

## 확인한 구현 범위

### 현재 되어 있는 부분

- UDP/IPv4 기반 SIP 수신 및 송신
- XML 기반 사전 등록 단말 로드
- 사전 등록 단말에 대한 `REGISTER` 처리
- 등록된 단말로 `INVITE` 프록시 포워딩
- `ACK`, `BYE`, `CANCEL` 기본 전달
- `OPTIONS` 응답
- `MESSAGE` 전달
- `SUBSCRIBE` / `NOTIFY` 기본 처리
- `Timer C` 기반 INVITE 타임아웃 정리
- 다중 워커 + `Call-ID` 기반 라우팅

### 아직 부족하거나 미구현인 부분

- `Authorization` / `Proxy-Authorization` 기반 인증
- SIP Digest 인증
- TCP / TLS / WSS 전송
- DNS / SRV / NAPTR 기반 라우팅
- NAT 대응에서 `received` / `rport` 정교한 처리
- 멀티도메인 AoR 모델
- 포킹(forking)
- 정식 transaction state machine의 실사용 연동
- RTP / SDP 협상 및 미디어 처리

## 주요 취약점 및 보완 필요 사항

### 1. REGISTER 인증 부재

위험도: Critical

현재 `REGISTER`는 XML에 사전 등록된 사용자 여부만 확인하고 로그인 처리한다.
`Authorization`, `Proxy-Authorization`, nonce, Digest 검증이 없다.

영향:

- 임의의 호스트가 사용자 번호만 알면 등록 탈취 가능
- 실제 단말 대신 공격자가 등록 바인딩을 점유 가능
- 이후 호 수신 라우팅이 공격자에게 갈 수 있음

관련 코드:

- `src/SipCore.cpp` `handleRegister()`
- `include/SipCore.h` 등록 저장소 관련 구조

권장 조치:

- SIP Digest 인증 추가
- 미인증 REGISTER에 `401 Unauthorized` 또는 `407 Proxy Authentication Required` 반환
- nonce, realm, qop, nc, cnonce 검증
- 비밀번호는 XML 평문 대신 해시 또는 별도 credential 저장소 사용 검토

### 2. ACK 인다이얼로그 검증 부족

위험도: Critical

현재 `ACK`는 사실상 `Call-ID`와 `CSeq` 중심으로 처리되고, 송신자 검증이 약하다.
기존 통화의 `Call-ID`를 아는 제3자가 ACK를 보내도 통화가 confirmed 상태로 전이될 수 있다.

영향:

- 세션 상태 위조
- 잘못된 ACK 포워딩
- 통화 상태 머신 오염

관련 코드:

- `src/SipCore.cpp` `handleAck()`

권장 조치:

- `Call-ID + From tag + To tag + source tuple(IP:port)` 검증
- dialog route set 기반 검증 강화
- ACK가 기존 dialog와 정확히 매칭될 때만 통과

### 3. BYE / in-dialog MESSAGE 발신자 검증 부족

위험도: Critical

`BYE`와 in-dialog `MESSAGE`는 현재 "caller가 아니면 callee" 식으로 상대를 추정한다.
정상 dialog participant가 아닌 제3자도 `Call-ID`를 안다면 세션 종료나 메시지 주입이 가능하다.

영향:

- 제3자 세션 종료
- 통화 중 메시지 주입
- dialog 상태 교란

관련 코드:

- `src/SipCore.cpp` `handleBye()`
- `src/SipCore.cpp` `handleMessage()`

권장 조치:

- dialog 식별을 `Call-ID` 단독이 아니라 tag 조합까지 확장
- 송신자 IP/port와 저장된 peer 일치 여부 확인
- 불일치 시 `481 Call/Transaction Does Not Exist`

### 4. 사용자 매칭이 user part만 기준

위험도: High

등록 조회 함수가 AoR 전체가 아니라 user part만 비교한다.
예: `sip:1001@a.com` 과 `sip:1001@b.com` 이 충돌 가능

영향:

- 멀티도메인 환경 오동작
- 다른 도메인 사용자를 잘못 라우팅
- 번호 충돌 시 의도하지 않은 단말이 선택될 수 있음

관련 코드:

- `include/SipCore.h` `findByUser_()`

권장 조치:

- AoR 전체 문자열 또는 정규화된 `user@domain` 키 사용
- 멀티도메인을 고려한 등록/조회 구조로 변경

### 5. 구독 만료 정리 미연결

위험도: High

구독 만료 정리 함수는 구현되어 있지만 메인 루프에서 호출하지 않는다.

영향:

- 만료된 `SUBSCRIBE`가 메모리에 계속 남음
- 잘못된 NOTIFY 대상 유지
- 장기 실행 시 상태 누적

관련 코드:

- `include/SipCore.h` `cleanupExpiredSubscriptions()`
- `src/main.cpp` 메인 cleanup 루프

권장 조치:

- 메인 주기 작업에 `cleanupExpiredSubscriptions()` 추가

### 6. Via / Route / Contact 파싱이 단순 문자열 결합 기반

위험도: Medium

파서가 동일 헤더를 모두 콤마로 합친다.
이후 `Via` 등은 첫 콤마까지만 잘라 쓰는 보정 로직이 들어가 있다.
복잡한 URI, quoted string, comma 포함 파라미터가 있으면 깨질 가능성이 있다.

영향:

- 비표준 또는 복합 헤더 처리 실패
- 잘못된 라우팅/포워딩
- 향후 기능 확장 시 파서 한계 노출

관련 코드:

- `src/SipParser.cpp`
- `src/SipCore.cpp` `buildAckForPending()`
- `src/SipCore.cpp` `buildCancelForPending()`

권장 조치:

- `Via`, `Route`, `Record-Route`, `Contact`를 일반 헤더와 분리해 리스트 구조로 저장
- SIP 헤더별 파서를 별도 구현

## 구조 관점에서 본 상태

- 핵심 로직은 `SipCore`에 집중되어 있다.
- 주석이 매우 많아 문서 역할은 하지만, 실제 핵심 로직 추적은 오히려 어려운 편이다.
- `SipTransactionManager`는 구조상 잘 준비되어 있으나 실제 런타임 경로에는 거의 연결되지 않았다.
- 현재는 "테스트 가능한 단일 프로세스 SIP 실험 서버"에 가깝고, 운영 수준 SIP 서버로 보기에는 방어 로직이 더 필요하다.

## 테스트 결과

2026-03-14 기준 아래 명령으로 확인:

```bash
make test_all
```

결과:

- parser tests 통과
- utils tests 통과
- sipcore tests 통과
- extended sipcore tests 통과
- transaction/dialog tests 통과
- xmlconfig tests 통과
- concurrent queue tests 통과
- logger tests 통과

즉, 현재 테스트 스위트 기준으로는 정상이다.
다만 이는 현재 설계 범위 안에서의 정상이며, 인증/보안/운영 내구성까지 보장하지는 않는다.

## 우선 보완 순서

1. `REGISTER`에 SIP Digest 인증 추가
2. `ACK`, `BYE`, `MESSAGE`, `NOTIFY`의 dialog 검증 강화
3. AoR 조회 로직을 전체 AoR 기준으로 변경
4. `cleanupExpiredSubscriptions()`를 메인 루프에 연결
5. `Via/Route/Contact` 파서를 구조화
6. `SipTransactionManager`를 실제 런타임 처리와 연동할지 결정

## 바로 수정하면 효과 큰 항목

단기 효과가 큰 수정은 아래 4개다.

- `REGISTER` 인증 추가
- 인다이얼로그 요청 송신자 검증 추가
- 구독 만료 cleanup 연결
- `findByUser_()` 제거 또는 AoR 전체 매칭으로 변경

## 참고한 주요 파일

- `src/main.cpp`
- `src/UdpServer.cpp`
- `src/SipParser.cpp`
- `src/SipCore.cpp`
- `include/SipCore.h`
- `include/SipTransaction.h`
- `include/SipTransactionManager.h`
- `include/SipDialog.h`
- `tests/*.cpp`

