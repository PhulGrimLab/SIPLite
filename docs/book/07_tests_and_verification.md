# 7. 테스트와 검증 전략

## 7.1 왜 테스트를 책에 포함해야 하는가

많은 코드 분석 문서는 구현 설명만 하고 테스트는 부록처럼 취급한다. 하지만 SIPLite에서는 테스트가 구현 의도와 현재 보장 범위를 드러내는 핵심 자료다.

이유는 다음과 같다.

- 코드가 점진적으로 확장되어 왔다.
- transport-aware 동작은 문장 설명보다 테스트가 더 분명하다.
- RFC 기반 기대 행동과 실제 구현의 접점을 테스트가 보여준다.
- 리팩터링 시 무엇을 깨뜨리면 안 되는지 테스트가 알려준다.

따라서 이 장은 "테스트 소개"가 아니라 "현재 시스템이 무엇을 보장한다고 말할 수 있는가"를 정리하는 장이다.

## 7.2 테스트 파일 구성

현재 테스트 파일은 [tests](/home/windmorning/projects/SIPWorks/SIPLite/tests) 디렉터리에 있다.

주요 파일:

- [tests/test_parser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_parser.cpp)
- [tests/test_parser_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_parser_extended.cpp)
- [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp)
- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp)
- [tests/test_transaction.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_transaction.cpp)
- [tests/test_utils.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_utils.cpp)
- [tests/test_utils_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_utils_extended.cpp)
- [tests/test_xmlconfig.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_xmlconfig.cpp)
- [tests/test_concurrent_queue.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_concurrent_queue.cpp)
- [tests/test_logger.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_logger.cpp)

이 구성을 보면 프로젝트가 단순 parser 테스트에 머물지 않고, `SipCore`, 설정, 동시성 도구, 로거까지 폭넓게 검증하려 한다는 점을 알 수 있다.

## 7.3 빌드 시스템에서의 테스트 위치

[Makefile](/home/windmorning/projects/SIPWorks/SIPLite/Makefile)는 테스트 타깃을 비교적 잘 정리하고 있다.

중요 타깃:

- `make test`
- `make test_utils`
- `make test_sipcore`
- `make test_parser_ext`
- `make test_utils_ext`
- `make test_sipcore_ext`
- `make test_transaction`
- `make test_xmlconfig`
- `make test_concurrent_queue`
- `make test_logger`
- `make test_all`
- `make asan_test_all`
- `make tsan_test_sipcore_ext`

이 구성은 기능 검증과 sanitizer 검증을 분리하려는 의도를 보여준다.

## 7.4 parser 테스트가 검증하는 것

파서 계열 테스트는 [src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp)의 신뢰 경계를 확인한다.

현재 파서가 책임지는 주요 항목:

- start line 해석
- request / response 판별
- 헤더 map 구축
- compact header 확장
- header continuation 처리
- `Content-Length` 일치 여부 확인
- 크기 제한 검증

책에서는 이 파서 계층을 "보안 입력 게이트"로 설명하는 편이 좋다. 이 프로젝트는 malformed SIP를 관대하게 흘려보내기보다 비교적 일찍 거절하는 편이다.

## 7.5 `SipCore` 테스트가 검증하는 것

`SipCore` 테스트는 프로젝트의 핵심 보장 범위를 드러낸다. 특히 [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp)가 중요하다.

이 테스트는 다음 주제를 다룬다.

- 등록과 로그인 상태
- INVITE 라우팅
- domain-aware AoR 조회
- TLS transport 보존
- cleanup 동작
- subscription 만료 동작
- response 처리

즉 구현 설명을 쓸 때 테스트를 인용하면 "이건 단순히 코드가 이렇게 생겼다"가 아니라 "프로젝트가 이렇게 동작한다고 주장하고 있다"까지 말할 수 있다.

## 7.6 transport-aware 테스트의 중요성

최근 코드의 핵심 가치는 transport-aware routing이다. 이 부분은 특히 테스트 근거를 붙이는 것이 중요하다.

### TLS registration transport 보존

[tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L638)의 테스트는 TLS로 들어온 REGISTER가 `Registration.transport`에 TLS로 저장되고, 이후 전달 INVITE도 TLS transport로 나가는지 검증한다.

이 테스트의 의미는 크다.

- TLS가 단순 수신 transport가 아니다.
- 등록 상태가 transport를 기억한다.
- INVITE 포워딩이 그 transport 정보를 사용한다.

### subscription 만료 후 transport 유지

[tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L805)의 테스트는 만료된 subscription에 대해 `terminated` NOTIFY를 보내면서 subscriber transport를 유지하는지 확인한다.

이 역시 매우 중요한 신호다. 프로젝트가 현재 "모든 응답/알림을 UDP로 떨구는 구조"가 아니라는 뜻이기 때문이다.

## 7.7 domain-aware 라우팅 테스트

AoR 조회가 `user`만 보는지, `user@domain`을 보는지는 SIP 서버에서 의외로 큰 차이를 만든다.

관련 테스트:

- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L672)
- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L699)

이 테스트들은 다음 사실을 보장하려 한다.

- 같은 user라도 domain이 다르면 다른 등록으로 취급
- 존재하지 않는 domain은 다른 domain의 동일 user로 매칭되지 않음

책에서는 이를 "초기 단일 도메인 예제에서 멀티도메인 친화 구조로 진화한 흔적"으로 설명할 수 있다.

## 7.8 cleanup 테스트

cleanup 함수는 실무적으로 중요하지만, 설명 문서에서 종종 빠진다. 그러나 SIPLite는 이 부분도 테스트로 일부 검증한다.

대표 테스트:

- registration 만료 정리: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L723)
- stale call 정리: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L751)
- stale transaction 정리: [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp#L781)

이 테스트들은 시간이 흐른 뒤의 상태 정리를 검증한다. 즉 프로젝트가 단지 요청 순간의 로직만 검증하는 것이 아니라, 상태 수명 관리도 신경 쓴다는 뜻이다.

## 7.9 XML 설정 테스트

[tests/test_xmlconfig.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_xmlconfig.cpp)는 `XmlConfigLoader`를 검증한다.

이 계열 테스트가 중요한 이유:

- XML 기반 정적 등록이 실제 시스템 흐름에 영향을 준다.
- transport를 XML에서 읽는 경로가 있다.
- 잘못된 transport 값이나 URI 형식을 문서가 아니라 코드로 검증한다.

즉 책에서 XML 설정 장을 쓸 때도 테스트를 근거로 삼을 수 있다.

## 7.10 sanitizer 타깃의 의미

`Makefile`에 있는 `asan_test_all`, `tsan_test_sipcore_ext`는 프로젝트가 단순 기능 테스트를 넘어 런타임 오류와 스레드 문제를 의식하고 있음을 보여준다.

### ASan / UBSan

- 메모리 오류
- 정의되지 않은 동작

### TSan

- 동시성 경합
- 락 설계 문제

물론 특정 실행 환경에서는 sanitizer가 제한될 수 있다. 하지만 중요한 점은, 프로젝트가 최소한 이 방향의 검증 채널을 준비해 두었다는 사실이다.

## 7.11 테스트로부터 읽을 수 있는 한계

테스트가 있다는 사실과 테스트가 충분하다는 사실은 다르다. 책에는 이 점도 남겨야 한다.

현재 테스트로부터 추론할 수 있는 한계:

- 실제 외부 SIP UA와의 상호운용성은 별도 문제다.
- TLS 검증 정책의 모든 운영 시나리오가 테스트로 다 덮였다고 보긴 어렵다.
- 장시간 연결 유지, 네트워크 오류, half-open, 재연결 등은 더 실전적인 검증이 필요하다.
- parser와 core가 방어적으로 동작하지만, 공격적 입력에 대한 fuzz 수준 검증은 별도 과제일 수 있다.

## 7.12 책 집필 관점에서의 활용법

테스트는 단순 부록이 아니라 각 장의 근거 자료로 직접 인용하는 것이 좋다.

권장 방식:

- 구조 설명 뒤에 관련 테스트 나열
- "이 동작은 테스트 X에서 확인된다" 식으로 연결
- 구현 의도와 회귀 보호 범위를 함께 적기

예를 들어 TLS 장에서는 다음처럼 연결할 수 있다.

- 구현 근거: `TlsServer.cpp`
- 라우팅 근거: `SipCore.cpp`
- 보장 근거: `test_sipcore_extended.cpp`

이 세 층을 같이 쓰면 문서 신뢰도가 높아진다.

## 7.13 이 장의 핵심 정리

SIPLite의 테스트는 이 프로젝트를 설명하는 데 꼭 필요한 재료다.

- parser가 무엇을 거부하는지
- `SipCore`가 무엇을 보장하는지
- TLS transport가 상태에 어떻게 반영되는지
- cleanup이 실제로 어떤 상태를 정리하는지

를 테스트가 분명하게 보여준다.

다음 장에서는 마지막으로 현재 코드베이스의 리스크와 앞으로 어떤 방향으로 집필과 분석을 이어갈지 정리한다.
