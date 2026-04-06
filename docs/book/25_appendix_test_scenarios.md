# 25장. 테스트 시나리오 부록

이 장은 현재 저장소에 들어 있는 테스트들을 기능 시나리오 관점으로 다시 정리한 부록이다. 목적은 두 가지다.

1. 어떤 기능이 이미 검증되고 있는지 파악한다.
2. 아직 비어 있는 테스트 영역을 드러낸다.

기준 파일은 다음과 같다.

- [tests/test_parser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_parser.cpp)
- [tests/test_utils.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_utils.cpp)
- [tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp)
- [tests/test_parser_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_parser_extended.cpp)
- [tests/test_utils_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_utils_extended.cpp)
- [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp)
- [tests/test_transaction.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_transaction.cpp)
- [tests/test_xmlconfig.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_xmlconfig.cpp)
- [tests/test_concurrent_queue.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_concurrent_queue.cpp)
- [tests/test_logger.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_logger.cpp)

## 25.1 테스트 묶음을 어떻게 읽어야 하는가

현재 테스트 구성은 프레임워크 중심이 아니라 주제 중심이다. 즉 "parser 테스트", "utils 테스트", "sipcore 테스트"처럼 파일 단위로 책임이 나뉜다.

이 구조는 작은 프로젝트에서는 이해하기 쉽다. 다만 시간이 지나면 같은 기능 시나리오가 여러 테스트 파일에 분산될 수 있으므로, 책에서는 다시 "기능별 시나리오"로 재분류해 주는 것이 좋다.

## 25.2 Parser 시나리오

Parser 계열 테스트는 [src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp)가 raw SIP 메시지를 어떻게 해석하는지 검증한다.

대표 시나리오는 다음 범주로 묶을 수 있다.

1. 요청/응답 라인 파싱
2. 헤더 추출
3. compact header 지원
4. `Content-Length` 일관성 검증
5. malformed 메시지 거부

이 테스트들의 의미는 단순 문자열 처리가 아니다. parser가 흔들리면 그 위의 모든 REGISTER/INVITE/TLS 기능이 잘못된 전제 위에 올라가게 되므로, parser는 가장 기초적인 방어선이다.

## 25.3 Utils 시나리오

Utils 계열 테스트는 SIP URI, 헤더 문자열, sanitize 로직, 각종 helper 함수의 정확성을 본다. 겉으로 보기에는 사소하지만, 실제로는 로그 안정성, 헤더 조작, 입력 검증의 기반이다.

책에서는 이 영역을 "프로토콜 주변부를 안정화하는 기반 유틸리티"라고 설명하는 편이 적절하다.

## 25.4 SipCore 기본 시나리오

[tests/test_sipcore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore.cpp)와 [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp)는 가장 중요한 테스트 묶음이다. 이유는 이들이 실제 프로토콜 동작과 가장 가깝기 때문이다.

특히 extended 테스트는 helper를 통해 `SipCore`를 만들고, sender callback에 전송 기록을 남기며, raw SIP 메시지를 직접 구성해서 `handlePacket()`에 넣는 형태를 사용한다. 이는 단위 테스트와 통합 시뮬레이션의 중간쯤에 위치한 방식이다.

## 25.5 REGISTER 시나리오

[tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp) 초반부에는 REGISTER 관련 시나리오가 비교적 촘촘히 들어 있다.

예를 들면 다음과 같은 케이스를 볼 수 있다.

- `Expires: 0`을 이용한 deregistration
- 잘못된 `Expires` 값에 대한 `400 Bad Request`
- 음수 `Expires` 거부
- `To` 또는 `Contact` 누락 REGISTER 거부

이 테스트들은 단순 성공 경로보다 실패 경로를 더 잘 드러낸다. 즉 구현이 "정상 케이스만 처리"하는 수준이 아니라, 입력 오류에 대해 어떤 응답을 내는지까지 일부 검증하고 있다.

## 25.6 INVITE 시나리오

INVITE 관련 테스트는 다음 범주로 나누어 읽으면 좋다.

1. 등록된 단말로의 라우팅
2. 미등록 대상에 대한 실패 응답
3. provisional/final response 전달
4. `PendingInvite` 생성과 정리
5. Timer C 연계 정리

이 영역은 사실상 프록시 동작의 중심이다. 책에서는 "호출 성립 시나리오"와 "호출 실패 시나리오"를 나눠서 설명하면 독자가 이해하기 쉽다.

## 25.7 ACK, BYE, CANCEL 시나리오

현재 테스트 helper를 보면 `makeBye()` 같은 생성기가 들어 있고, ACK/BYE/CANCEL 흐름도 별도 시나리오로 다뤄진다.

이 시나리오의 핵심은 다음과 같다.

- ACK가 active call 또는 pending 상태를 따라 올바르게 라우팅되는가
- BYE가 대화 상대에게 전달되고 상태가 정리되는가
- CANCEL이 아직 최종 응답 전 INVITE에 대해서만 적절히 처리되는가

이 부분은 실제 통화 수명주기를 설명할 때 중요한 테스트 근거가 된다.

## 25.8 SUBSCRIBE/NOTIFY 시나리오

구독 관련 테스트는 REGISTER/INVITE만큼 오래된 경로는 아닐 수 있지만, 현재 프로젝트가 이미 `SUBSCRIBE`와 `NOTIFY`를 코드 수준에서 지원하고 있다는 근거가 된다.

여기서 확인해야 할 핵심은 다음과 같다.

1. 구독 생성
2. 구독 갱신
3. 구독 해제
4. 초기 NOTIFY 또는 상태 통지
5. 만료 cleanup

이 시나리오는 event package 전체 준수 여부보다, 서버 내부 상태 관리가 제대로 이어지는지에 초점을 두고 읽는 것이 맞다.

## 25.9 Transport/TLS 시나리오

현재 테스트는 transport-aware 동작을 어느 정도 확인한다. 특히 helper 내부의 `TransportType`과 `viaToken()`은 UDP/TCP/TLS별 헤더 및 송신 경로가 달라질 수 있음을 반영한다.

다만 여기서 중요한 것은 "TLS 테스트가 곧 실제 TLS 핸드셰이크 통합 테스트를 의미하지는 않는다"는 점이다. 많은 경우 `SipCore` 수준 테스트는 transport 타입이 전달되는지, 헤더가 올바르게 구성되는지, sender callback이 어떤 transport로 호출되는지를 본다.

따라서 실제 SSL 소켓, 인증서 파일, peer verification까지 검증하려면 별도의 통합 테스트나 수동 검증이 추가로 필요하다.

## 25.10 Transaction/Dialog 시나리오

[tests/test_transaction.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_transaction.cpp)는 transaction과 dialog 문맥을 직접 보는 테스트다. 이 파일은 SIPLite가 단순 패킷 전달기가 아니라, 요청과 응답의 관계를 상태로 관리하려는 프로젝트라는 점을 보여 준다.

책에서는 이 테스트를 바탕으로 "이 프로젝트는 완전한 범용 transaction engine은 아니지만, 통화와 응답 라우팅에 필요한 최소 상태 모델을 구현한다"고 설명하는 것이 적절하다.

## 25.11 XML 설정 시나리오

[tests/test_xmlconfig.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_xmlconfig.cpp)는 입력 파일 검증과 XML 로드 정책을 확인하는 근거다. 이 테스트는 SIP 프로토콜 자체보다 "운영 입력 안전성"을 보는 축이다.

특히 다음 항목들을 기대할 수 있다.

- 경로 검증
- 파일 크기 제한
- 잘못된 XML/위험한 패턴 거부
- tag 추출과 필드 변환

이 테스트는 문서에서 종종 간과되지만, 실제 운영 관점에서는 상당히 중요하다.

## 25.12 Concurrent Queue와 Logger 시나리오

[tests/test_concurrent_queue.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_concurrent_queue.cpp)와 [tests/test_logger.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_logger.cpp)는 네트워크 프로토콜 자체보다 시스템 품질을 떠받치는 테스트다.

- concurrent queue는 워커 분산과 스레드 안전성의 기반이다.
- logger는 운영 관측 가능성의 기반이다.

즉 "부가 기능 테스트"가 아니라, 서버다운 서버로 동작하기 위한 기반 품질 테스트로 읽는 것이 맞다.

## 25.13 현재 테스트의 강점

현재 테스트 구성의 장점은 다음과 같다.

1. 기능별로 파일이 분리되어 있다.
2. raw SIP 메시지를 직접 만들기 때문에 프로토콜 감각을 유지한다.
3. 실패 경로 테스트가 포함되어 있다.
4. sanitizer 타겟과 결합하기 좋다.

특히 [Makefile](/home/windmorning/projects/SIPWorks/SIPLite/Makefile)의 `test_all`, `asan_test_all`, `tsan_test_sipcore_ext`는 테스트 전략이 단순 "성공 여부"를 넘어서 있음을 보여 준다.

## 25.14 아직 약한 테스트 영역

문서화 관점에서, 테스트가 없는 영역도 함께 써야 정직한 분석서가 된다. 현재 코드 성격상 다음 영역은 추가 테스트 가치가 크다.

1. 실제 TLS 소켓 기반 통합 테스트
2. 장시간 cleanup/expiration 테스트
3. 대량 동시 REGISTER/INVITE 부하 테스트
4. malformed TCP/TLS stream fragmentation 테스트
5. hostname verification 관련 보안 테스트
6. 콘솔 종료와 stdin close 경계 테스트

즉 현재 테스트는 기능 검증에는 충분히 도움 되지만, production-hardening 관점에서는 아직 확장 여지가 많다.

## 25.15 추천 시나리오 분류 체계

표 8은 현재 테스트를 기능 기준으로 다시 묶은 커버리지 요약표다.

| 기능 영역 | 테스트 파일 | 커버 상태 | 메모 |
|---|---|---|---|
| Parser | `test_parser*.cpp` | 양호 | compact header, length 검증 |
| Utils | `test_utils*.cpp` | 양호 | 문자열/URI/helper |
| Register/Auth | `test_sipcore*.cpp` | 양호 | 성공/실패/해지 포함 |
| Invite/Call | `test_sipcore_extended.cpp` | 양호 | 상태 기반 시나리오 |
| Transaction/Dialog | `test_transaction.cpp` | 보통 | 추가 확장 가능 |
| XML config | `test_xmlconfig.cpp` | 양호 | 입력 안전성 |
| TLS 통합 | 부분 | 부족 | 실제 SSL 통합은 더 필요 |
| Stress/Load | 거의 없음 | 부족 | 별도 필요 |

책이나 팀 문서에서 테스트를 더 읽기 쉽게 만들려면 아래 분류 체계를 추천한다.

1. Parser/입력 검증
2. Registration/인증
3. Call setup/teardown
4. Subscription/event
5. Transport/TLS
6. Runtime/config/logging
7. Concurrency/stress

이렇게 분류하면 독자는 테스트 파일 이름보다 "무슨 품질 속성을 검증하는가"를 먼저 이해할 수 있다.

## 25.16 이 장의 핵심 정리

현재 SIPLite 테스트는 작지만 의미 있는 범위를 커버한다. 특히 `SipCore` 중심 시나리오와 parser 검증은 프로젝트 이해에 큰 도움을 준다.

하지만 책에서는 테스트 존재 자체보다 "무엇이 검증되었고 무엇이 아직 비어 있는가"를 함께 써야 한다. 그래야 독자가 현재 구현의 신뢰 범위를 현실적으로 판단할 수 있다.
