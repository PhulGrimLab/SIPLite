# 27장. 성능과 확장성 관점

이 장은 SIPLite를 성능과 확장성 관점에서 읽는다. 목표는 벤치마크 숫자를 임의로 추정하는 것이 아니라, 현재 코드 구조가 어떤 처리 특성을 가질지 설명하는 것이다.

기준 파일은 다음과 같다.

- [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)
- [src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp)
- [src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp)
- [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)
- [include/concurrent_queue.h](/home/windmorning/projects/SIPWorks/SIPLite/include/concurrent_queue.h)
- [src/Logger.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/Logger.cpp)
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)

## 27.1 성능을 볼 때 가장 먼저 봐야 할 것

이 프로젝트는 단일 이벤트 루프 기반 시스템이 아니라, 수신 계층과 워커 큐, 공통 `SipCore`가 결합된 구조다. 따라서 성능은 다음 세 층으로 나누어 봐야 한다.

1. 소켓 수신과 메시지 추출
2. 워커 큐 분산
3. `SipCore` 내부 상태 접근과 메시지 조작

즉 "빠른가"라는 질문보다 "어느 층에서 병목이 생길 가능성이 큰가"를 먼저 보는 것이 맞다.

## 27.2 워커 수 자동 설정의 의미

[src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)는 `std::thread::hardware_concurrency()`를 기반으로 워커 수를 정한다. 정책은 대략 다음과 같다.

- 논리 코어 수 기반
- `hwThreads - 1`
- 최소 1
- 최대 8

이 정책은 보수적이고 실용적이다. 무작정 코어 수만큼 늘리지 않고, 과도한 스레드 폭증을 막는다.

장점은 다음과 같다.

- 작은 장비에서도 안전하다.
- 초과 스레드 생성에 따른 컨텍스트 스위칭을 줄인다.
- 기본값 없이도 적당히 동작한다.

다만 성능 문서에서는 이 한계도 같이 적어야 한다. 고코어 서버에서 최대 8개로 제한하면, 대형 장비의 잠재 성능을 다 쓰지 못할 수 있다.

## 27.3 `Call-ID` 기반 워커 라우팅의 장점

transport 서버들은 대체로 `Call-ID`를 기준으로 워커 큐를 선택한다. 이는 SIP에서 매우 합리적인 선택이다. 같은 호출 또는 같은 메시지 흐름이 같은 워커에 들어가면 상태 일관성을 유지하기 쉬워지기 때문이다.

이 접근의 장점은 다음과 같다.

1. 같은 call/session 관련 메시지가 같은 스레드에 모일 가능성이 높다.
2. 락 경쟁을 줄일 수 있다.
3. 메시지 순서 문제를 다루기 쉬워진다.

즉 완전한 actor 모델은 아니지만, 그 방향에 가까운 실용적 설계다.

## 27.4 큐 기반 구조의 장점과 비용

[include/concurrent_queue.h](/home/windmorning/projects/SIPWorks/SIPLite/include/concurrent_queue.h)는 단순한 mutex + condition_variable 기반 큐다. 이 구조의 장점은 구현이 명확하고 디버깅이 쉽다는 점이다.

하지만 비용도 있다.

- lock contention
- 큐 복사/이동 비용
- wakeup/notify 비용
- 큐 포화 시 drop 가능성

즉 현재 구조는 "극단적 고성능 최적화"보다는 "명확한 동작과 충분한 성능"을 우선한 설계라고 보는 편이 맞다.

## 27.5 UDP, TCP, TLS의 성능 특성 차이

현재 세 transport는 같은 `SipCore`를 공유하지만, 성능 특성은 서로 다르다.

### UDP

장점:
- 연결 상태가 단순하다.
- 수신 오버헤드가 낮다.

한계:
- 메시지 크기와 손실에 민감하다.
- 재전송/순서 보장을 transport가 해주지 않는다.

### TCP

장점:
- 스트림 기반이므로 큰 메시지에 유리하다.
- 재전송과 순서 보장을 transport가 맡는다.

한계:
- 메시지 경계 추출 비용이 있다.
- 연결 수가 늘수록 상태 관리가 필요하다.

### TLS

장점:
- 기밀성과 인증을 제공한다.
- TCP 기반 안정성을 공유한다.

한계:
- 핸드셰이크 비용
- 암복호화 비용
- 인증서 검증 비용
- 연결 재사용 및 소켓 상태 관리 복잡성

즉 성능 관점에서는 당연히 TLS가 가장 비싸다. 하지만 이 비용은 단순 CPU 사용률뿐 아니라, 연결 수명 관리와 오류 처리 비용까지 포함해 이해해야 한다.

## 27.6 `SipCore`가 잠재 병목이 되는 이유

현재 구조에서 모든 프로토콜 로직은 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)로 모인다. 이것은 기능 일관성에는 좋지만, 성능 관점에서는 잠재 병목 후보이기도 하다.

이유는 다음과 같다.

1. 상태 저장소가 한 중심부에 모여 있다.
2. 메시지 재작성과 응답 생성이 같은 계층에서 수행된다.
3. REGISTER, INVITE, SUBSCRIBE, response 처리 경로가 모두 같은 중심 클래스를 지난다.

즉 요청 종류가 늘수록 `SipCore`의 코드 복잡도뿐 아니라 실행 hot path도 두꺼워질 수 있다.

## 27.7 로깅이 성능에 주는 영향

[src/Logger.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/Logger.cpp)는 로그 로테이션과 flush 정책을 가진다. `SIPLITE_LOG_FLUSH_EVERY`도 지원한다. 이 점은 성능 조절에 유용하다.

하지만 로그는 항상 비용을 갖는다.

- 문자열 조립
- 시간 포맷팅
- mutex 획득
- 파일 flush 또는 write
- 콘솔 출력

특히 SIP 서버처럼 패킷 단위 로그가 많은 시스템에서는, "로직 자체보다 로그가 더 비싼" 순간이 생길 수 있다. 따라서 성능 평가 시에는 반드시 로그 레벨과 flush 정책을 함께 봐야 한다.

## 27.8 cleanup 루프의 비용 특성

[src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)는 1초 간격으로 다음 cleanup을 수행한다.

- `cleanupTimerC()`
- `cleanupExpiredRegistrations()`
- `cleanupExpiredSubscriptions()`
- `cleanupStaleCalls()`
- `cleanupStaleTransactions()`

이 구조는 이해하기 쉽고 운영도 단순하다. 하지만 상태 수가 커질수록 주기 스캔 비용이 누적될 수 있다. 즉 현재 구조는 "규모가 적당한 동안은 충분히 좋은" 방식이고, 상태 수가 매우 커지면 별도 타이머 휠이나 우선순위 큐 기반 만료 관리가 필요해질 수 있다.

## 27.9 확장성 관점에서 가장 중요한 질문

이 프로젝트의 확장성을 판단할 때는 단순 TPS보다 다음 질문이 더 중요하다.

1. 동시 등록 수가 늘면 cleanup과 lookup 비용이 어떻게 변하는가
2. 동시 통화 수가 늘면 `ActiveCall`/`PendingInvite` 관리 비용이 어떻게 변하는가
3. TLS 연결 수가 늘면 `TlsServer` 연결 맵과 `SSL_*` 호출 비용이 어떻게 변하는가
4. 로그량이 늘면 파일 I/O와 lock 비용이 얼마나 커지는가

즉 확장성은 네트워크 속도만의 문제가 아니라, 상태 수와 운영 관측 비용까지 함께 보는 문제다.

## 27.10 현재 구조의 강점

현재 코드 기준으로 성능에 유리한 요소도 분명 있다.

1. 멀티워커 구조
2. `Call-ID` 기반 분산
3. 큐 최대 크기 제한
4. transport별 수신 계층 분리
5. 하나의 공통 `SipCore`를 통한 기능 일관성

특히 작은 팀이나 개인 프로젝트에서는 "충분히 빠르고 이해 가능한 구조"가 "최대 성능이지만 복잡한 구조"보다 더 낫다. SIPLite는 현재 전자에 가깝다.

## 27.11 현재 구조의 한계

반대로 성능/확장성 한계도 분명하다.

1. 워커 수 상한 8개
2. `SipCore` 집중형 구조
3. 주기적 전체 cleanup 스캔 가능성
4. logger lock과 I/O 비용
5. TLS 연결 관리 복잡도

즉 현재 구조는 중간 규모까지는 실용적일 수 있지만, 대규모 carrier-grade SIP 서버와 같은 확장성을 기대하는 구조는 아니다.

## 27.12 추천 측정 항목

표 10은 성능 장을 실제 측정 계획으로 확장할 때 출발점이 되는 지표들이다.

| 지표 | 의미 | 수집 방법 예시 |
|---|---|---|
| REGISTER TPS | 등록 처리량 | 부하 도구 + 로그 카운트 |
| INVITE TPS | 호출 설정 처리량 | 시나리오 테스트 |
| 응답 지연 p95/p99 | tail latency | 타임스탬프 기반 측정 |
| 워커 큐 길이 | 내부 적체 | 큐 상태 로깅/계측 |
| TLS 연결 수 | 연결 부담 | TlsServer 상태 조회 |
| 로그 flush 비용 | I/O 영향 | flush 정책 비교 실험 |
| cleanup CPU 비용 | 주기 정리 부담 | profiling |

책이나 분석서에 성능 장을 더 확장하려면, 다음 항목을 실제 측정 지표로 제안하는 것이 좋다.

1. 초당 REGISTER 처리 수
2. 초당 INVITE 처리 수
3. 동시 active call 수
4. 동시 TLS 연결 수
5. 평균 응답 지연과 95/99 percentile
6. 워커 큐 길이
7. 로그 flush 정책별 처리량 차이
8. cleanup 주기별 CPU 사용량 차이

이런 지표를 제안하면 책이 단순 설명을 넘어서, 실제 실험 가능한 분석서가 된다.

## 27.13 개선 아이디어

성능을 더 올리기 위한 현실적인 후보는 다음과 같다.

1. 워커 수 설정 외부화
2. hot path 로그 최소화
3. 상태 저장소 세분화
4. cleanup 자료구조 개선
5. TLS 연결 재사용 정책 정교화

이 중에서도 가장 쉬우면서 효과가 큰 것은 보통 "로그와 상태 저장소 분리"다. 반면 transport 계층 재작성은 비용이 크고 회귀 위험도 크다.

## 27.14 이 장의 핵심 정리

현재 SIPLite는 고도로 최적화된 통신 스택이라기보다, 멀티워커와 공통 코어를 조합한 실용적 서버 구조다. 작은 규모에서 중간 규모까지는 이해 가능성과 충분한 성능을 같이 노린 설계로 읽는 것이 맞다.

병목 후보는 `SipCore`, 로그, cleanup, TLS 연결 관리 쪽에 있고, 확장성 개선은 워커 정책, 상태 저장소 분리, hot path 단순화에서 시작하는 편이 현실적이다.
