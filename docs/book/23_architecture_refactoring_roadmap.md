# 23장. 아키텍처 리팩터링 로드맵

이 장은 현재 SIPLite를 비판적으로 읽기 위한 장이다. 목적은 "어디가 나쁘다"를 말하는 것이 아니라, 현재 구조가 어떤 이유로 유지보수 비용을 키울 수 있는지 설명하고, 그에 맞는 단계별 리팩터링 순서를 제안하는 것이다.

기준 파일은 다음과 같다.

- [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)
- [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)
- [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h)
- [src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp)
- [src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp)
- [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)
- [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)
- [src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp)

## 23.1 현재 구조의 장점부터 인정해야 한다

리팩터링을 논하기 전에 현재 구조의 장점을 먼저 인정할 필요가 있다.

1. 실행 경로가 단순하다.
2. `SipCore`에 로직이 모여 있어 추적이 쉽다.
3. UDP/TCP/TLS가 같은 코어를 공유해 기능 일관성이 높다.
4. XML 초기 등록, 콘솔, 로깅, 테스트가 한 저장소 안에 모여 있어 실험하기 쉽다.

즉 이 프로젝트는 "작고 빠르게 기능을 확장하기 좋은 구조"다. 문제는 규모가 커질수록 같은 장점이 결합도와 책임 과밀로 바뀐다는 점이다.

## 23.2 가장 큰 구조적 특징: `SipCore` 집중형 설계

[src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)는 사실상 시스템 중심부다. 여기에는 다음이 함께 들어 있다.

- SIP 메서드별 분기
- 인증 처리
- REGISTER 상태 관리
- INVITE pending 상태 관리
- active call 추적
- dialog/transaction 정리
- SUBSCRIBE/NOTIFY 처리
- 응답 생성
- 헤더 재작성
- transport-aware Contact/Via/Record-Route 생성

초기에는 매우 효율적이다. 하지만 시간이 지나면 한 가지 문제가 생긴다. 새로운 기능 하나를 넣을 때마다 `SipCore`를 열어야 하고, 그 수정이 다른 경로에 어떤 영향을 미치는지 머릿속으로 계속 추적해야 한다.

즉 현재 구조의 가장 큰 리스크는 "복잡한 코드"가 아니라 "변경 충돌이 잦아지는 중심부가 하나뿐"이라는 점이다.

## 23.3 우선순위 1: 상태 저장소와 메서드 처리기를 분리하기

가장 먼저 고려할 만한 리팩터링은 `SipCore`를 무조건 여러 파일로 쪼개는 것이 아니다. 먼저 "상태"와 "행위"를 나누는 것이 더 효과적이다.

예를 들면 현재 `SipCore` 내부에는 아래 상태들이 함께 존재한다.

- registration store
- pending invite store
- active call store
- subscription store
- transaction/dialog 관련 상태

이들을 별도 저장소 클래스로 분리하면 얻는 이점은 명확하다.

1. cleanup 함수의 책임이 명확해진다.
2. 테스트가 단순해진다.
3. 락 범위를 더 세밀하게 조절할 수 있다.
4. 상태 구조 변경이 메서드 처리 로직 전체를 흔들지 않게 된다.

예를 들어 다음과 같은 방향을 생각할 수 있다.

- `RegistrationStore`
- `CallStore`
- `SubscriptionStore`
- `TransactionStore`

중요한 점은 처음부터 완전한 DDD 구조를 도입하는 것이 아니라, 현재 `SipCore` 안에 있는 자료구조와 cleanup 함수만 밖으로 옮겨도 효과가 크다는 것이다.

## 23.4 우선순위 2: 메서드별 핸들러 모듈화

현재 `handleRegister()`, `handleInvite()`, `handleAck()`, `handleBye()`, `handleCancel()`, `handleSubscribe()`, `handleNotify()`는 이름으로는 분리되어 있지만 구현 단위는 여전히 하나의 큰 클래스에 매여 있다.

이 경우 생기는 문제는 다음과 같다.

1. 공통 helper의 의존 범위가 계속 넓어진다.
2. 특정 메서드 로직만 별도 리뷰하기 어렵다.
3. 병렬 개발 시 충돌이 잦다.

따라서 두 번째 단계에서는 메서드별 처리기를 분리하는 것이 좋다. 예를 들면 아래와 같은 구성이 가능하다.

- `RegisterHandler`
- `InviteHandler`
- `DialogHandler`
- `SubscriptionHandler`
- `ResponseRouter`

이때 모든 것을 인터페이스 기반으로 과도하게 추상화할 필요는 없다. 가장 실용적인 방식은 `SipCore`가 공통 컨텍스트만 제공하고, 개별 핸들러가 그 컨텍스트를 받아 처리하는 형태다.

## 23.5 우선순위 3: transport 공통부 추출

[src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp), [src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp), [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)를 보면 세 서버는 서로 다른 소켓 특성을 갖지만, 동시에 공통 패턴도 반복한다.

- 수신 루프
- 워커 큐 라우팅
- `Call-ID` 기반 분산
- raw SIP 메시지 추출
- `UdpPacket` 형태로 `SipCore`에 전달

TLS는 SSL 핸드셰이크와 연결 관리가 더 복잡하므로 완전 통합은 어렵다. 하지만 "수신한 SIP 메시지를 워커로 라우팅하는 공통 단계"는 별도 유틸리티나 베이스 컴포넌트로 추출할 수 있다.

이 작업의 목적은 상속 구조를 세우는 것이 아니라, 중복 로직을 줄이고 버그 수정이 transport마다 따로 필요해지는 문제를 줄이는 데 있다.

## 23.6 우선순위 4: 설정 로드와 런타임 등록 정책 분리

[include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)는 현재 다음 역할을 동시에 수행한다.

- 경로 보안 검증
- XML 텍스트 유효성 검사
- 태그 추출
- 타입 변환
- transport 파싱
- `SipCore` 등록 호출

이 구조는 편하지만, "설정을 읽는 것"과 "실제 서버 상태를 바꾸는 것"이 강하게 결합되어 있다. 따라서 설정을 단독 테스트하거나, 나중에 JSON/YAML/DB 기반 설정을 추가하려면 부담이 커진다.

실용적인 리팩터링 방향은 다음과 같다.

1. `XmlConfigLoader`는 `std::vector<TerminalConfig>`만 반환한다.
2. 적용은 별도 `TerminalBootstrapper`나 `ConfigApplier`가 담당한다.

이렇게 나누면 설정 파일 파싱 문제와 등록 정책 문제를 따로 설명하고 테스트할 수 있다.

## 23.7 우선순위 5: 런타임 제어 경로 정리

[src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)는 지금도 읽을 수 있는 수준이지만, 이미 책임이 꽤 많다.

- 시그널 처리
- 로그 초기화
- XML 로딩
- UDP/TCP/TLS 시작
- sender wiring
- 단말 선등록
- 콘솔 시작
- cleanup 루프
- 종료 순서 관리

즉 `main`이 단순 엔트리포인트를 넘어서 "애플리케이션 조립기" 역할까지 맡고 있다.

이 부분은 다음처럼 나눌 수 있다.

- `RuntimeOptions`
- `ServerBootstrap`
- `CleanupScheduler`
- `SignalManager`

이 분리는 기능 추가보다 운영 안정성 측면에서 가치가 크다. 예를 들어 나중에 콘솔 대신 REST 관리 API를 붙이거나, cleanup 간격을 설정으로 빼거나, daemon 모드와 foreground 모드를 나누려 할 때 `main`을 계속 비대하게 만들지 않게 된다.

## 23.8 동시성 관점에서의 개선 포인트

현재 프로젝트는 원자 변수, mutex, worker queue를 적절히 사용하고 있지만, 동시성 설계가 명시적으로 문서화되어 있지는 않다. 이것은 규모가 커질수록 위험하다.

리팩터링 시 다음 질문을 문서로 먼저 고정하는 것이 좋다.

1. 어떤 상태가 어떤 락으로 보호되는가
2. transport 스레드와 worker 스레드의 책임 경계는 무엇인가
3. cleanup 함수는 어떤 thread-safety 전제를 갖는가
4. sender callback은 재진입 가능한가
5. 로그 호출은 hot path에서 어느 정도 비용을 허용하는가

즉 코드 변경보다 먼저 "동시성 규약"을 문서화하는 것이 더 값어치 있는 경우가 많다.

## 23.9 테스트 구조의 개선 방향

현재 테스트는 [tests/test_sipcore_extended.cpp](/home/windmorning/projects/SIPWorks/SIPLite/tests/test_sipcore_extended.cpp)처럼 기능별 시나리오를 손으로 구성해 `assert`로 검증하는 형태다. 이 방식은 단순하고 빠르지만, 케이스가 늘어날수록 유지보수 비용이 커진다.

테스트 쪽 리팩터링 후보는 다음과 같다.

1. 메시지 생성 helper를 별도 공통 파일로 이동
2. transport/인증/통화/구독 시나리오별 fixture 정리
3. 로그 기반 검증과 상태 기반 검증을 분리
4. 통합 테스트와 단위 테스트를 구분

특히 `REGISTER`, `INVITE`, `TLS`, `SUBSCRIBE`는 각각 시나리오 행렬을 만들 수 있으므로, 장기적으로는 데이터 중심 테스트가 더 적합하다.

## 23.10 단계별 실행 로드맵

리팩터링은 한 번에 끝내려 하면 실패하기 쉽다. 현재 프로젝트에는 다음 순서가 현실적이다.

### 단계 1: 문서화 우선

- 현재 상태 구조와 락 정책 문서화
- transport별 공통/차이점 문서화
- `SipCore` 내부 helper 분류표 작성

### 단계 2: 저장소 분리

- registration 관련 자료구조와 cleanup 분리
- subscription 관련 자료구조와 cleanup 분리
- call/pending-invite 관련 자료구조 분리

### 단계 3: 처리기 분리

- `handleRegister()` 계열 분리
- `handleInvite()/handleResponse()` 계열 분리
- `handleSubscribe()/handleNotify()` 계열 분리

### 단계 4: 부트스트랩 정리

- `main`의 초기화와 종료 경로를 조립 코드로 분리
- 설정 적용 계층 분리

### 단계 5: transport 공통화

- 워커 라우팅 공통 유틸리티 추출
- 공통 메시지 extraction 계층 정리

이 순서가 좋은 이유는, 먼저 "위험이 낮고 효과가 큰" 구조부터 건드리기 때문이다. 반대로 transport 계층이나 TLS 내부를 초반에 크게 흔들면 회귀 위험이 커진다.

## 23.11 하지 말아야 할 리팩터링

현재 코드 상태에서 피하는 편이 좋은 것도 있다.

1. 모든 클래스를 인터페이스 기반으로 과도하게 추상화하기
2. transport 서버를 억지 상속 구조로 통합하기
3. 작은 문제를 해결하려고 프레임워크를 도입하기
4. 테스트 정비 없이 대규모 파일 분할부터 시작하기

이 프로젝트는 복잡한 엔터프라이즈 플랫폼이 아니라 비교적 직접적인 네트워크 서버다. 따라서 리팩터링도 단순성과 관측 가능성을 유지하는 방향이어야 한다.

## 23.12 이 장의 핵심 정리

현재 SIPLite의 가장 큰 문제는 "동작하지 않는다"가 아니라 "성장할수록 `SipCore`와 `main`에 책임이 몰린다"는 점이다.

따라서 리팩터링의 핵심 원칙은 다음과 같다.

1. 상태를 먼저 분리한다.
2. 메서드 처리기를 그 다음에 분리한다.
3. transport 공통화는 늦게 한다.
4. 문서화와 테스트를 리팩터링보다 앞에 둔다.

이 원칙을 지키면 프로젝트를 무리 없이 확장하면서도, 현재 갖고 있는 장점인 단순한 실행 흐름을 잃지 않을 수 있다.
