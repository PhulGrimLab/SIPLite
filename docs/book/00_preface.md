# 서문

이 문서는 `/home/windmorning/projects/SIPWorks/SIPLite`를 분석하고 이해하기 위해 작성한 원고다. 출발점은 단순했다. "현재 코드가 실제로 무엇을 하고 있는지 정확히 이해하고, 그 결과를 나중에 책으로 남길 수 있게 하자"는 목적이었다.

SIPLite는 겉으로 보면 비교적 작은 C++ 프로젝트처럼 보인다. 하지만 코드를 실제로 따라가 보면 단순한 샘플을 넘어서는 요소가 이미 들어 있다. `REGISTER`, `INVITE`, `ACK`, `BYE`, `CANCEL`, `SUBSCRIBE`, `NOTIFY`, Digest 인증, UDP/TCP/TLS transport, XML 설정, 로그, 콘솔, 테스트, cleanup 루프가 하나의 코드베이스 안에서 연결되어 있다.

그래서 이 원고는 "기능 목록 정리"보다 "코드가 어떻게 연결되어 동작하는가"를 설명하는 데 더 큰 비중을 둔다. 다시 말해, 이 책은 SIP 이론서도 아니고 C++ 문법 해설서도 아니다. 이 책이 풀고자 하는 질문은 더 구체적이다.

1. 이 프로젝트의 중심은 무엇인가
2. 실제 실행 흐름은 어떤 순서로 이어지는가
3. 각 SIP 메서드는 코드에서 어디를 타는가
4. TLS는 실제 구현인지, 흔적인지
5. 현재 구조의 강점과 약점은 무엇인가
6. 앞으로 어떻게 확장하거나 정리할 수 있는가

이 질문들은 모두 현재 코드 기준으로 답한다. 즉 설계 의도나 이상적인 구조를 상상해서 쓰지 않고, 지금 저장소에 있는 파일과 함수, 테스트, 스크립트, 로그 기준으로 서술한다.

## 이 문서를 읽는 방법

이 원고는 처음부터 끝까지 순서대로 읽어도 되지만, 독자 성격에 따라 더 효율적인 경로가 있다.

### SIP 구조를 먼저 이해하고 싶은 독자

다음 순서를 권한다.

1. [01_project_overview.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/01_project_overview.md)
2. [02_entrypoint_and_runtime.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/02_entrypoint_and_runtime.md)
3. [03_transport_layers.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/03_transport_layers.md)
4. [04_sipcore_flow.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/04_sipcore_flow.md)
5. [06_state_and_data_model.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/06_state_and_data_model.md)

### 실제 SIP 흐름을 먼저 보고 싶은 독자

다음 순서를 권한다.

1. [09_register_flow.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/09_register_flow.md)
2. [10_invite_call_flow.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/10_invite_call_flow.md)
3. [11_bye_cancel_ack.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/11_bye_cancel_ack.md)
4. [12_subscribe_notify.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/12_subscribe_notify.md)
5. [17_sequence_diagrams.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/17_sequence_diagrams.md)

### 운영과 배포를 먼저 보고 싶은 독자

다음 순서를 권한다.

1. [15_console_and_operations.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/15_console_and_operations.md)
2. [21_build_run_and_deployment.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/21_build_run_and_deployment.md)
3. [24_appendix_configuration_reference.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/24_appendix_configuration_reference.md)
4. [28_operations_checklist.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/28_operations_checklist.md)

### 코드를 실제로 수정해야 하는 독자

다음 순서를 권한다.

1. [18_code_reading_guide.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/18_code_reading_guide.md)
2. [20_appendix_key_functions.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/20_appendix_key_functions.md)
3. [23_architecture_refactoring_roadmap.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/23_architecture_refactoring_roadmap.md)
4. [26_security_review.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/26_security_review.md)
5. [27_performance_and_scalability.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/27_performance_and_scalability.md)

## 이 문서의 태도

이 원고는 두 가지를 동시에 지키려고 한다.

첫째, 구현을 과장하지 않는다.  
둘째, 이미 잘된 부분은 분명히 인정한다.

예를 들어 TLS는 실제 구현이지만 hostname verification은 아직 미구현이다. Digest 인증은 동작하지만 credential 저장 정책은 단순하다. `SipCore`는 프로젝트의 강점이지만, 동시에 책임이 몰리는 지점이기도 하다. 이런 식으로 장점과 한계를 같이 적는 태도를 유지했다.

## 왜 이 프로젝트를 책으로 남길 가치가 있는가

SIPLite는 교육용으로도, 분석용으로도, 리팩터링 출발점으로도 의미가 있다. 이유는 복잡한 SIP 서버의 핵심 요소들이 비교적 직접적인 코드 구조 안에 들어 있기 때문이다. 거대한 프레임워크 속에 묻혀 있지 않고, `main.cpp`, transport 서버들, `SipCore`, parser, 테스트 파일들을 따라가면 전체 그림을 잡을 수 있다.

즉 이 프로젝트는 "완벽하게 분리된 교과서적 구조"라서 가치가 있는 것이 아니라, 실제 구현의 밀도와 타협이 그대로 드러나기 때문에 가치가 있다. 그 점이 오히려 배우기 좋은 코드베이스를 만든다.

## 마지막 안내

이 문서는 이미 책의 뼈대를 갖추고 있지만, 동시에 살아 있는 작업 문서이기도 하다. 따라서 이후 코드가 바뀌면 문서도 함께 갱신해야 한다. 가장 중요한 원칙은 하나다.

`문서는 반드시 현재 코드보다 앞서가지 말고, 항상 현재 코드에 의해 검증되어야 한다.`

이 원칙을 지키는 한, 이 원고는 분석서이면서 동시에 좋은 기술 문서의 기반이 될 수 있다.
