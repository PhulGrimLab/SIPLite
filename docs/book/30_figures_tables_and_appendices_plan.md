# 30장. 도표, 표, 부록 편집 계획

이 장은 원고를 더 읽기 쉽게 만들기 위한 편집 계획을 정리한다. 지금 원고는 텍스트 밀도가 높고 코드 참조가 풍부해서 분석서로는 좋지만, 책으로 읽기에는 시각적 완충 장치가 더 필요하다. 그 역할을 하는 것이 그림, 표, 예제 박스, 부록이다.

## 30.1 왜 도표가 필요한가

SIPLite 같은 프로젝트는 텍스트만으로도 설명할 수 있지만, 독자가 실제로 이해하는 속도는 시각 자료의 유무에 크게 좌우된다. 특히 다음 주제는 도표가 들어가면 이해가 급격히 쉬워진다.

1. 전체 구조
2. REGISTER 흐름
3. INVITE와 응답 흐름
4. ACK/BYE/CANCEL 분기
5. SUBSCRIBE/NOTIFY 수명주기
6. UDP/TCP/TLS 비교
7. 상태 저장 구조

따라서 출판용 편집에서는 각 부마다 최소 하나 이상의 대표 도표가 필요하다.

## 30.2 우선 넣어야 할 그림 목록

### 그림 1. 전체 아키텍처 지도

내용:

- `main.cpp`
- `UdpServer`
- `TcpServer`
- `TlsServer`
- `SipCore`
- `SipParser`
- `XmlConfigLoader`
- `ConsoleInterface`
- `Logger`

이 그림은 책 초반, [01_project_overview.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/01_project_overview.md) 또는 [02_entrypoint_and_runtime.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/02_entrypoint_and_runtime.md) 근처에 배치하는 것이 가장 효과적이다.

### 그림 2. REGISTER 처리 흐름도

내용:

- REGISTER 수신
- To/Contact 확인
- 인증 필요 여부
- 401 challenge 또는 200 OK
- Registration 저장

이는 [09_register_flow.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/09_register_flow.md)와 [13_digest_auth.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/13_digest_auth.md)를 묶는 그림이 된다.

### 그림 3. INVITE와 PendingInvite 수명주기

내용:

- INVITE 수신
- 100 Trying
- callee 라우팅
- provisional response
- final response
- ACK
- Timer C timeout 또는 cleanup

이 그림은 [10_invite_call_flow.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/10_invite_call_flow.md)의 핵심 그림이 된다.

### 그림 4. ACK/BYE/CANCEL 분기 지도

이 그림은 [11_bye_cancel_ack.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/11_bye_cancel_ack.md)를 훨씬 읽기 쉽게 만든다.

### 그림 5. SUBSCRIBE/NOTIFY 수명주기

이 그림은 [12_subscribe_notify.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/12_subscribe_notify.md)에 넣는 것이 좋다.

### 그림 6. TLS 연결과 SIP 메시지 흐름

이 그림은 [05_tls_implementation.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/05_tls_implementation.md)와 [17_sequence_diagrams.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/17_sequence_diagrams.md)를 연결하는 역할을 한다.

## 30.3 표로 바꾸면 좋은 내용

현재 원고에는 문장과 bullet로 설명한 내용 중 표가 더 적합한 항목이 많다.

### 표 1. 주요 소스 파일 책임표

열 예시:

- 파일
- 클래스/함수
- 역할
- 읽는 우선순위

### 표 2. SIP 메서드별 처리기 표

열 예시:

- 메서드
- 진입 함수
- 주요 상태
- 주요 응답
- 관련 cleanup

### 표 3. 상태 구조 표

열 예시:

- 구조체
- 위치
- 역할
- 생성 시점
- 제거 시점

### 표 4. transport 비교표

열 예시:

- transport
- 장점
- 한계
- 관련 파일
- 보안 특성

### 표 5. 환경 변수 참조표

열 예시:

- 이름
- 기본값
- 위치
- 영향 범위
- 운영 주의점

### 표 6. 테스트 시나리오 맵

열 예시:

- 기능
- 테스트 파일
- 검증 내용
- 아직 비어 있는 영역

## 30.4 예제 박스로 분리하면 좋은 내용

책의 가독성을 높이려면 일부 내용은 본문에서 분리해 박스로 배치하는 편이 좋다.

추천 박스 유형은 다음과 같다.

1. `코드 읽기 팁`
2. `운영 주의`
3. `보안 경고`
4. `RFC 메모`
5. `실제 패킷 예시`

예를 들어 hostname verification 미구현은 본문 한 줄보다 `보안 경고` 박스로 뽑는 편이 더 효과적이다.

## 30.5 시퀀스 다이어그램의 편집 방향

[17_sequence_diagrams.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/17_sequence_diagrams.md)는 이미 좋은 초안이지만, 출판용으로는 약간 더 다듬을 수 있다.

권장 편집은 다음과 같다.

1. 각 다이어그램 위에 한 줄 요약 추가
2. 각 다이어그램 아래에 코드 참조 2~3개만 핵심적으로 배치
3. 너무 세부적인 branch 설명은 본문으로 옮기고 다이어그램은 단순화

즉 다이어그램은 "전체 흐름 보기" 용도로 두고, 세부 예외 처리는 본문에 남겨두는 편이 좋다.

## 30.6 부록을 어떻게 나눌 것인가

현재 부록 성격의 장은 이미 여러 개 있다. 출판용으로는 부록을 다음처럼 재구성할 수 있다.

### 부록 A. 용어와 RFC

- [22_glossary_and_rfc_map.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/22_glossary_and_rfc_map.md)

### 부록 B. 코드 읽기 안내

- [18_code_reading_guide.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/18_code_reading_guide.md)
- [20_appendix_key_functions.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/20_appendix_key_functions.md)

### 부록 C. 설정과 운영 참조

- [24_appendix_configuration_reference.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/24_appendix_configuration_reference.md)
- [28_operations_checklist.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/28_operations_checklist.md)

### 부록 D. 테스트와 로그

- [19_logs_and_debugging.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/19_logs_and_debugging.md)
- [25_appendix_test_scenarios.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/25_appendix_test_scenarios.md)

이렇게 나누면 부록도 구조적으로 읽히게 된다.

## 30.7 각 장 끝에 넣으면 좋은 고정 요소

출판용 완성도를 높이려면 각 장 끝에 다음 중 2~3개를 고정적으로 넣는 것이 좋다.

1. 핵심 요약
2. 코드 포인트
3. 독자 질문
4. 다음 장 예고

지금 초안에는 이미 `핵심 정리`가 들어간 장이 많으므로, 여기에 `다음 장 예고`만 더 붙여도 책의 흐름이 좋아진다.

## 30.8 실제 편집 작업 순서

도표와 표를 무작정 추가하면 오히려 정리가 안 된다. 따라서 아래 순서가 현실적이다.

1. 전체 아키텍처 그림 먼저 제작
2. REGISTER/INVITE 두 개의 대표 흐름 그림 제작
3. transport 비교표와 상태 구조표 제작
4. 환경 변수 표와 테스트 시나리오 표 제작
5. 부록 재편집

이 순서가 좋은 이유는, 앞부분의 대표 그림 몇 개만으로도 책의 인상이 크게 좋아지기 때문이다.

## 30.9 이 장의 핵심 정리

현재 원고는 내용은 충분하다. 남은 일은 시각화와 편집이다.

즉 다음 단계의 핵심은 새 설명을 더 쓰는 것이 아니라, 이미 있는 설명을 독자가 더 빨리 이해하도록 바꾸는 것이다. 그림, 표, 박스, 부록 구조는 바로 그 작업을 위한 도구다.
