# 15. 콘솔 인터페이스와 운영 관찰성

## 15.1 이 장의 목적

SIPLite는 완전히 headless한 데몬만은 아니다. 현재 코드는 콘솔 기반 운영 인터페이스를 제공하며, 이를 통해 서버 상태, 등록 단말, 활성 통화, 연결 수 등을 확인할 수 있다.

핵심 코드:

- [include/ConsoleInterface.h](/home/windmorning/projects/SIPWorks/SIPLite/include/ConsoleInterface.h)
- [src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp)
- [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L219)

## 15.2 콘솔 인터페이스의 구조

`ConsoleInterface`는 [include/ConsoleInterface.h](/home/windmorning/projects/SIPWorks/SIPLite/include/ConsoleInterface.h#L26)에 정의되어 있다.

생성 시 다음 객체를 받는다.

- `UdpServer&`
- `TcpServer*`
- `TlsServer*`

즉 콘솔은 단순 문자열 명령 처리기가 아니라, 실제 서버 객체를 직접 조회하는 운영 인터페이스다.

## 15.3 왜 입력 스레드와 처리 스레드를 나누는가

[src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp#L40) 이후를 보면 콘솔은 두 개의 스레드를 사용한다.

- `inputLoop()`
- `consoleLoop()`

이 분리의 목적은 명확하다.

- `std::getline`은 블로킹 I/O다.
- 입력 대기 때문에 상태 출력과 종료 절차가 꼬이지 않도록 해야 한다.
- 입력 수집과 명령 실행을 분리하면 종료 처리와 동기화가 쉬워진다.

즉 이 콘솔은 단순 while-loop가 아니라 운영 중 종료 안정성을 고려한 구조다.

## 15.4 종료 시 stdin 닫기

[src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp#L75) 이후에는 Unix에서 `STDIN_FILENO`를 닫아 블로킹 `getline`을 끊는 코드가 있다.

이 선택은 다소 공격적이지만, 프로세스 종료를 빠르게 보장하기 위한 실용적 조치다.

문서에는 이 사실을 남겨둘 가치가 있다.

- 콘솔 종료는 부드러운 UI 종료보다 프로세스 안전 종료를 우선한다.

## 15.5 명령 체계

[src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp#L230)의 `processCommand()`를 보면 현재 지원 명령은 비교적 단순하다.

- `1`, `status`
- `2`, `terminals`, `reg`
- `3`, `calls`
- `4`, `exit`, `quit`, `q`
- `h`, `help`, `?`

즉 운영 인터페이스는 현재 "관찰과 종료"에 초점을 둔 미니 콘솔이다.

## 15.6 입력 검증

[src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp#L201)의 `validateConsoleInput()`는 허용 문자를 강하게 제한한다.

허용:

- 영문자
- 숫자
- 공백
- `-`, `_`, `?`, `.`

거부:

- 한글 포함 비ASCII
- 기타 특수문자

이 설계는 과도하게 보일 수 있지만, 콘솔 입력도 외부 입력으로 보고 안전하게 제한하려는 의도다.

## 15.7 서버 상태 화면

[src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp#L266)의 `showServerStatus()`는 현재 운영자가 가장 먼저 보게 되는 정보다.

표시 항목:

- 서버 실행 상태
- 활성 transport (`UDP`, `TCP`, `TLS`)
- 등록된 단말 수
- 로그인 단말 수
- 활성 통화 수
- TCP 연결 수
- TLS 연결 수
- 현재 시간

이 정보는 [include/SipCore.h](/home/windmorning/projects/SIPWorks/SIPLite/include/SipCore.h#L800)의 `ServerStats`와 각 서버의 `connectionCount()`를 조합해 만든다.

즉 콘솔은 이미 프로젝트 내부 통계 모델을 활용하는 운영 뷰다.

## 15.8 등록된 단말 현황

[src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp#L331)의 `showRegisteredTerminals()`는 등록 정보를 표 형태로 보여준다.

이 함수는 단순 목록 출력 이상을 한다.

- 현재 등록 목록 조회
- 활성 통화 목록 조회
- busy AoR 집합 생성
- 만료 시간 계산
- 상태 문자열 생성

즉 운영자는 단말이 등록돼 있는지뿐 아니라, 현재 바쁜지/오프라인인지 같은 의미 정보를 같이 볼 수 있다.

## 15.9 활성 통화 현황

`showActiveCalls()`는 `SipCore::getAllActiveCalls()`를 사용해 현재 통화 상태를 보여준다. 이 뷰는 `ActiveCall` 모델이 실제 운영 관찰성에도 쓰이고 있음을 보여준다.

이 장에서는 코드 전체를 다 옮기기보다, 중요한 의미를 적는 편이 좋다.

- 통화는 단순 count가 아니라 실제 call record로 조회 가능하다.
- 확인된 통화와 미확정 통화 구분이 가능하다.
- caller/callee 방향 문맥을 화면에서 표현할 수 있다.

## 15.10 운영 인터페이스의 철학

현재 콘솔 인터페이스는 기능이 많진 않지만, 철학은 분명하다.

- 명령은 적다.
- 읽기 중심이다.
- 종료는 명시적이다.
- 상태 정보는 실제 코어 통계에서 읽는다.

즉 이 인터페이스는 "운영 자동화 API"보다 "수동 점검용 로컬 오퍼레이터 콘솔"에 가깝다.

## 15.11 로그와 함께 봐야 하는 이유

콘솔이 즉시 상태를 보여준다면, 로그는 시간 축을 보여준다. 이 프로젝트는 `Logger`를 꽤 적극적으로 사용하므로 운영 관찰성은 다음 두 축으로 이루어진다.

- 콘솔: 현재 상태
- 로그: 시간 순 이벤트

책에서는 이후 `logs/` 디렉터리의 실제 예제를 붙여 "상태 뷰와 이벤트 로그를 같이 읽는 법"을 설명할 수 있다.

## 15.12 현재 한계

현재 콘솔 인터페이스는 실용적이지만 제한적이다.

- 동적 설정 변경 기능 없음
- 특정 callId/AoR 필터 조회 없음
- 로그 레벨 변경 같은 운영 제어 없음
- 원격 관리 인터페이스 없음

즉 현재는 로컬 수동 운영용 최소 인터페이스라고 보는 편이 맞다.

## 15.13 이 장의 핵심 정리

SIPLite의 콘솔 인터페이스는 작지만 의미 있다.

- 서버 상태를 즉시 확인할 수 있고
- 등록/통화 상태를 실제 코어에서 읽어오며
- TCP/TLS 연결 수까지 운영자가 볼 수 있다

즉 이 프로젝트는 단순 라이브러리가 아니라 실제 실행형 서버로서의 운영 감각을 어느 정도 갖추고 있다.

다음 장에서는 지금까지 설명한 흐름을 실제 SIP 메시지 예제로 정리한다.
