# 28장. 운영 체크리스트

이 장은 SIPLite를 실제로 실행하고 유지할 때 확인해야 할 항목을 체크리스트 형태로 정리한 것이다. 앞선 장들이 구조와 개념을 설명했다면, 이 장은 "실행 전", "실행 중", "문제 발생 시" 무엇을 확인해야 하는지에 초점을 둔다.

기준 파일은 다음과 같다.

- [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)
- [src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp)
- [src/Logger.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/Logger.cpp)
- [scripts/start_tls.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/start_tls.sh)
- [scripts/ensure_tls_certs.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/ensure_tls_certs.sh)
- [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)

## 28.1 실행 전 체크리스트

표 11은 운영 전 최소 점검 항목을 빠르게 훑기 위한 요약표다.

| 구분 | 점검 항목 |
|---|---|
| Build | `make all`, 테스트 바이너리 확인 |
| Config | XML 경로, AOR/contact/transport 확인 |
| Port | 5060/5061 사용 가능 여부 |
| TLS | cert/key/CA/verify 정책 확인 |
| Logs | `logs/` 쓰기 권한, 보존 기간 설정 |
| Runtime | REGISTER/INVITE/BYE 기본 동작 확인 |
| Cleanup | registration/subscription/timer 정리 확인 |
| Shutdown | 정상 종료와 로그 flush 확인 |

### 빌드 환경

- `g++`와 OpenSSL 개발 헤더가 설치되어 있는가
- `make all`이 정상 완료되는가
- 필요한 테스트 바이너리가 함께 빌드되는가

### 설정 파일

- 사용할 설정 파일 경로가 [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)의 경로 검증을 통과하는가
- `config/terminals.xml` 또는 대체 파일이 존재하는가
- `aor`, `contact`, `ip`, `port`, `transport`, `expires`, `password` 값이 의도와 맞는가

### 포트와 권한

- UDP/TCP 5060 포트 사용 가능 여부를 확인했는가
- TLS 5061 포트 사용 가능 여부를 확인했는가
- `logs/` 디렉터리에 쓰기 권한이 있는가

### TLS

- TLS를 켤 것인지 결정했는가
- 운영용 인증서와 키 파일 경로를 확인했는가
- self-signed 개발 인증서를 운영 환경에 그대로 쓰지 않는가
- `SIPLITE_TLS_VERIFY_PEER`, `SIPLITE_TLS_REQUIRE_CLIENT_CERT` 정책을 정했는가

## 28.2 초기 기동 체크리스트

서버가 시작되면 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)는 로그 초기화, XML 로딩, UDP 시작, TCP 시작, TLS 조건부 시작, sender wiring, 단말 bootstrap 등록, 콘솔 시작 순으로 진행한다.

초기 기동 시 확인할 항목은 다음과 같다.

- 로그에 서버 시작 메시지가 남는가
- XML 로딩 성공 메시지가 출력되는가
- UDP 서버 기동 메시지가 보이는가
- TCP 서버가 실패 없이 시작되었는가
- TLS 활성화 시 인증서/키 오류 없이 기동되는가
- bootstrap 단말 수가 기대값과 일치하는가

## 28.3 평문 운용 체크리스트

TLS를 쓰지 않는 환경이라면 최소한 다음을 확인해야 한다.

- REGISTER가 정상적으로 `200 OK`를 받는가
- INVITE가 등록된 단말로 라우팅되는가
- BYE/CANCEL 후 상태 정리가 되는가
- 로그에 malformed 패킷 드롭이 과도하게 발생하지 않는가

평문 운용은 단순하지만, 네트워크 노출 환경에서는 보안 위험도 더 크므로 내부망 또는 테스트 환경 전제로 쓰는 것이 바람직하다.

## 28.4 TLS 운용 체크리스트

TLS를 켠 경우에는 추가로 다음을 확인한다.

- `make run_tls` 또는 동등한 환경 변수 설정으로 정상 기동되는가
- 인증서 CN/SAN이 테스트 단말의 기대와 맞는가
- TLS 연결 수립 후 실제 SIP 메시지가 처리되는가
- peer verification 설정이 기대한 방향으로 동작하는가
- hostname verification 미구현 한계를 운영 문서에 반영했는가

특히 "TLS 포트가 열렸다"와 "보안 정책이 완성되었다"는 같은 말이 아니다. 운영 문서에는 반드시 이 차이를 적어야 한다.

## 28.5 로그 운영 체크리스트

[src/Logger.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/Logger.cpp)는 시간 단위 로그 로테이션과 보존 기간 정책을 가진다. 운영자는 다음 항목을 확인해야 한다.

- 로그 파일이 `logs/siplite_YYYYMMDD_HH.txt` 형태로 생성되는가
- 보존 일수 `SIPLITE_LOG_RETENTION_DAYS`가 기대대로 적용되는가
- `SIPLITE_LOG_FLUSH_EVERY` 정책이 너무 공격적이거나 느슨하지 않은가
- 인증 관련 민감 헤더가 과도하게 노출되지 않는가
- 로그량이 디스크 사용량과 성능에 미치는 영향이 허용 범위인가

## 28.6 런타임 상태 점검 체크리스트

콘솔 인터페이스가 살아 있다면 [src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp)를 통해 다음을 주기적으로 확인할 수 있다.

- 서버 상태
- 등록된 단말 수
- 활성 통화 수
- 종료 요청 동작

운영 문서에는 "어떤 메뉴가 무엇을 의미하는가"를 한 번 더 요약해 두는 것이 좋다. 콘솔 자체는 단순하지만, 장애 상황에서는 단순한 인터페이스가 더 유용할 수 있다.

## 28.7 주기 정리 작업 체크리스트

메인 루프는 1초마다 cleanup 계열 함수를 호출한다. 따라서 다음 항목을 확인할 필요가 있다.

- 만료 등록이 적절히 사라지는가
- 만료 구독이 적절히 사라지는가
- stale call과 transaction이 누적되지 않는가
- Timer C timeout이 기대대로 발동하는가

이 부분은 기능 검증뿐 아니라 메모리와 상태 누수 관점에서도 중요하다.

## 28.8 장애 대응 체크리스트

문제가 생겼을 때는 다음 순서로 보는 것이 좋다.

1. 로그에 시작/종료/오류 메시지가 있는가
2. 설정 파일이 바뀌었는가
3. TCP/TLS 서버가 부분적으로만 실패했는가
4. 특정 transport에서만 문제가 재현되는가
5. 등록 상태는 정상인데 라우팅이 실패하는가
6. cleanup 누락 또는 timeout 처리 이상이 있는가

이 순서는 실제로 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)와 [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)의 책임 구조를 그대로 반영한다.

## 28.9 테스트 기반 운영 체크리스트

배포 전에는 최소한 다음 정도의 검증 루틴을 권장할 수 있다.

- `make test_all`
- `make asan_test_all`
- 필요 시 `make tsan_test_sipcore_ext`
- 평문 REGISTER/INVITE/BYE 수동 검증
- TLS REGISTER/INVITE 수동 검증

이 프로젝트는 sanitizer 타겟이 이미 있으므로, 운영 전 검증 루틴에서 이를 활용하지 않는 것은 아쉬운 선택이 될 수 있다.

## 28.10 종료 절차 체크리스트

정상 종료 시 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)는 대략 다음 순서를 따른다.

1. 콘솔 정지
2. TLS 서버 정지
3. TCP 서버 정지
4. UDP 서버 정지
5. 로거 종료

운영자가 확인해야 할 것은 다음이다.

- 종료 명령이 실제로 루프를 빠져나오게 하는가
- stdin close 기반 종료가 환경에 맞는가
- TLS 연결 정리가 지연되지 않는가
- 로그 flush가 마지막까지 수행되는가

## 28.11 운영 문서에 꼭 넣어야 할 경고

경고 상자:
개발용 self-signed 인증서를 운영에 그대로 쓰지 말 것.
TLS hostname verification은 아직 미구현이다.
콘솔 인터페이스는 로컬 표준 입력 기반이므로 서비스 환경과의 상호작용을 따로 검토해야 한다.
로그는 민감 정보 노출 위험을 항상 점검해야 하며, 대규모 부하 환경에서는 cleanup, logging, TLS 비용을 별도로 평가해야 한다.

책이나 운영 가이드에는 아래 경고를 별도 박스로 넣는 것이 좋다.

1. 개발용 self-signed 인증서를 운영에 그대로 쓰지 말 것
2. TLS hostname verification은 아직 미구현이라는 점
3. 콘솔 인터페이스는 로컬 표준 입력 기반이라는 점
4. 로그에는 민감 정보가 남지 않도록 정책 검토가 필요하다는 점
5. 대규모 부하 환경에서는 cleanup, logging, TLS 비용을 별도로 평가해야 한다는 점

이 경고는 단점 나열이 아니라, 실제 운영자가 실수하기 쉬운 지점을 미리 드러내는 역할을 한다.

## 28.12 추천 운영 루틴

일상 운영 관점에서는 다음 정도의 루틴이 현실적이다.

### 매 기동 전

- 설정 파일 diff 확인
- 인증서 만료일 확인
- 포트 사용 상태 확인

### 매 기동 직후

- 로그 파일 생성 확인
- bootstrap 등록 수 확인
- 평문 또는 TLS health check 수행

### 주기 점검

- 등록/구독 수 추이 확인
- 로그 디스크 사용량 확인
- stale state 누적 여부 확인

### 배포 전

- 테스트 전체 실행
- 보안 정책 검토
- 장애 복구 절차 점검

## 28.13 이 장의 핵심 정리

SIPLite는 실행 자체는 단순하지만, 운영은 여전히 여러 층으로 나뉜다. 설정, TLS, 로그, cleanup, 종료 절차를 각각 따로 확인해야 한다.

이 체크리스트는 그 과정을 문장 대신 행동 항목으로 바꿔 준다. 책의 마지막 부록으로도 유용하고, 실제 운영 핸드북의 초안으로도 바로 쓸 수 있다.
