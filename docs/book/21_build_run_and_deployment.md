# 21장. 빌드, 실행, 배포 절차

이 장은 SIPLite를 "코드로 이해하는 것"에서 한 단계 더 나아가, 실제로 빌드하고 실행하고 운영하는 절차를 정리한다. 기준은 현재 저장소의 빌드 스크립트와 런타임 초기화 코드다.

핵심 기준 파일은 다음과 같다.

- [Makefile](/home/windmorning/projects/SIPWorks/SIPLite/Makefile)
- [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)
- [scripts/start_tls.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/start_tls.sh)
- [scripts/ensure_tls_certs.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/ensure_tls_certs.sh)
- [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)

## 21.1 이 프로젝트의 실행 산출물

이 저장소는 라이브러리와 바이너리를 분리한 CMake 프로젝트가 아니라, 하나의 메인 서버 바이너리와 여러 개의 테스트 바이너리를 `Makefile`로 직접 구성하는 구조다.

[Makefile](/home/windmorning/projects/SIPWorks/SIPLite/Makefile) 기준으로 최종 서버 바이너리는 `build/my_siplite`다. `all` 타겟은 `src/*.cpp` 전체를 컴파일해서 이 바이너리를 만든다.

테스트 바이너리는 기능별로 나뉜다.

- `build/test_parser`
- `build/test_utils`
- `build/test_sipcore`
- `build/test_parser_extended`
- `build/test_utils_extended`
- `build/test_sipcore_extended`
- `build/test_transaction`
- `build/test_xmlconfig`
- `build/test_concurrent_queue`
- `build/test_logger`

이 구조는 실무적으로 두 가지 의미가 있다.

첫째, 서버 본체와 테스트가 느슨하게 분리되어 있다. 즉 테스트를 전부 통과했다고 해서 런타임 초기화 경로가 완전히 검증되는 것은 아니다. 특히 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)에서 수행하는 시그널 처리, 콘솔 시작, 실제 소켓 바인딩, TLS 활성화 여부는 통합 실행에서 다시 확인해야 한다.

둘째, 정적 라이브러리 단위의 모듈 경계보다 "소스 묶음" 중심으로 빌드되므로, 하나의 헤더 변경이 꽤 넓은 재컴파일을 유발할 수 있다. 현재 단계에서는 단순하지만, 프로젝트가 더 커지면 빌드 시간 관리가 별도 과제가 될 수 있다.

## 21.2 요구 조건과 빌드 전제

현재 빌드 시스템은 `g++`, `pthread`, OpenSSL 개발 헤더를 전제로 한다. 이 점은 [Makefile](/home/windmorning/projects/SIPWorks/SIPLite/Makefile)의 다음 요소에서 드러난다.

- `CXX = g++`
- `CXXFLAGS = -Wall -Wextra -std=c++17 -g -I./include -pthread $(OPENSSL_CFLAGS)`
- `LDFLAGS = -pthread $(OPENSSL_LIBS)`
- `/usr/include/openssl/err.h` 존재 여부 검사

즉 최소 전제는 다음과 같이 정리할 수 있다.

1. C++17을 지원하는 `g++`
2. POSIX 스레드 환경
3. OpenSSL 개발 패키지
4. Linux 계열 런타임

특히 OpenSSL 헤더가 없으면 `Makefile`이 곧바로 중단된다. 즉 TLS를 옵션처럼 보이게 만들었지만, 실제 빌드 전제에서는 이미 OpenSSL이 필수 의존성이다. 이것은 "TLS는 선택, 빌드는 공통" 구조다.

## 21.3 기본 빌드 흐름

표 6은 `Makefile`에서 실제로 자주 쓰게 되는 타겟을 빠르게 보여 준다.

| 타겟 | 용도 |
|---|---|
| `make all` | 기본 서버 빌드 |
| `make debug` | 디버그 빌드 |
| `make release` | 릴리즈 빌드 |
| `make run_plain` | 평문 실행 |
| `make run_tls` | TLS 실행 스크립트 경유 |
| `make test_all` | 전체 테스트 실행 |
| `make asan_test_all` | ASan/UBSan 기반 테스트 |
| `make tsan_test_sipcore_ext` | TSan 기반 동시성 집중 테스트 |

가장 단순한 빌드 절차는 다음과 같다.

```bash
make all
```

이 명령은 [Makefile](/home/windmorning/projects/SIPWorks/SIPLite/Makefile)의 `all` 타겟을 따라 `build/` 디렉터리를 만들고, `src/*.cpp`를 오브젝트로 컴파일한 뒤 `build/my_siplite`를 링크한다.

개발 단계에서 자주 쓰일 수 있는 타겟은 아래와 같다.

- `make debug`
- `make release`
- `make clean`
- `make rebuild`
- `make test_all`
- `make asan_test_all`
- `make tsan_test_sipcore_ext`

여기서 주목할 점은 sanitizer 지원이 이미 빌드 시스템 안에 들어 있다는 것이다. `asan_test_all`과 `tsan_test_sipcore_ext`는 단순 편의 기능이 아니라, 현재 코드가 멀티스레드 서버라는 점을 고려하면 상당히 중요한 운영 전 사전 검증 루틴이다.

## 21.4 디버그 빌드와 릴리즈 빌드의 의미

`debug` 타겟은 `-DDEBUG -O0`를 추가한다. `release` 타겟은 `-O2 -DNDEBUG`와 심볼 제거용 `-s`를 추가한다.

이 차이는 단순한 속도 차이만이 아니다.

- 디버그 빌드는 로그와 디버깅, 크래시 분석에 유리하다.
- 릴리즈 빌드는 실제 처리량과 배포 크기에 유리하다.

다만 현재 프로젝트는 런타임 로그를 꽤 적극적으로 남기므로, 초반 분석 단계에서는 디버그 빌드가 더 적합하다. 반면 장시간 호출 테스트나 대량 REGISTER/INVITE 부하를 걸어볼 때는 릴리즈 빌드가 더 현실적인 성능 값을 준다.

## 21.5 실행 경로: UDP, TCP, TLS

[src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp) 기준으로 서버 기동 절차는 다음 순서로 진행된다.

1. 시그널 핸들러 등록
2. 로그 시스템 초기화
3. 단말 설정 XML 로드
4. UDP 서버 시작
5. TCP 서버 시작
6. 환경 변수에 따라 TLS 서버 시작
7. `SipCore::setSender(...)`로 전송 콜백 연결
8. XML에 정의된 단말 초기 등록
9. 콘솔 인터페이스 시작
10. 메인 루프에서 cleanup 작업 반복

여기서 중요한 구조적 포인트는 UDP가 항상 기준 서버라는 점이다.

- `UdpServer udpServer;`
- `TcpServer tcpServer(udpServer.sipCore());`
- `TlsServer tlsServer(udpServer.sipCore());`

즉 `SipCore`는 `UdpServer`가 보유하고, TCP/TLS 서버는 같은 `SipCore`를 공유한다. 이 말은 운용 관점에서 "프로토콜별로 로직이 분산된 것이 아니라, 수신 계층만 다르고 처리 코어는 공통"이라는 뜻이다.

## 21.6 TLS 실행은 왜 스크립트가 필요한가

평문 실행은 `make run_plain`으로 충분하지만, TLS 실행은 `make run_tls`가 [scripts/start_tls.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/start_tls.sh)를 호출한다.

이 스크립트가 필요한 이유는 세 가지다.

1. 바이너리 존재 여부 확인
2. 인증서/키 경로 환경 변수 정리
3. 인증서가 없으면 자동 생성 스크립트 호출

즉 현재 TLS 실행은 "프로세스 시작"보다 "실행 환경 조립"에 더 가깝다.

[scripts/start_tls.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/start_tls.sh)는 다음 환경 변수를 다룬다.

- `SIPLITE_TLS_PORT`
- `SIPLITE_TLS_CERT_FILE`
- `SIPLITE_TLS_KEY_FILE`
- `SIPLITE_TLS_CA_FILE`
- `SIPLITE_TLS_VERIFY_PEER`
- `SIPLITE_TLS_REQUIRE_CLIENT_CERT`
- `SIPLITE_TLS_CERT_CN`
- `SIPLITE_TLS_CERT_SAN_IP`
- `SIPLITE_TLS_CERT_SAN_DNS`

그 뒤 내부적으로 [scripts/ensure_tls_certs.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/ensure_tls_certs.sh)를 호출하고, 마지막에 `SIPLITE_TLS_ENABLE=1`을 설정한 상태로 `build/my_siplite`를 실행한다.

## 21.7 인증서 자동 생성의 의미

[scripts/ensure_tls_certs.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/ensure_tls_certs.sh)는 인증서와 키 파일이 없을 때 OpenSSL 명령으로 self-signed 인증서를 생성한다.

이 설계는 개발 편의성 측면에서는 매우 유용하다. 처음 실행하는 사용자가 인증서 준비 때문에 막히지 않기 때문이다.

하지만 운영 관점에서는 분명한 제약도 있다.

- 기본 인증서는 self-signed다.
- CN과 SAN 값은 개발 기본값 `127.0.0.1`, `localhost` 중심이다.
- 외부 단말과 상호 인증을 하려면 CA 파일과 검증 정책을 별도로 정해야 한다.

즉 자동 생성은 "TLS 기능을 빠르게 켜 보는 데모 경로"로 보는 것이 맞고, 운영 배포에서는 명시적 인증서 관리 절차가 별도로 필요하다.

## 21.8 TLS 검증 정책

[src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)의 `TlsServer::initializeSsl()`과 `TlsServer::configureVerification()`을 보면 검증 정책이 환경 변수에 의해 결정된다.

- `SIPLITE_TLS_VERIFY_PEER`
- `SIPLITE_TLS_REQUIRE_CLIENT_CERT`
- `SIPLITE_TLS_CA_FILE`

구체적으로는 다음과 같다.

- `verifyPeer = true`이면 outbound TLS 연결에서 상대 인증서 체인을 검증한다.
- `requireClientCert = true`이면 inbound TLS 연결에서 클라이언트 인증서를 요구한다.
- `caFile`이 있으면 명시한 CA 저장소를 사용한다.
- `caFile`이 없으면 기본 시스템 CA 경로를 시도한다.

중요한 세부 사항이 하나 있다. [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)에는 "hostname verification is still not implemented"라는 취지의 로그가 들어 있다. 즉 체인 검증은 지원하지만, 원격 호스트 이름 검증까지 완성된 것은 아니다. 이 점은 TLS를 "보안 완성"으로 오해하지 않게 해 준다.

## 21.9 운영자가 알아야 할 런타임 환경 변수

이 프로젝트는 설정 파일뿐 아니라 환경 변수로도 런타임 정책을 바꾼다. 현재 코드 기준으로 눈에 띄는 항목은 다음과 같다.

- `SIPLITE_LOG_RETENTION_DAYS`
- `SIPLITE_TLS_ENABLE`
- `SIPLITE_TLS_PORT`
- `SIPLITE_TLS_CERT_FILE`
- `SIPLITE_TLS_KEY_FILE`
- `SIPLITE_TLS_CA_FILE`
- `SIPLITE_TLS_VERIFY_PEER`
- `SIPLITE_TLS_REQUIRE_CLIENT_CERT`
- `SIPLITE_TLS_CERT_CN`
- `SIPLITE_TLS_CERT_SAN_IP`
- `SIPLITE_TLS_CERT_SAN_DNS`

운영 문서를 작성할 때는 이 값을 "필수", "선택", "개발용", "운영용"으로 다시 분류하는 것이 좋다. 현재는 스크립트와 코드에 분산되어 있으므로, 초보 사용자는 전부를 한 번에 파악하기 어렵다.

## 21.10 추천 실행 시나리오

정리 상자:
개발 환경에서는 `run_plain`, `run_tls`, `test_all` 중심으로 기능 확인을 빠르게 반복하는 편이 좋다.
운영 준비 단계에서는 여기에 sanitizer 테스트, 인증서 정책, 로그 보존 정책, 포트/권한 검토까지 함께 포함해야 한다.

분석과 검증을 위해서는 실행 시나리오를 분리하는 편이 좋다.

### 1) 평문 기본 동작 확인

```bash
make all
make run_plain
```

이 경로는 UDP/TCP 수신, XML 로딩, 콘솔 인터페이스, 로그 파일 생성이 정상인지 확인하는 가장 단순한 시나리오다.

### 2) TLS 포함 전체 기동 확인

```bash
make all
make run_tls
```

이 경로는 인증서 자동 생성, TLS 포트 기동, `TransportType::TLS` 기반 송신 경로를 함께 점검한다.

### 3) 기능 회귀 테스트

```bash
make test_all
```

### 4) 메모리 오류 확인

```bash
make asan_test_all
```

### 5) 동시성 이슈 집중 확인

```bash
make tsan_test_sipcore_ext
```

현재 프로젝트의 특성상, 단순 기능 테스트보다 sanitizer 기반 검증의 가치가 높다. 이유는 `UdpServer`, `TcpServer`, `TlsServer`가 워커 스레드와 공유 상태를 함께 사용하기 때문이다.

## 21.11 배포 시 주의할 점

현재 코드와 스크립트 기준으로 운영 배포 시 체크해야 할 항목은 다음과 같다.

1. `config/terminals.xml`이 운영 환경에 맞는지 확인
2. `logs/` 쓰기 권한 확인
3. 5060/5061 포트 바인딩 정책 확인
4. self-signed 인증서 대신 운영 인증서 배치
5. `SIPLITE_TLS_VERIFY_PEER`와 `SIPLITE_TLS_REQUIRE_CLIENT_CERT` 정책 결정
6. 로그 보존 기간 `SIPLITE_LOG_RETENTION_DAYS` 결정
7. 종료 절차에서 콘솔, TLS, TCP, UDP가 순서대로 정리되는지 확인

특히 [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)의 종료 경로는 `console.stop()`, `tlsServer.stop()`, `tcpServer.stop()`, `udpServer.stop()` 순으로 진행된다. 운영 중 hang이나 느린 종료가 생긴다면 이 순서를 기준으로 원인을 좁혀 볼 수 있다.

## 21.12 이 장의 핵심 정리

이 프로젝트의 빌드와 실행은 단순히 `make` 한 번으로 끝나는 구조가 아니다. 실제로는 다음 세 층이 겹친다.

1. `Makefile`이 담당하는 컴파일과 테스트
2. `main.cpp`가 담당하는 런타임 초기화와 transport 조립
3. TLS 스크립트가 담당하는 인증서 준비와 실행 환경 구성

따라서 책을 쓸 때도 "빌드", "실행", "TLS 준비", "운영 배포"를 한 문단에 섞기보다, 지금처럼 층을 분리해서 서술하는 편이 독자의 이해에 훨씬 유리하다.
