# 24장. 설정 참조 부록

이 장은 SIPLite를 분석하거나 운영할 때 필요한 설정 항목을 한곳에 모은 참조 부록이다. 앞선 장들이 흐름과 구조를 설명했다면, 이 장은 실제 설정 값을 찾을 때 바로 펼쳐보는 용도에 가깝다.

기준 파일은 다음과 같다.

- [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)
- [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)
- [scripts/start_tls.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/start_tls.sh)
- [scripts/ensure_tls_certs.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/ensure_tls_certs.sh)

## 24.1 설정 계층은 두 종류다

현재 프로젝트의 설정은 크게 두 계층으로 나뉜다.

1. 정적 설정 파일
2. 실행 시 환경 변수

정적 설정 파일은 주로 사전 등록 단말 목록을 뜻하고, 실행 시 환경 변수는 TLS와 로그 보존 정책처럼 프로세스 동작 방식을 제어한다.

## 24.2 기본 설정 파일 경로

[src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)에서 기본 설정 경로는 `config/terminals.xml`이다.

사용자가 인자를 넘기면 다른 경로를 쓸 수 있지만, [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)의 `validateFilePath()`를 통과해야 한다.

즉 설정 파일은 "아무 경로나 자유롭게" 읽는 구조가 아니라, 보안 검증을 전제로 한 제한된 경로 모델이다.

## 24.3 XML 단말 설정 구조

[include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)의 `TerminalConfig`는 다음 필드를 가진다.

- `aor`
- `contact`
- `ip`
- `port`
- `transport`
- `expiresSec`
- `password`
- `description`

책 관점에서 보면 이는 사실상 "정적 bootstrap registration 레코드"다. 즉 단말 계정 정보이면서 동시에 초기 연락 주소의 기본값이다.

## 24.4 XML 태그 의미

코드상 파싱되는 태그는 다음과 같다.

- `<aor>`
- `<contact>`
- `<ip>`
- `<port>`
- `<transport>`
- `<password>`
- `<description>`
- `<expires>`

이 태그들은 모두 필수는 아니다. 하지만 실제 동작 관점에서는 `aor`가 가장 중요하고, `contact`, `ip`, `transport`, `expires`는 등록/로그인 시나리오에 직접 영향을 준다.

## 24.5 `aor`

`aor`는 Address of Record다. 예를 들면 `sip:1001@server` 같은 형태다. [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)의 `isValidAor()` 검증을 통과해야 하며, REGISTER와 라우팅의 기준 키 역할을 한다.

문서에는 다음처럼 설명하는 것이 좋다.

"`aor`는 사용자를 대표하는 논리 주소이며, 실제 접속 지점인 `contact`와는 구분된다."

## 24.6 `contact`

`contact`는 실제 연락 주소다. 예를 들면 `<sip:1001@10.0.0.5:5060>` 형태다. 비어 있으면 런타임 REGISTER 과정에서 실제 패킷 정보를 바탕으로 갱신될 수 있지만, 정적 bootstrap에서는 기본 주소 역할을 한다.

## 24.7 `ip`와 `port`

`ip`와 `port`는 단말의 실제 네트워크 위치를 나타낸다. `port` 기본값은 `5060`이고, 유효하지 않은 값이면 다시 `5060`으로 되돌린다.

현재 코드는 `ip`가 비어 있는 경우를 허용한다. 즉 XML은 완전한 네트워크 인벤토리이기보다, "초기 힌트 + 정책 데이터"로 이해하는 편이 맞다.

## 24.8 `transport`

`transport`는 [include/UdpPacket.h](/home/windmorning/projects/SIPWorks/SIPLite/include/UdpPacket.h)의 `TransportType`으로 파싱된다. 현재 의미 있는 값은 다음 세 가지다.

- `UDP`
- `TCP`
- `TLS`

이 값은 단순 메타데이터가 아니라, `SipCore`가 해당 등록을 통해 요청을 보낼 때 어떤 transport를 우선 사용해야 하는지에 영향을 준다.

## 24.9 `expires`

`expires`는 등록 유효 시간을 초 단위로 의미한다. 비정상 값이면 기본 `3600`초를 사용한다. REGISTER 해제나 refresh 동작을 설명할 때 이 값을 연결해 서술하면 좋다.

## 24.10 `password`

`password`는 Digest 인증 문맥에서 중요하다. 현재 프로젝트는 정적 단말 정보와 인증 정보를 함께 보유하므로, 이 값은 단순 문서 필드가 아니라 실제 인증 검증에 쓰이는 민감한 데이터다.

운영 문서에서는 다음 사항을 함께 적는 것이 좋다.

1. 평문 저장 여부
2. 테스트 환경과 운영 환경 분리 여부
3. 향후 해시 저장 또는 외부 인증 연동 가능성

## 24.11 `description`

`description`은 운영 편의용 메타데이터다. 등록 시 콘솔 출력이나 문서화에 도움이 되지만, 프로토콜 로직에는 직접 관여하지 않는다.

## 24.12 XML 로더의 안전 장치

[include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)는 단순 파서를 넘어서 몇 가지 안전 장치를 둔다.

- 최대 파일 크기 제한 `MAX_FILE_SIZE`
- 최대 단말 수 제한 `MAX_TERMINALS`
- 문자열 길이 제한 `MAX_STRING_LENGTH`
- 태그 깊이 제한 `MAX_TAG_DEPTH`
- 위험한 경로 패턴 차단
- 심볼릭 링크 차단
- 위험한 XML 패턴 차단

이 점은 책에서 강조할 가치가 있다. 이 프로젝트는 단순 예제 서버처럼 보일 수 있지만, 설정 입력에 대해서는 꽤 방어적인 자세를 취하고 있기 때문이다.

## 24.13 런타임 환경 변수 참조

표 7은 런타임 환경 변수를 한눈에 보기 위한 참조표다.

| 변수 | 기본값 | 영향 범위 | 비고 |
|---|---|---|---|
| `SIPLITE_LOG_RETENTION_DAYS` | `7` | 로그 보존 | `main.cpp` |
| `SIPLITE_LOG_FLUSH_EVERY` | `16` | 로그 flush 정책 | `Logger.cpp` |
| `SIPLITE_TLS_ENABLE` | `0` | TLS 시작 여부 | `main.cpp` |
| `SIPLITE_TLS_PORT` | `5061` | TLS 리슨 포트 | `main.cpp` |
| `SIPLITE_TLS_CERT_FILE` | `certs/server.crt` | 인증서 경로 | script/main |
| `SIPLITE_TLS_KEY_FILE` | `certs/server.key` | 키 경로 | script/main |
| `SIPLITE_TLS_CA_FILE` | 없음 | CA 검증 | TLS |
| `SIPLITE_TLS_VERIFY_PEER` | `0` | outbound peer 검증 | TLS |
| `SIPLITE_TLS_REQUIRE_CLIENT_CERT` | `0` | inbound client cert 요구 | TLS |

다음은 현재 코드와 스크립트 기준으로 확인되는 주요 환경 변수다.

### 로그 관련

- `SIPLITE_LOG_RETENTION_DAYS`

설명:
로그 보존 일수를 제어한다. [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)에서 읽으며, 잘못된 값이면 기본 `7`일을 사용한다.

### TLS 활성화 관련

- `SIPLITE_TLS_ENABLE`
- `SIPLITE_TLS_PORT`
- `SIPLITE_TLS_CERT_FILE`
- `SIPLITE_TLS_KEY_FILE`
- `SIPLITE_TLS_CA_FILE`
- `SIPLITE_TLS_VERIFY_PEER`
- `SIPLITE_TLS_REQUIRE_CLIENT_CERT`

설명:
TLS 서버 기동 여부, 리슨 포트, 인증서/키 위치, CA 저장소, peer 검증 정책, 클라이언트 인증서 요구 여부를 제어한다.

### 인증서 자동 생성 관련

- `SIPLITE_TLS_CERT_DIR`
- `SIPLITE_TLS_OPENSSL_CONFIG`
- `SIPLITE_TLS_CERT_DAYS`
- `SIPLITE_TLS_CERT_CN`
- `SIPLITE_TLS_CERT_SAN_IP`
- `SIPLITE_TLS_CERT_SAN_DNS`

설명:
[scripts/ensure_tls_certs.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/ensure_tls_certs.sh)가 self-signed 인증서를 만들 때 사용하는 값들이다.

## 24.14 설정 문서 작성 시 권장 표기법

이 프로젝트를 책이나 운영 매뉴얼로 옮길 때는 설정을 다음 열로 정리하면 읽기 좋다.

1. 이름
2. 위치
3. 기본값
4. 필수 여부
5. 영향 범위
6. 운영 주의사항

예를 들면 `SIPLITE_TLS_VERIFY_PEER`는 "기본값 0, 선택, outbound TLS 검증에 영향, hostname verification 미구현 주의"처럼 적을 수 있다.

## 24.15 예시: 최소 설정 프로필

### 개발용 최소 프로필

- `config/terminals.xml` 준비
- `SIPLITE_TLS_ENABLE=0`
- 기본 로그 보존 기간 사용

이 경우 UDP/TCP 중심으로 기본 기능 분석이 가능하다.

### TLS 포함 개발 프로필

- `SIPLITE_TLS_ENABLE=1`
- `SIPLITE_TLS_CERT_FILE`, `SIPLITE_TLS_KEY_FILE` 기본값 사용 가능
- 필요 시 `make run_tls`

이 경우 self-signed 인증서 기반으로 TLS 경로를 빠르게 확인할 수 있다.

### 운영 준비 프로필

- 운영용 인증서 배치
- `SIPLITE_TLS_VERIFY_PEER=1` 검토
- `SIPLITE_TLS_REQUIRE_CLIENT_CERT=1` 여부 검토
- 로그 보존 정책 조정
- XML에 운영 단말 정보 반영

## 24.16 이 장의 핵심 정리

현재 SIPLite의 설정은 복잡한 외부 시스템에 의존하지 않는다. 대신 XML과 환경 변수만으로 많은 동작을 제어한다.

이 단순함은 장점이지만, 동시에 의미를 정확히 문서화하지 않으면 오해가 생기기 쉽다. 특히 `aor`, `contact`, `transport`, `password`, TLS 환경 변수는 반드시 코드 기준으로 해석해야 한다.

이 부록은 그런 오해를 줄이기 위한 빠른 참조표 역할을 한다.
