# 14. XML 설정과 정적 단말 모델

## 14.1 이 장의 목적

SIPLite는 동적 REGISTER만으로 동작하는 서버가 아니다. 시작 시점에 XML 설정 파일을 읽어 정적 단말을 등록할 수 있다. 이 구조는 이 프로젝트를 일반적인 public SIP registrar보다 controlled testbed 또는 appliance형 서버에 더 가깝게 만든다.

핵심 코드:

- [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)
- [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L114)
- [config/terminals.xml](/home/windmorning/projects/SIPWorks/SIPLite/config/terminals.xml)

## 14.2 `TerminalConfig`

[include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h#L22)의 `TerminalConfig`는 XML에서 읽은 단말 정보를 담는 구조다.

필드:

- `aor`
- `contact`
- `ip`
- `port`
- `transport`
- `expiresSec`
- `password`
- `description`

이 필드 구성을 보면 XML 설정은 단순 표시용이 아니라 `registerTerminal()`에 거의 직접 대응하는 입력 모델이다.

## 14.3 전체 로드 흐름

`XmlConfigLoader::loadTerminals()`는 다음 순서로 동작한다.

1. 파일 경로 보안 검증
2. 파일 존재 확인
3. 심볼릭 링크 거부
4. 파일 크기 제한 확인
5. XML 본문 읽기
6. 위험 패턴(XXE 등) 검사
7. `<terminal>` 블록 반복 추출
8. 태그별 값 추출
9. 각 필드 검증
10. `TerminalConfig` 목록 반환

즉 XML 파서는 단순 "예제용 문자열 읽기"가 아니라, 보안 제약을 꽤 의식한 loader다.

## 14.4 경로 보안

[include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h#L236)의 `validateFilePath()`는 꽤 공격적으로 경로를 제한한다.

주요 방어:

- 빈 경로 / 과도하게 긴 경로 거부
- 널 바이트 거부
- `..`, `%2e%2e`, 시스템 경로 패턴 거부
- `.xml` 확장자만 허용

이 설계는 "설정 파일도 외부 입력"이라는 보안 관점을 반영한다.

## 14.5 XML 본문 보안

[include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h#L281)의 `validateXmlContent()`는 XXE, 외부 엔티티, URL 기반 리소스 로드를 차단하려고 한다.

거부 패턴:

- `<!ENTITY`
- `<!DOCTYPE`
- `SYSTEM`
- `PUBLIC`
- `FILE://`
- `HTTP://`
- `HTTPS://`
- 기타 scheme

또한 태그 깊이도 제한한다.

즉 이 XML 로더는 범용 XML 파서 대신 제한된 안전 subset을 직접 읽는 전략을 택했다.

## 14.6 왜 정규식을 쓰지 않는가

코드를 보면 XML 파싱은 정규식이 아니라 문자열 검색과 `extractTag()` 기반으로 이루어진다.

이 선택의 장점:

- 단순 구조에서는 구현이 명확하다
- 위험한 XML 기능을 지원하지 않아도 된다
- 디버깅이 쉽다

단점:

- 복잡한 XML 문법 전체를 지원하진 못한다
- 구조가 달라지면 확장성이 낮다

하지만 현재 목적이 "신뢰 가능한 제한된 설정 파일"이라면 충분히 납득 가능한 선택이다.

## 14.7 개별 필드 검증

로더는 각 필드를 별도 검증한다.

### `aor`

- `sip:` 또는 `sips:` 시작
- 길이 제한
- 사용자 부분 문자 제한

### `contact`

- `sip:` 또는 `sips:` 시작
- CRLF, 널 바이트, 제어문자 거부

### `ip`

- IPv4 형식 검증
- 선행 0 거부

### `port`

- `std::from_chars` 기반 예외 없는 파싱
- `1..65535`

### `expires`

- 음수면 0
- 최대값 clamp

### `transport`

- `udp`
- `tcp`
- `tls`

이 검증 덕분에 XML 설정은 비교적 신뢰 가능한 초기 입력이 된다.

## 14.8 transport 설정의 의미

[include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h#L544)의 `parseTransport()`는 `udp`, `tcp`, `tls`를 `TransportType`으로 변환한다.

이것이 중요한 이유는 다음과 같다.

- 동적 REGISTER 없이도 정적 등록 단말의 transport를 지정할 수 있다.
- 테스트 환경에서 곧바로 TLS 단말 모델을 만들 수 있다.
- `main.cpp` 시작 직후부터 transport-aware 라우팅이 가능해진다.

즉 XML 설정은 단말 목록만 주는 것이 아니라, 라우팅 모델의 초기 상태를 만든다.

## 14.9 `registerTerminals()`

[include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h#L209)의 `registerTerminals()`는 `TerminalConfig` 리스트를 `SipCore::registerTerminal()`에 넣는다.

즉 XML loader는 단순 parser가 아니라 `SipCore` 초기화 파이프라인의 일부다.

이 함수는 성공/실패 로그도 남긴다. 따라서 운영자는 어떤 단말이 로드됐는지 시작 시점에서 바로 확인할 수 있다.

## 14.10 `main.cpp`와의 연결

[src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L114) 이후에서 `loadTerminals()`를 호출하고, [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp#L204) 이후에서 `registerTerminals()`를 호출한다.

즉 XML 설정은 서버 초기화 단계의 일부이며, 런타임 동적 재로딩 구조는 아니다.

이 점은 문서에 분명히 적어둘 필요가 있다.

- 현재는 startup-time configuration
- hot reload 시스템은 아님

## 14.11 XML 설정과 REGISTER의 관계

이 프로젝트에서 XML 정적 등록과 REGISTER는 대립 관계가 아니라 연속 관계다.

순서는 대체로 이렇다.

1. XML이 허용 단말과 기본 값, 비밀번호, transport를 미리 정의
2. REGISTER가 실제 로그인 상태와 최신 source 정보를 반영

즉 XML은 "단말 정의", REGISTER는 "단말 활성화"라고 볼 수 있다.

## 14.12 문서로 남겨둘 운영적 의미

XML 설정 모델은 다음 장점을 준다.

- 테스트 환경 재현 용이
- 허용 단말 통제 쉬움
- 비밀번호/transport 초기값 제공
- 실제 REGISTER 이전에도 대상 라우팅 구조 준비 가능

동시에 다음 한계도 있다.

- 사용자 추가/변경이 런타임 동적 시스템이 아님
- XML 포맷 확장이 커지면 수동 파서 유지 부담 증가
- 관리 UI나 DB backend와는 아직 연결되어 있지 않음

## 14.13 이 장의 핵심 정리

SIPLite의 XML 설정은 단순 부트스트랩 파일이 아니다.

- 허용 단말 모델
- 기본 라우팅 모델
- 초기 credential 모델
- transport 초기값

을 제공하는 시스템 초기 상태 정의 파일이다.

다음 장에서는 런타임 중 운영자가 서버 상태를 어떻게 관찰하고 제어하는지 본다.
