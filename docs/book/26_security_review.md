# 26장. 보안 검토

이 장은 SIPLite를 "기능이 있는가"가 아니라 "어떤 보안 경계와 방어선을 갖고 있는가"의 관점에서 읽는다. 목표는 과장 없이 현재 수준을 설명하는 것이다. 즉 잘한 점과 남은 위험을 함께 적는다.

기준 파일은 다음과 같다.

- [src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp)
- [src/SipUtils.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipUtils.cpp)
- [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)
- [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)
- [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)
- [src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp)
- [include/concurrent_queue.h](/home/windmorning/projects/SIPWorks/SIPLite/include/concurrent_queue.h)

## 26.1 보안 검토의 기준

이 프로젝트는 전형적인 인터넷 노출형 SIP 서버의 일부 속성을 가진다. 따라서 다음 공격면을 기준으로 보는 것이 적절하다.

1. 네트워크 입력
2. 설정 파일 입력
3. 인증 정보 처리
4. TLS 구성
5. 로그 노출
6. 운영 인터페이스
7. 자원 고갈 공격

즉 메모리 안전성만 보는 것으로는 부족하고, 입력 검증과 운영 노출까지 같이 봐야 한다.

## 26.2 강점 1: 파서 차원의 기본 방어

[src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp)는 현재 코드 기준으로 몇 가지 중요한 방어선을 가진다.

- compact header 지원
- `Content-Length`와 실제 body 길이 비교
- malformed SIP 메시지 거부

특히 `Content-Length` 검증은 매우 중요하다. SIP는 UDP뿐 아니라 TCP/TLS 위에서도 동작하므로, 메시지 경계와 body 길이가 어긋나면 파싱 혼선이나 요청 스머글링류 문제의 발판이 될 수 있다. 이 프로젝트는 그 지점에서 최소한의 일관성 검사를 수행한다.

## 26.3 강점 2: 설정 입력에 대한 방어적 태도

[include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)는 예제 수준 파서치고는 보수적이다. 확인되는 방어 요소는 다음과 같다.

- 파일 경로 길이 제한
- 널 바이트 차단
- 위험한 경로 패턴 차단
- 심볼릭 링크 차단
- 파일 크기 제한
- 최대 단말 수 제한
- 위험한 XML 패턴 차단

즉 설정 로딩은 단순한 편의 기능이 아니라, 어느 정도 신뢰 경계를 의식한 설계다. 책에서는 이 부분을 분명히 적는 편이 좋다. 많은 독자가 "직접 XML 파싱 = 대충 만든 코드"로 오해할 수 있기 때문이다.

## 26.4 강점 3: 로그 민감정보 가리기 시도

[src/SipUtils.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipUtils.cpp)를 보면 `Authorization`, `Proxy-Authorization`, `WWW-Authenticate`, `Proxy-Authenticate` 같은 헤더를 민감 정보로 판단하는 로직이 들어 있다.

이것은 운영 관점에서 매우 중요하다. SIP Digest 인증은 헤더에 challenge/response 정보가 실리므로, 로그가 그대로 남으면 보안 문제가 된다.

다만 여기서는 표현을 조심해야 한다. "민감정보 완전 보호"라고 쓰기보다, "일부 인증 헤더를 로그에서 가리기 위한 방어 로직이 존재한다"고 쓰는 편이 정확하다.

## 26.5 강점 4: 큐 크기 제한

[include/concurrent_queue.h](/home/windmorning/projects/SIPWorks/SIPLite/include/concurrent_queue.h)는 `DEFAULT_MAX_SIZE = 10000`을 두고, 큐가 가득 차면 `push()`가 실패하도록 설계되어 있다.

이것은 단순 구현 디테일이 아니라, 자원 고갈 공격에 대한 중요한 완충 장치다. 무한 큐였다면 burst 트래픽이나 악의적 flood에서 메모리 사용량이 계속 커질 수 있다.

물론 10000이라는 숫자가 충분한지는 별도 운영 기준이 필요하다. 하지만 "상한이 존재한다"는 사실 자체가 안전성 면에서 의미가 있다.

## 26.6 강점 5: TLS 1.2 이상 강제

[src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)의 `initializeSsl()`는 서버/클라이언트 컨텍스트에 대해 최소 TLS 1.2를 설정한다.

이것은 현재 기준으로 합리적인 기본값이다. 오래된 프로토콜을 허용하지 않는다는 점에서 보안 기본선은 나쁘지 않다.

또한 다음 항목도 지원한다.

- 서버 인증서/개인키 로드
- outbound peer chain 검증 옵션
- inbound client cert 요구 옵션
- CA 파일 지정 또는 기본 CA 경로 사용

즉 TLS 기능은 "포트만 연다" 수준이 아니라, 인증서 정책을 조절할 수 있는 구조를 이미 갖고 있다.

## 26.7 약점 1: hostname verification 미구현

현재 가장 분명한 TLS 보안 공백은 [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)에 직접 드러난다. peer chain verification은 있지만 hostname verification은 아직 구현되지 않았다고 로그로 밝히고 있다.

이 점은 매우 중요하다. 인증서 체인이 유효하다고 해서, 접속한 상대가 "정말 기대한 호스트"라는 보장은 따로 확인해야 하기 때문이다.

따라서 책에서는 이렇게 적는 것이 정확하다.

"SIPLite는 TLS 체인 검증 옵션을 제공하지만, 원격 호스트명 검증은 아직 완성되지 않았다."

## 26.8 약점 2: self-signed 인증서 기본 경로

[scripts/ensure_tls_certs.sh](/home/windmorning/projects/SIPWorks/SIPLite/scripts/ensure_tls_certs.sh)는 개발 편의를 위해 self-signed 인증서를 자동 생성한다. 이것은 개발 단계에서는 장점이지만, 운영 단계에서는 분명한 위험 요인이다.

이 스크립트는 나쁘지 않다. 문제는 사용자가 개발 경로를 운영 경로로 착각할 수 있다는 데 있다.

따라서 운영 문서에는 반드시 다음 문장을 넣는 것이 좋다.

"자동 생성 인증서는 개발 및 테스트용 기본 경로이며, 운영 배포에서는 신뢰 가능한 인증서와 검증 정책을 별도로 구성해야 한다."

## 26.9 약점 3: 인증 정보 저장 모델

현재 정적 단말 설정은 [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)의 `password` 필드를 통해 비밀번호를 다룬다. 이 값은 Digest 인증 검증에 사용된다.

책에서는 이 부분을 과장 없이 써야 한다.

- 장점: 인증 자체는 구현되어 있다.
- 한계: 비밀번호 저장 정책은 외부 보안 저장소와 분리되어 있지 않다.

즉 현재 모델은 개발/학습/소규모 환경에는 충분할 수 있지만, production-grade credential management라고 말하기는 어렵다.

## 26.10 약점 4: 콘솔 인터페이스의 운영 경계

[src/ConsoleInterface.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/ConsoleInterface.cpp)는 로컬 콘솔 기반 운영 인터페이스를 제공한다. 입력 길이 제한과 허용 문자 검증은 들어 있지만, 이 인터페이스 자체는 프로세스 표준 입력에 직접 결합되어 있다.

이 구조는 로컬 운영에는 단순하고 유용하다. 그러나 운영 모델이 복잡해지면 다음 질문이 생긴다.

1. 표준 입력이 닫히는 환경에서 어떻게 동작하는가
2. 서비스 매니저와 함께 돌릴 때 상호작용은 어떤가
3. 종료를 위해 `STDIN_FILENO`를 닫는 방식이 항상 안전한가

즉 보안 취약점이라기보다, 운영 경계가 명확히 문서화되어야 하는 영역이다.

## 26.11 약점 5: SIP 레벨 보안 확장의 미완성 가능성

현재 코드 기준으로 확인되는 기능은 REGISTER Digest, TLS transport, 기본 헤더 검증, 일부 입력 sanitization이다. 반면 다음 영역은 신중하게 표현해야 한다.

- SIP rate limiting
- source reputation / ACL
- flood 방어 정책
- nonce lifecycle hardening
- replay 저항성 강화
- 정교한 abuse detection

즉 구현된 기능이 적다고 볼 필요는 없지만, "공개 인터넷용 보안 완성 서버"라고 말하는 것은 과장이다.

## 26.12 로그 보안 관점

[src/Logger.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/Logger.cpp)는 로테이션과 보존 정책을 갖고 있다. 이는 운영 품질 측면에서는 장점이다. 하지만 보안 관점에서는 다음 질문이 추가로 필요하다.

1. 로그 파일 권한은 어떤가
2. 민감한 SIP 메시지가 어느 수준까지 남는가
3. TLS 오류나 인증 실패 시 어떤 정보가 노출되는가
4. 로그 주기가 과도한 정보 누출로 이어지지 않는가

즉 현재는 "로그가 잘 남는다"가 장점이지만, 운영 문서에서는 "무엇을 남기면 안 되는가"도 함께 정의해야 한다.

## 26.13 권장 보안 개선 순서

표 9는 현재 보안 상태를 개선 우선순위 관점에서 압축한 것이다.

| 항목 | 현재 상태 | 평가 | 우선순위 |
|---|---|---|---|
| XML path/content validation | 구현됨 | 강점 | 유지 |
| Content-Length 검증 | 구현됨 | 강점 | 유지 |
| 민감 헤더 redaction | 일부 구현 | 보통 | 중간 |
| TLS 1.2 minimum | 구현됨 | 강점 | 유지 |
| Peer chain verification | 옵션 지원 | 보통 | 중간 |
| Hostname verification | 미구현 | 약점 | 높음 |
| Self-signed default path | 개발용 적합 | 운영 위험 | 높음 |
| Credential storage model | 단순 | 운영 확장 필요 | 높음 |

현재 코드 기준으로 가장 효과적인 개선 순서는 다음과 같다.

1. TLS hostname verification 구현
2. 운영용 인증서 관리 절차 문서화
3. Digest credential 저장 정책 분리
4. flood/abuse 방어 정책 추가
5. TLS 통합 테스트와 보안 회귀 테스트 강화

이 순서가 좋은 이유는, 실제 공격면이 큰 지점부터 먼저 다루기 때문이다.

## 26.14 문서에 어떻게 써야 하는가

책이나 분석서에서는 다음과 같은 표현이 적절하다.

- "입력 검증과 설정 로딩 방어는 비교적 신중하게 구현되어 있다."
- "TLS는 인증서와 검증 정책을 지원하지만 hostname verification은 아직 미구현이다."
- "Digest 인증은 동작하지만 자격 증명 저장 정책은 단순하다."
- "운영 보안은 아직 문서화와 하드닝 여지가 남아 있다."

이런 표현은 구현을 깎아내리지 않으면서도, 독자에게 현실적인 기대치를 준다.

## 26.15 이 장의 핵심 정리

현재 SIPLite는 기본적인 보안 의식을 가진 코드다. 입력 검증, 설정 방어, 로그 민감정보 처리, 큐 제한, TLS 1.2 이상 강제 같은 요소는 분명한 강점이다.

반면 hostname verification, credential 관리, flood 방어, 운영 경계 문서화는 아직 더 다듬어야 한다. 따라서 이 프로젝트는 "보안 기능이 없는 예제"는 아니지만, "보안 하드닝이 끝난 운영 제품"이라고 보기도 어렵다.
