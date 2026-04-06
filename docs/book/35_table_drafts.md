# 표 초안

이 문서는 본문에 표시한 표 삽입 위치에 대응하는 실제 초안 모음이다. 출판 편집 시 그대로 옮기거나 열을 조금 조정해 사용할 수 있도록 작성한다.

## Table 1. SIPLite 주요 기능 범위 요약

권장 배치:

- [01_project_overview.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/01_project_overview.md)

| 영역 | 현재 구현 | 핵심 위치 |
|---|---|---|
| Registration | 구현됨 | `handleRegister()`, `Registration` |
| Call Proxying | 구현됨 | `handleInvite()`, `handleResponse()` |
| Dialog / Call teardown | 구현됨 | `handleAck()`, `handleBye()`, `handleCancel()` |
| Subscription | 구현됨 | `handleSubscribe()`, `handleNotify()` |
| UDP transport | 구현됨 | `UdpServer` |
| TCP transport | 구현됨 | `TcpServer` |
| TLS transport | 구현됨 | `TlsServer` |
| XML bootstrap | 구현됨 | `XmlConfigLoader` |
| Digest auth | 구현됨 | REGISTER auth path |
| Hostname verification | 미구현 | TLS 보안 공백 |

## Table 2. 서버 시작/종료 단계 요약

권장 배치:

- [02_entrypoint_and_runtime.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/02_entrypoint_and_runtime.md)

| 단계 | 위치 | 설명 |
|---|---|---|
| 시그널 등록 | `main.cpp` | `SIGINT`, `SIGTERM` 처리 준비 |
| 로그 초기화 | `main.cpp` | 보존 기간 설정, 로그 파일 준비 |
| UDP 시작 | `main.cpp` | 기본 transport 및 SipCore 기준점 |
| TCP 시작 | `main.cpp` | 선택적 연결형 transport |
| TLS 시작 | `main.cpp` | 환경 변수 기반 조건부 시작 |
| sender wiring | `main.cpp` | transport별 송신 분기 |
| bootstrap 등록 | `main.cpp` | XML 단말 선등록 |
| 콘솔 시작 | `main.cpp` | 운영 인터페이스 활성화 |
| cleanup loop | `main.cpp` | 타이머/상태 정리 |
| shutdown | `main.cpp` | console -> tls -> tcp -> udp -> logger |

## Table 3. UDP/TCP/TLS transport 비교표

권장 배치:

- [03_transport_layers.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/03_transport_layers.md)

| Transport | 장점 | 한계 | 핵심 파일 | 비고 |
|---|---|---|---|---|
| UDP | 단순, 빠른 수신 | 손실/재전송 고려 필요 | `src/UdpServer.cpp` | 기준 transport |
| TCP | 순서 보장, 큰 메시지 유리 | framing/연결 관리 필요 | `src/TcpServer.cpp` | `epoll`, connection map |
| TLS | 보안 채널, 인증서 활용 | handshake/암복호화 비용 | `src/TlsServer.cpp` | OpenSSL 기반 |

## Table 4. REGISTER 테스트 시나리오 맵

권장 배치:

- [09_register_flow.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/09_register_flow.md)

| 시나리오 | 기대 결과 | 근거 테스트 |
|---|---|---|
| 정상 REGISTER | `200 OK` | `test_sipcore.cpp` |
| Digest challenge | `401 Unauthorized` 후 재시도 | `test_sipcore.cpp` |
| deregistration | `loggedIn=false` 또는 제거 | `test_sipcore_extended.cpp` |
| invalid Expires | `400 Bad Request` | `test_sipcore_extended.cpp` |
| missing To/Contact | `400 Bad Request` | `test_sipcore_extended.cpp` |
| unknown user | `404 Not Found` | `test_sipcore_extended.cpp` |

## Table 5. INVITE 단계별 상태 변화

권장 배치:

- [10_invite_call_flow.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/10_invite_call_flow.md)

| 단계 | ActiveCall | PendingInvite | Dialog |
|---|---|---|---|
| INVITE 수신 직후 | 생성 | 생성 | 없음 |
| provisional response | 유지 | 유지, Timer C 연장 | 없음 |
| 2xx response | 유지 | 유지 | 생성 가능 |
| ACK 수신 | `confirmed=true` | 제거 | `confirmed=true` |
| CANCEL / error / timeout | 정리 대상 | 제거 | 생성 안 됨 또는 제거 |

## Table 6. Makefile 주요 타겟과 용도

권장 배치:

- [21_build_run_and_deployment.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/21_build_run_and_deployment.md)

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

## Table 7. SIPLite 환경 변수 참조표

권장 배치:

- [24_appendix_configuration_reference.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/24_appendix_configuration_reference.md)

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

## Table 8. 기능별 테스트 커버리지 표

권장 배치:

- [25_appendix_test_scenarios.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/25_appendix_test_scenarios.md)

| 기능 영역 | 테스트 파일 | 커버 상태 | 메모 |
|---|---|---|---|
| Parser | `test_parser*.cpp` | 양호 | compact header, length 검증 |
| Utils | `test_utils*.cpp` | 양호 | 문자열/URI/helper |
| Register/Auth | `test_sipcore*.cpp` | 양호 | 성공/실패/해지 포함 |
| Invite/Call | `test_sipcore_extended.cpp` | 양호 | 상태 기반 시나리오 |
| Transaction/Dialog | `test_transaction.cpp` | 보통 | 추가 확장 가능 |
| XML config | `test_xmlconfig.cpp` | 양호 | 입력 안전성 |
| TLS 통합 | 부분 | 부족 | 실제 SSL 통합은 더 필요 |
| Stress/Load | 거의 없음 | 부족 | 별도 필요 |

## Table 9. 보안 강점/약점/개선 우선순위 표

권장 배치:

- [26_security_review.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/26_security_review.md)

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

## Table 10. 성능 측정 지표와 수집 방법

권장 배치:

- [27_performance_and_scalability.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/27_performance_and_scalability.md)

| 지표 | 의미 | 수집 방법 예시 |
|---|---|---|
| REGISTER TPS | 등록 처리량 | 부하 도구 + 로그 카운트 |
| INVITE TPS | 호출 설정 처리량 | 시나리오 테스트 |
| 응답 지연 p95/p99 | tail latency | 타임스탬프 기반 측정 |
| 워커 큐 길이 | 내부 적체 | 큐 상태 로깅/계측 |
| TLS 연결 수 | 연결 부담 | TlsServer 상태 조회 |
| 로그 flush 비용 | I/O 영향 | flush 정책 비교 실험 |
| cleanup CPU 비용 | 주기 정리 부담 | profiling |

## Table 11. 운영 전 점검 체크리스트 요약표

권장 배치:

- [28_operations_checklist.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/28_operations_checklist.md)

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
