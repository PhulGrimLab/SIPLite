# SIPLite 분석서

이 디렉터리는 `/home/windmorning/projects/SIPWorks/SIPLite` 프로젝트를 책 형태로 정리하기 위한 초안이다.

목표는 두 가지다.

1. 현재 코드를 이해할 수 있게 한다.
2. 나중에 책이나 기술 문서로 확장할 수 있는 집필 뼈대를 남긴다.

이 문서는 "기능 목록"보다 "코드가 실제로 어떻게 동작하는가"에 초점을 둔다.

## 권장 읽기 순서

1. `00_preface.md`
2. `01_project_overview.md`
3. `02_entrypoint_and_runtime.md`
4. `03_transport_layers.md`
5. `04_sipcore_flow.md`
6. `05_tls_implementation.md`
7. `06_state_and_data_model.md`
8. `07_tests_and_verification.md`
9. `08_risks_and_next_work.md`
10. `09_register_flow.md`
11. `10_invite_call_flow.md`
12. `11_bye_cancel_ack.md`
13. `12_subscribe_notify.md`
14. `13_digest_auth.md`
15. `14_xml_configuration.md`
16. `15_console_and_operations.md`
17. `16_packet_examples.md`
18. `17_sequence_diagrams.md`
19. `18_code_reading_guide.md`
20. `19_logs_and_debugging.md`
21. `20_appendix_key_functions.md`
22. `21_build_run_and_deployment.md`
23. `22_glossary_and_rfc_map.md`
24. `23_architecture_refactoring_roadmap.md`
25. `24_appendix_configuration_reference.md`
26. `25_appendix_test_scenarios.md`
27. `26_security_review.md`
28. `27_performance_and_scalability.md`
29. `28_operations_checklist.md`
30. `29_book_outline_for_publication.md`
31. `30_figures_tables_and_appendices_plan.md`
32. `31_final_summary.md`
33. `32_afterword.md`
34. `33_publication_toc_draft.md`
35. `34_figure_drafts.md`
36. `35_table_drafts.md`

## 집필 원칙

- 설명은 반드시 현재 코드 기준으로 작성한다.
- 문장만 쓰지 말고, 항상 관련 파일과 함수명을 함께 적는다.
- "왜 이런 구조인지"와 "어디가 아직 약한지"를 분리해서 쓴다.
- 구현 완료와 설계 의도를 혼동하지 않는다.

## 현재 대상 코드

- 엔트리포인트: [src/main.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/main.cpp)
- SIP 핵심 처리: [src/SipCore.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipCore.cpp)
- 파서: [src/SipParser.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/SipParser.cpp)
- 전송 계층: [src/UdpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/UdpServer.cpp), [src/TcpServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TcpServer.cpp), [src/TlsServer.cpp](/home/windmorning/projects/SIPWorks/SIPLite/src/TlsServer.cpp)
- 설정 로더: [include/XmlConfigLoader.h](/home/windmorning/projects/SIPWorks/SIPLite/include/XmlConfigLoader.h)
- 테스트: [tests](/home/windmorning/projects/SIPWorks/SIPLite/tests)

## 현재 상태

- 구조 장, 흐름 장, 운영 장, 부록 장, 편집 장까지 작성된 상태다.
- 핵심 장 일부에는 실제 그림과 표가 본문에 이미 반영되어 있다.
- 출판용 재배치 초안은 [33_publication_toc_draft.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/33_publication_toc_draft.md)에 정리되어 있다.
- 원고 진행 상황과 남은 작업은 [MANUSCRIPT_STATUS.md](/home/windmorning/projects/SIPWorks/SIPLite/docs/book/MANUSCRIPT_STATUS.md)에서 관리한다.
