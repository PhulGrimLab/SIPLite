# 책 메타데이터 초안

이 문서는 SIPLite 분석서의 출판 또는 배포를 위한 메타데이터 초안이다. 실제 인쇄본, PDF, 웹 문서 중 어떤 형식으로 나가더라도 기본 참조 정보로 사용할 수 있다.

## 기본 정보

- 작업명: `SIPLite 분석서`
- 원고 경로: `/home/windmorning/projects/SIPWorks/SIPLite/docs/book`
- 대상 프로젝트: `/home/windmorning/projects/SIPWorks/SIPLite`
- 원고 성격: 코드 분석서 / 기술 서적 초안 / 운영 참조 문서

## 제목 후보

1. `SIPLite 코드 분석`
2. `SIPLite 실전 분석서`
3. `SIPLite로 배우는 SIP 서버 구조`
4. `SIPLite: Registrar, Proxy, TLS 구현 읽기`

권장 기본 제목:

`SIPLite 코드 분석`

## 부제 후보

1. `C++로 읽는 SIP Registrar, Proxy, TLS 서버 구조`
2. `REGISTER, INVITE, TLS, 운영까지 따라가는 구현 해설`
3. `코드, 흐름, 운영, 리팩터링을 함께 보는 SIPLite 해설서`

권장 기본 부제:

`REGISTER, INVITE, TLS, 운영까지 따라가는 구현 해설`

## 대상 독자

- SIP 구조를 코드와 함께 이해하려는 개발자
- C++ 네트워크 서버 구현을 읽고 싶은 개발자
- SIPLite 유지보수, 리팩터링, 운영 문서화가 필요한 사용자

## 핵심 키워드

- SIP
- SIPLite
- Registrar
- Stateful Proxy
- REGISTER
- INVITE
- Digest Authentication
- TLS
- OpenSSL
- C++
- Transport
- Testing
- Operations

## 원고 구성

- 서문
- 프로젝트 구조 장
- SIP 흐름 장
- TLS/transport 장
- 운영/설정/테스트 장
- 보안/성능/리팩터링 장
- 부록
- 맺음말

## 강점 요약

- 코드 기준 설명이라 근거가 분명하다
- REGISTER, INVITE, TLS, 운영까지 범위가 넓다
- 테스트, 로그, 설정, 배포까지 같이 다룬다
- 출판용 목차와 그림/표 초안이 이미 있다

## 남은 편집 작업

- 그림 형식 통일
- 본문 중복 압축
- 출판본 기준 재번호화 여부 결정
- 표지/판권/저자 정보 확정

## 배포 형식 후보

1. Markdown 원고 유지
2. PDF 전환
3. 정적 사이트 문서
4. 인쇄용 편집본

권장 우선순위:

1. Markdown 정리 완료
2. PDF 변환본 생성
3. 필요 시 인쇄본 편집
