1. URL 검사 모듈 (checkURLRules.js)

목적:
웹사이트 URL의 구조와 구성에서 잠재적 위험 요소를 탐지하여 보안 점수 평가.

주요 점검 항목:

HTTPS 사용 여부 – 비암호화 HTTP 사용 시 위험

민감 경로 포함 여부 – /admin, /login, phpmyadmin, .git, config 등

쿼리 파라미터 위험 패턴 – =, ', --, <, > 포함 여부 (인젝션 가능성)

점수 산정:

위험 요소 발견 시 ruleWeights 기준 점수를 누적 합산

최종 점수 기준:

0 ~ 19점: 양호

20 ~ 49점: 주의

50점 이상: 위험

2. HTTP 헤더 검사 모듈 (checkHeaderRules.js)

목적:
HTTP 응답 헤더 설정을 점검하여 클릭재킹, XSS, 콘텐츠 스니핑 등 보안 취약점 평가.

주요 점검 항목:

CSP(Content-Security-Policy) – XSS, 인라인 스크립트 방지

X-Frame-Options – 클릭재킹 방지

Strict-Transport-Security(HSTS) – HTTPS 강제

X-Content-Type-Options – 콘텐츠 타입 스니핑 방지

CORS – Access-Control-Allow-Origin이 *일 경우 위험

점수 산정:

설정되지 않았거나 부적합한 경우 ruleWeights 기준 점수를 누적 합산

최종 점수 기준:

0 ~ 19점: 양호

20 ~ 49점: 주의

50점 이상: 위험

3. SSL 인증서 검사 모듈 (checkSSLRules.js)

목적:
HTTPS 및 SSL/TLS 인증서의 신뢰성과 유효성을 확인.

주요 점검 항목:

만료 여부 – 만료된 인증서 또는 만료 임박 인증서

발급자 신뢰성 – Let's Encrypt, DigiCert, Google Trust Services, Amazon 등 신뢰 여부

API 실패 시 로컬 TLS 검사 – 로컬 소켓을 이용한 인증서 검증

점수 산정:

발견된 문제마다 ruleWeights 기준 점수 누적

최종 점수 기준:

0 ~ 19점: 양호

20 ~ 49점: 주의

50점 이상: 위험

4. DNS 검사 모듈 (checkDnsRules.js)

목적:
DNS 레코드와 네임서버 신뢰도를 분석하여 도메인 안정성과 이메일 보안 평가.

주요 점검 항목:

SPF 레코드 – 이메일 스푸핑 방지

DMARC 레코드 – 이메일 피싱 방어

네임서버 신뢰도 – Cloudflare, AWS, Google 등 신뢰 여부

CNAME(www 서브도메인) – 정상 연결 여부

A 레코드 및 PTR – Fast Flux, 클라우드 안정성 확인

MX 레코드 – 이메일 서버 존재 여부

점수 산정:

문제 발견 시 ruleWeights 기준 점수 누적

최종 점수 기준:

0 ~ 19점: 양호

20 ~ 49점: 주의

50점 이상: 위험

5. 취약점 검사 모듈 (checkVulnerabilityRules.js)

목적:
웹페이지의 일반 취약점(클라이언트/서버) 탐지.

주요 점검 항목:

XSS 의심 콘텐츠 – <script>, onerror=, javascript: 등 포함 여부

Clickjacking 보호 – X-Frame-Options 미설정

파일 업로드 경로 노출 – /upload, /files 등

디렉토리 리스팅 노출 – Index of, Directory Listing, Parent Directory 확인

점수 산정:

문제 발생 시 ruleWeights 기준 점수 누적

최종 점수 기준:

0 ~ 2점: 양호

3 ~ 5점: 주의

6점 이상: 위험

6. WHOIS 정보 검사 모듈 (checkWhoisRules.js)

목적:
도메인 등록 정보와 기간을 분석하여 신뢰성과 의심 사이트 가능성을 평가.

주요 점검 항목:

도메인 생성일 – 1년 미만 신생 도메인 위험

등록 기간 – 만료까지 12개월 이하 단기 등록 위험

등록자 정보 공개 여부 – Privacy/Redacted 처리

등록자 국가 – 위험 국가(NG, RU, CN 등) 등록 여부

점수 산정:

위험 요소 발견 시 ruleWeights 기준 점수 누적

최종 점수 기준:

0 ~ 19점: 양호

20 ~ 49점: 주의

50점 이상: 위험
