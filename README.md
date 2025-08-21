# 보안 룰 설명
본 시스템은 웹사이트의 다양한 보안 요소를 정량적으로 평가하기 위해 룰 기반 분석 기법을 도입한다. 
이를 위해 rules/ 디렉터리 내에 각 보안 영역별 검사 모듈을 구성하였다. 
각 모듈의 주요 기능은 다음과 같다.


## 구조
~~~text
security/               # Express 기반 보안 분석 API 서버
│
├─ config/              # 설정 관련
│   └─ ruleWeights.js   # 보안 룰별 가중치 정의
│
├─ rules/               # 보안 검사 규칙 모듈
│   ├─ dnsRules.js      # DNS 관련 검사
│   ├─ headerRules.js   # HTTP 보안 헤더 검사
│   ├─ sslRules.js      # SSL/TLS 인증서 검사
│   ├─ urlRules.js      # URL 패턴/구조 검사
│   ├─ vulnRules.js     # 알려진 취약점/보안 패치 검사
│   └─ whoisRules.js    # WHOIS/RDAP 기반 도메인 정보 검사
│
├─ utils/               # 공용 유틸리티
│   ├─ fetchUtil.js     # API 요청/네트워크 처리 함수
│   └─ gradeUtil.js     # 룰 검사 결과 점수화/등급화
│
├─ server.js            # Express 서버 진입점 (라우팅, 룰 실행, 결과 종합)
├─ package.json         # 프로젝트 메타 및 의존성 관리
└─ package-lock.json    # 의존성 버전 고정
~~~

## 1. URL 검사 모듈 (checkURLRules.js)

### 목적:
웹사이트 URL의 구조와 구성에서 잠재적 위험 요소를 탐지하여 보안 점수 평가.

### 주요 점검 항목:
1) HTTPS 사용 여부 – 비암호화 HTTP 사용 시 위험
2) 민감 경로 포함 여부 – /admin, /login, phpmyadmin, .git, config 등
3) 쿼리 파라미터 위험 패턴 – =, ', --, <, > 포함 여부 (인젝션 가능성)


## 2. HTTP 헤더 검사 모듈 (checkHeaderRules.js)

### 목적:
HTTP 응답 헤더 설정을 점검하여 클릭재킹, XSS, 콘텐츠 스니핑 등 보안 취약점 평가.

### 주요 점검 항목:
1) CSP(Content-Security-Policy) – XSS, 인라인 스크립트 방지
2) X-Frame-Options – 클릭재킹 방지
3) Strict-Transport-Security(HSTS) – HTTPS 강제
4) X-Content-Type-Options – 콘텐츠 타입 스니핑 방지
5) CORS – Access-Control-Allow-Origin이 *일 경우 위험


## 3. SSL 인증서 검사 모듈 (checkSSLRules.js)

### 목적:
HTTPS 및 SSL/TLS 인증서의 신뢰성과 유효성을 확인.

### 주요 점검 항목:
1) 만료 여부 – 만료된 인증서 또는 만료 임박 인증서
2) 발급자 신뢰성 – Let's Encrypt, DigiCert, Google Trust Services, Amazon 등 신뢰 여부
3) API 실패 시 로컬 TLS 검사 – 로컬 소켓을 이용한 인증서 검증


## 4. DNS 검사 모듈 (checkDnsRules.js)

### 목적:
DNS 레코드와 네임서버 신뢰도를 분석하여 도메인 안정성과 이메일 보안 평가.

### 주요 점검 항목:
1) SPF 레코드 – 이메일 스푸핑 방지
2) DMARC 레코드 – 이메일 피싱 방어
3) 네임서버 신뢰도 – Cloudflare, AWS, Google 등 신뢰 여부
4) CNAME(www 서브도메인) – 정상 연결 여부
5) A 레코드 및 PTR – Fast Flux, 클라우드 안정성 확인
6) MX 레코드 – 이메일 서버 존재 여부


## 5. 취약점 검사 모듈 (checkVulnerabilityRules.js)

### 목적:
웹페이지의 일반 취약점(클라이언트/서버) 탐지.

### 주요 점검 항목:
1) XSS 의심 콘텐츠 – <script>, onerror=, javascript: 등 포함 여부
2) Clickjacking 보호 – X-Frame-Options 미설정
3) 파일 업로드 경로 노출 – /upload, /files 등
4) 디렉토리 리스팅 노출 – Index of, Directory Listing, Parent Directory 확인


## 6. WHOIS 정보 검사 모듈 (checkWhoisRules.js)

### 목적:
도메인 등록 정보와 기간을 분석하여 신뢰성과 의심 사이트 가능성을 평가.

### 주요 점검 항목:
1) 도메인 생성일 – 1년 미만 신생 도메인 위험
2) 등록 기간 – 만료까지 12개월 이하 단기 등록 위험
3) 등록자 정보 공개 여부 – Privacy/Redacted 처리
4) 등록자 국가 – 위험 국가(NG, RU, CN 등) 등록 여부

