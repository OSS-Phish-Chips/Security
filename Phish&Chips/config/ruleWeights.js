// 가중치 일관화 위한 파일

module.exports = {
    // header
    csp: 30,
    xFrameOptions: 20,
    hsts: 20,
    contentTypeOptions: 15,
    corsWildcard: 15,
  
    // ssl
    sslExpired: 30,
    sslExpirySoon: 10,
    sslUntrustedCA: 10,
    sslAnalysisFail: 50,
  
    // url
    urlHttpUsage: 30,         // https 사용 여부
    urlSensitivePath: 28,
    urlInjectionPattern: 42,
  
    // vuln
    vulnXSS: 25,
    vulnClickjacking: 25,
    vulnFileUpload: 25,
    vulnDirListing: 25
  };
  