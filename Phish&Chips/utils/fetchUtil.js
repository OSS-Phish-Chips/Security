// 요청&파싱 유틸
// 공통 HTTP 요청, SSL 인증서 정보 가져오기 등의 유틸리티 함수 정의

const axios = require('axios');
const sslChecker = require('ssl-checker');  // 새로 추가
const { URL } = require('url');

/**
 * 주어진 URL에 HTTP GET 요청을 보내고 응답 객체를 반환
 * @param {string} url - 요청할 전체 URL
 * @returns {Promise<Object>} - axios response 객체
 */
async function fetchHeaders(url) {
  try {
    const response = await axios.get(url, {
      timeout: 5000,
      validateStatus: () => true, // HTTP 오류 코드도 허용해서 검사 가능하게
    });
    return response;
  } catch (error) {
    console.error(`❌ [HTTP 요청 오류] ${error.message}`);
    return null;
  }
}

/**
 * 도메인에서 SSL 인증서 정보를 가져옴
 * @param {string} rawUrl - URL 전체 문자열 (http:// 또는 https:// 포함)
 * @returns {Promise<Object|null>} - 인증서 객체 or null
 */
async function getSSLCertificate(rawUrl) {
  try {
    const hostname = new URL(rawUrl).hostname;
    const cert = await sslCertificate.get(hostname);
    return cert;
  } catch (error) {
    console.error(`❌ [SSL 인증서 오류] ${error.message}`);
    return null;
  }
}

module.exports = {
  fetchHeaders,
  getSSLCertificate,
};
