const axios = require("axios");
const tls = require("tls");
const { URL } = require("url");
const ruleWeights = require("../config/ruleWeights");

async function getSSLAnalysis(hostname) {
  const apiBase = "https://api.ssllabs.com/api/v3/analyze";

  // 1️⃣ 분석 요청 시작
  await axios.get(`${apiBase}?host=${hostname}&publish=off&all=done&startNew=on`);

  // 2️⃣ 결과 대기
  let analysis;
  for (let i = 0; i < 15; i++) { // 대기
    await new Promise((res) => setTimeout(res, 5000));
    const { data } = await axios.get(`${apiBase}?host=${hostname}`);
    if (data.status === "READY" || data.status === "ERROR") {
      analysis = data;
      break;
    }
    console.log(`⏳ SSL 분석 대기 중... (${i + 1}/15)`);
  }
  return analysis;
}

// SSL Labs API 실패 시 로컬 TLS 검사
async function localSSLCheck(hostname) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(443, hostname, { servername: hostname }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();

      if (!cert || !cert.valid_to) {
        return reject(new Error("로컬 인증서 정보 없음"));
      }

      const now = new Date();
      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

      resolve({
        validTo,
        daysRemaining,
        issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown Issuer"
      });
    });

    socket.on("error", (err) => {
      reject(new Error(`로컬 SSL 검사 실패: ${err.message}`));
    });
  });
}

async function checkSSLRules(rawUrl) {
  console.log("[SSL 인증서 검사]");

  let score = 0;
  const messages = [];

  try {
    const hostname = new URL(rawUrl).hostname;
    let analysis;

    try {
      // 1차: SSL Labs API 시도
      analysis = await getSSLAnalysis(hostname);

      if (!analysis || analysis.status === "ERROR") {
        throw new Error(`SSL Labs 분석 실패 (${analysis?.statusMessage || "이유 없음"})`);
      }

      // SSL Labs에서 인증서 정보 추출
      const cert = analysis.endpoints[0].details.cert;
      const now = new Date();
      const validTo = new Date(cert.notAfter);
      const daysRemaining = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

      // 만료 체크
      if (daysRemaining <= 0) {
        messages.push(`❌ 인증서가 만료됨 (만료일: ${validTo})`);
        score += ruleWeights.SSL_EXPIRED || 30;
      } else if (daysRemaining < 30) {
        messages.push(`⚠️ 인증서 만료 임박 (${daysRemaining}일 남음)`);
        score += ruleWeights.SSL_EXPIRING_SOON || 10;
      }

      // 발급자 체크
      const issuer = cert.issuerLabel || "";
      const trustedIssuers = ["Let's Encrypt", "DigiCert", "Google Trust Services", "Amazon"];
      const isTrusted = trustedIssuers.some((i) =>
        issuer.toLowerCase().includes(i.toLowerCase())
      );
      if (!isTrusted) {
        messages.push(`⚠️ 비신뢰 발급자: ${issuer}`);
        score += ruleWeights.SSL_UNTRUSTED_ISSUER || 15;
      }

    } catch (apiErr) {
      // 2차: 로컬 TLS 검사 시도
      console.warn(`⚠️ SSL Labs API 실패 → 로컬 검사 시도: ${apiErr.message}`);
      const certInfo = await localSSLCheck(hostname);

      if (certInfo.daysRemaining <= 0) {
        messages.push(`❌ 인증서 만료됨 (만료일: ${certInfo.validTo})`);
        score += ruleWeights.SSL_EXPIRED || 30;
      } else if (certInfo.daysRemaining < 30) {
        messages.push(`⚠️ 인증서 만료 임박 (${certInfo.daysRemaining}일 남음)`);
        score += ruleWeights.SSL_EXPIRING_SOON || 10;
      }

      const trustedIssuers = ["Let's Encrypt", "DigiCert", "Google Trust Services", "Amazon"];
      const isTrusted = trustedIssuers.some((i) =>
        certInfo.issuer.toLowerCase().includes(i.toLowerCase())
      );
      if (!isTrusted) {
        messages.push(`⚠️ 비신뢰 발급자: ${certInfo.issuer}`);
        score += ruleWeights.SSL_UNTRUSTED_ISSUER || 15;
      }
    }

  } catch (error) {
    messages.push(`❌ SSL 인증서 검사 완전 실패: ${error.message}`);
    score += ruleWeights.SSL_CHECK_FAIL || 50;
  }

  // 등급
  let grade = "";
  if (score >= 50) grade = "위험";
  else if (score >= 20) grade = "주의";
  else grade = "양호";

  console.log(`➡️ SSL 위험 점수: ${score}점 (${grade})\n`);
  messages.forEach((msg) => console.log(msg));

  return { score, grade, messages };
}

module.exports = { checkSSLRules };
