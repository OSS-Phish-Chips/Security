const axios = require("axios");
const { URL } = require("url");
const ruleWeights = require("../config/ruleWeights");

async function getSSLAnalysis(hostname) {
  const apiBase = "https://api.ssllabs.com/api/v3/analyze";

  // 1️⃣ 분석 요청 시작
  await axios.get(`${apiBase}?host=${hostname}&publish=off&all=done&startNew=on`);

  // 2️⃣ 결과가 준비될 때까지 대기 (폴링)
  let analysis;
  for (let i = 0; i < 15; i++) { // 최대 15회 시도 (~75초)
    await new Promise((res) => setTimeout(res, 5000)); // 5초 간격
    const { data } = await axios.get(`${apiBase}?host=${hostname}`);
    if (data.status === "READY" || data.status === "ERROR") {
      analysis = data;
      break;
    }
    console.log(`⏳ SSL 분석 대기 중... (${i + 1}/15)`);
  }
  return analysis;
}

async function checkSSLRules(rawUrl) {
  console.log("[SSL 인증서 검사 - API]");
  let score = 0;
  const messages = [];

  try {
    const hostname = new URL(rawUrl).hostname;
    const analysis = await getSSLAnalysis(hostname);

    if (!analysis || analysis.status === "ERROR") {
      throw new Error("SSL 분석 실패");
    }

    // SSL Labs는 endpoints[0].details.cert에서 인증서 정보 제공
    const cert = analysis.endpoints[0].details.cert;
    const now = new Date();
    const validTo = new Date(cert.notAfter);
    const daysRemaining = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

    // 유효성 체크
    if (daysRemaining <= 0) {
      messages.push(`❌ 인증서가 만료됨 (만료일: ${validTo})`);
      score += ruleWeights.SSL_EXPIRED || 30;
    } else if (daysRemaining < 30) {
      messages.push(`⚠️ 인증서 만료 임박 (${daysRemaining}일 남음)`);
      score += ruleWeights.SSL_EXPIRING_SOON || 10;
    }

    // 신뢰할 수 있는 발급자인지 확인
    const issuer = cert.issuerLabel || "";
    const trustedIssuers = ["Let's Encrypt", "DigiCert", "Google Trust Services", "Amazon"];
    const isTrusted = trustedIssuers.some((i) =>
      issuer.toLowerCase().includes(i.toLowerCase())
    );

    if (!isTrusted) {
      messages.push(`⚠️ 비신뢰 발급자: ${issuer}`);
      score += ruleWeights.SSL_UNTRUSTED_ISSUER || 15;
    }

  } catch (error) {
    messages.push(`❌ SSL 인증서 API 검사 실패: ${error.message}`);
    score += ruleWeights.SSL_CHECK_FAIL || 50;
  }

  // 등급 판단
  let grade = "";
  if (score >= 50) grade = "위험";
  else if (score >= 20) grade = "주의";
  else grade = "양호";

  console.log(`➡️ SSL 위험 점수: ${score}점 (${grade})\n`);
  messages.forEach((msg) => console.log(msg));

  return { score, grade, messages };
}

module.exports = { checkSSLRules };
