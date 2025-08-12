const axios = require("axios");
const { URL } = require("url");
const ruleWeights = require("../config/ruleWeights");

async function checkVulnerabilityRules(targetUrl) {
  console.log('[웹 취약점 분석]');
  let score = 0;
  const results = {
    XSS: false,
    Clickjacking: false,
    FileUploadExposure: false,
    DirectoryListing: false
  };

  const details = [];

  try {
    // 메인 페이지 응답
    const res = await axios.get(targetUrl, {
      maxRedirects: 5,
      validateStatus: null
    });

    const headers = res.headers;
    const body = res.data;

    // XSS 탐지
    const xssIndicators = ["<script", "onerror=", "javascript:"];
    if (xssIndicators.some(tag => body.toLowerCase().includes(tag))) {
      results.XSS = true;
      score += ruleWeights.vulnXSS;
      details.push({ issue: "XSS 의심 콘텐츠 포함", severity: 2 });
    }

    // Clickjacking 탐지
    if (!headers["x-frame-options"]) {
      results.Clickjacking = true;
      score += ruleWeights.vulnClickjacking;
      details.push({ issue: "Clickjacking 보호 미설정 (X-Frame-Options 없음)", severity: 2 });
    }

    // 파일 업로드 노출 경로 탐지
    const uploadPaths = ["/upload", "/uploads", "/file", "/files", "/images"];
    for (let path of uploadPaths) {
      const uploadUrl = new URL(path, targetUrl).href;
      try {
        const uploadRes = await axios.get(uploadUrl, { validateStatus: null });
        if (
          uploadRes.status === 200 &&
          uploadRes.headers["content-type"]?.includes("text/html")
        ) {
          results.FileUploadExposure = true;
          score += ruleWeights.vulnFileUpload;
          details.push({ issue: `파일 업로드 경로 노출 (${path})`, severity: 2 });
          break;
        }
      } catch {}
    }

    // [4] 디렉토리 리스팅 노출 여부
    const dirPaths = ["/uploads/", "/files/", "/data/", "/images/"];
    for (let path of dirPaths) {
      const dirUrl = new URL(path, targetUrl).href;
      try {
        const dirRes = await axios.get(dirUrl, { validateStatus: null });
        if (
          dirRes.status === 200 &&
          /(Index of|Directory Listing|Parent Directory)/i.test(dirRes.data)
        ) {
          results.DirectoryListing = true;
          score += ruleWeights.vulnDirListing;
          details.push({ issue: `디렉토리 리스팅 노출 (${path})`, severity: 2 });
          break;
        }
      } catch {}
    }

    // 위험도 평가
    let grade = "양호";
    if (score >= 6) grade = "위험";
    else if (score >= 3) grade = "주의";

    //console.log(`\n🔍 [${targetUrl}] 취약점 진단 결과`);
    console.log(`✔️ XSS 의심: ${results.XSS}`);
    console.log(`✔️ Clickjacking 가능성: ${results.Clickjacking}`);
    console.log(`✔️ 파일 업로드 경로 노출: ${results.FileUploadExposure}`);
    console.log(`✔️ 디렉토리 리스팅 노출: ${results.DirectoryListing}`);
    console.log(`➡️ vuln 위험 점수: ${score}점 (${grade})\n`);

    return {
      score,
      grade,
      results,
      details
    };
  } catch (err) {
    console.error("❌ 요청 실패:", err.message);
    return {
      score: 10,
      grade: "위험",
      results,
      details: [{ issue: "분석 요청 실패", severity: 3 }]
    };
  }
}

module.exports = { checkVulnerabilityRules };
