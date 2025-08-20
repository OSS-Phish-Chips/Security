// server.js
const express = require('express');
const { checkURLRules } = require('./rules/urlRules');
const { checkHeaderRules } = require('./rules/headerRules');
const { checkSSLRules } = require('./rules/sslRules');
const { checkVulnerabilityRules } = require('./rules/vulnRules');
const { checkWhoisRules } = require('./rules/whoisRules');
const { checkDnsRules } = require('./rules/dnsRules');
const { getGradeFromScore } = require('./utils/gradeUtil');

const app = express();
const PORT = 3000;

const inflight = new Map(); 
async function analyzeURLDeDup(url) {
  if (inflight.has(url)) return inflight.get(url);
  const p = (async () => {
    try { return await analyzeURL(url); }
    finally { inflight.delete(url); }
  })();
  inflight.set(url, p);
  return p;
}

async function analyzeURL(targetUrl) {
  console.log(`\n[사이트 분석 시작] ${targetUrl}\n`);

  const results = { details: {} };

  const urlResult = await checkURLRules(targetUrl);
  results.details.url = {
    score: urlResult.score,
    grade: getGradeFromScore(urlResult.score),
    messages: urlResult.messages
  };

  const headerResult = await checkHeaderRules(targetUrl);
  results.details.header = {
    score: headerResult.score,
    grade: getGradeFromScore(headerResult.score),
    messages: headerResult.messages
  };

  const sslResult = await checkSSLRules(targetUrl);
  results.details.ssl = {
    score: sslResult.score,
    grade: getGradeFromScore(sslResult.score),
    messages: sslResult.messages
  };

  const vulnResult = await checkVulnerabilityRules(targetUrl);
  results.details.vulnerability = {
    score: vulnResult.score,
    grade: getGradeFromScore(vulnResult.score),
    messages: vulnResult.messages
  };

  const whoisResult = await checkWhoisRules(targetUrl);
  results.details.whois = {
    score: whoisResult.score,
    grade: getGradeFromScore(whoisResult.score),
    messages: whoisResult.details
  }

  const dnsResult = await checkDnsRules(targetUrl);
  results.details.dns = {
    score: dnsResult.score,
    grade: getGradeFromScore(dnsResult.score),
    messages: dnsResult.details
  }

  // -----------------------------
  // 위험 합계 → 안전 점수 변환
  // -----------------------------
  const sections = Object.values(results.details);
  const sectionCount = sections.length;
  const MAX_PER_SECTION = 100;
  const MAX_TOTAL = MAX_PER_SECTION * sectionCount;

  const totalRisk = sections.reduce((sum, s) => sum + (Number(s.score) || 0), 0);
  const totalSafe = Math.max(0, MAX_TOTAL - totalRisk);

  const avgSafePerSection = totalSafe / sectionCount;
  const safeScore100 = Math.round((totalSafe / MAX_TOTAL) * 100);

  results.totalScore = Math.round(avgSafePerSection);
  results.overallGrade = getGradeFromScore(totalRisk);

  results.meta = {
    sectionCount,
    maxPerSection: MAX_PER_SECTION,
    maxTotal: MAX_TOTAL,
    totalRisk,                  // 0 ~ 600 (높을수록 위험)
    totalSafe,                  // 0 ~ 600 (높을수록 안전)
    avgSafePerSection: Math.round(avgSafePerSection), // 0~100
    safeScore100                // 0~100 (백분율)
  };

  console.log(`[위험 합계] ${totalRisk}/${MAX_TOTAL}`);
  console.log(`[안전 점수] ${totalSafe}/${MAX_TOTAL}  → 평균(0~100): ${results.totalScore}, 백분율: ${safeScore100}`);
  console.log(`[등급(위험기준)] ${results.overallGrade}\n`);

  return results;
}

// API 엔드포인트
app.get('/analyze', async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: 'url 파라미터를 넣어주세요' });
  }

  try {
    const result = await analyzeURLDeDup(url);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '분석 중 오류 발생' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ 서버 실행 중: http://localhost:${PORT}`);
});
