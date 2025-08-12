// server.js
const express = require('express');
const { checkURLRules } = require('./rules/urlRules');
const { checkHeaderRules } = require('./rules/headerRules');
const { checkSSLRules } = require('./rules/sslRules');
const { checkVulnerabilityRules } = require('./rules/vulnRules');
const { getGradeFromScore } = require('./utils/gradeUtil');

const app = express();
const PORT = 3000;

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

  const totalScore = Object.values(results.details).reduce(
    (sum, section) => sum + section.score,
    0
  );
  results.totalScore = totalScore;
  results.overallGrade = getGradeFromScore(totalScore);

  return results;
}

// API 엔드포인트
app.get('/analyze', async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: 'url 파라미터를 넣어주세요' });
  }

  try {
    const result = await analyzeURL(url);
    res.json(result);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '분석 중 오류 발생' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ 서버 실행 중: http://localhost:${PORT}`);
});
