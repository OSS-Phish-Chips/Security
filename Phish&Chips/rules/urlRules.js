// URL 관련 룰
const { URL } = require('url');
const ruleWeights = require('../config/ruleWeights'); // 가중치 불러오기

function checkURLRules(rawUrl) {
    const url = new URL(rawUrl);

    console.log('[URL 기반 룰 검사]');
    let score = 0;
    const messages = [];

    // 1. HTTPS 사용 여부
    if (url.protocol !== 'https:') {
        messages.push(`⚠️ HTTPS 사용하지 않음 (${ruleWeights.urlHttpUsage}점)`);
        score -= ruleWeights.urlHttpUsage;
    }

    // 2. 민감 경로 키워드 사용 여부
    const sensitivePaths = ['admin', 'login', 'phpmyadmin', '.git', 'config'];
    sensitivePaths.forEach((keyword) => {
        if (url.pathname.toLowerCase().includes(keyword)) {
            messages.push(`⚠️ 민감 경로 포함됨: ${keyword} (${ruleWeights.urlSensitivePath}점)`);
            score -= ruleWeights.urlSensitivePath;
        }
    });

    // 3. 쿼리 파라미터에 위험한 패턴 사용 여부
    if (url.search.includes('=') && /('|--|<|>)/.test(url.search)) {
        messages.push(`⚠️ URL 파라미터에 잠재적 인젝션 패턴 감지됨 (${ruleWeights.urlInjectionPattern}점)`);
        score -= ruleWeights.urlInjectionPattern;
    }

    let grade = "";
    if (score >= 50) grade = "위험";
    else if (score >= 20) grade = "주의";
    else grade = "양호";

    // 최종 결과 출력
    console.log(messages.join('\n') || '✅ 이상 없음');
    console.log(`➡️ URL 위험 점수: ${score}점 (${grade})\n`);

    return {
        score,
        messages,
    };
}

module.exports = { checkURLRules };
