// HTTP 헤더 관련 룰
const { fetchHeaders } = require('../utils/fetchUtil');
const ruleWeights = require('../config/ruleWeights'); // 점수 가중치 가져오기

async function checkHeaderRules(url) {
    console.log('[HTTP 헤더 분석]');

    let totalScore = 0; // 누적 감점 점수
    const issues = []; // 발견된 이슈 목록

    try {
        const res = await fetchHeaders(url);
        if (!res) return { score: 0, details: [] };

        const headers = res.headers;

        // 1. CSP (Content-Security-Policy): XSS, 인라인 스크립트 방지
        if (!headers['content-security-policy']) {
            console.warn('⚠️ CSP 헤더 없음');
            totalScore += ruleWeights.csp;
            issues.push({ issue: 'CSP 헤더 없음', severity: 3 });
        }

        // 2. X-Frame-Options: 클릭재킹 방지
        if (!headers['x-frame-options']) {
            console.warn('⚠️ X-Frame-Options 헤더 없음');
            totalScore += ruleWeights.xFrameOptions;
            issues.push({ issue: 'X-Frame-Options 헤더 없음', severity: 2 });
        }

        // 3. Strict-Transport-Security: HTTPS 접속 강제
        if (!headers['strict-transport-security']) {
            console.warn('⚠️ HSTS 헤더 없음');
            totalScore += ruleWeights.hsts;
            issues.push({ issue: 'HSTS 미설정', severity: 2 });
        }

        // 4. X-Content-Type-Options: 콘텐츠 타입 스니핑 방지
        if (!headers['x-content-type-options'] || headers['x-content-type-options'].toLowerCase() !== 'nosniff') {
            console.warn('⚠️ X-Content-Type-Options 미흡');
            totalScore += ruleWeights.contentTypeOptions;
            issues.push({ issue: 'X-Content-Type-Options 설정 미흡', severity: 1 });
        }

        // 5. CORS 설정 검사: access-control-allow-origin 이 * 인 경우는 보안에 취약함
        if (headers['access-control-allow-origin'] === '*') {
            console.warn('⚠️ CORS 정책이 모든 출처 허용 중임');
            totalScore += ruleWeights.corsWildcard;
            issues.push({ issue: 'CORS 모든 출처 허용', severity: 1 });
        }

        // 결과 해석 및 리턴
        let grade = '';
        if (totalScore >= 50) grade = '위험';
        else if (totalScore >= 20) grade = '주의';
        else grade = '양호';

        console.log(`➡️ HTTP 헤더 위험 점수: ${totalScore}점 (${grade})\n`);

        return {
            score: totalScore,
            grade,
            details: issues
        };
    } catch (err) {
        console.error('❌ 헤더 분석 실패:', err.message);
        return {
            score: 50,
            grade: '위험',
            details: [{ issue: 'HTTP 헤더 분석 실패', severity: 3 }]
        };
    }
}

module.exports = { checkHeaderRules };
