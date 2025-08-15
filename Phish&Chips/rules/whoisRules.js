const whois = require('whois-json');
const dayjs = require('dayjs');
const { parse } = require('tldts');
const ruleWeights = require('../config/ruleWeights'); // 점수 가중치 가져오기

function extractDomain(url) {
    const result = parse(url);
    return result.domain || null;
}

function validDate(info, candidates) {
    for (const key of candidates) {
        if (key in info) {
            const value = info[key];
            const parsed = dayjs(value);
            if (parsed.isValid()) return parsed;
        }
    }
    return null;
}

async function checkWhoisRules(url) {
    console.log('[도메인/WHOIS 분석]');

    let totalScore = 0; // 누적 감점 점수
    const issues = [];  // 발견된 이슈 목록

    try {
        const domain = extractDomain(url);
        if (!domain) {
            console.warn('❗ 유효하지 않은 URL 또는 도메인 파싱 실패');
            return {
                score: 50,
                grade: '위험',
                details: [{ issue: '유효하지 않은 URL 또는 도메인 파싱 실패', severity: 3 }]
            };
        }

        const info = await whois(domain);
        const creationDateKeys = [
            'createdDate', 'creationDate', 'registeredDate',
            'Creation Date', 'Created On'
        ];
        const expirationDateKeys = [
            'expiresDate', 'expirationDate', 'registryExpiryDate',
            'registrarRegistrationExpirationDate',
            'Registry Expiry Date',
            'Registrar Registration Expiration Date'
        ];

        const createdDate = validDate(info, creationDateKeys);
        const expiresDate = validDate(info, expirationDateKeys);

        // 1) 생성일: 1년 미만 신생 도메인
        if (createdDate) {
            const ageYears = dayjs().diff(createdDate, 'year');
            if (ageYears < 1) {
                console.warn('⚠️ 도메인이 생성된 지 1년 미만');
                totalScore += ruleWeights.whoisRecentDomain;
                issues.push({ issue: '도메인이 1년 미만으로 최근에 생성됨', severity: 2 });
            }
        } else {
            console.warn('⚠️ 도메인 생성일 확인 불가');
            totalScore += ruleWeights.whoisMissingCreatedDate;
            issues.push({ issue: '도메인 생성일을 확인할 수 없음', severity: 1 });
        }

        // 2) 등록 기간: 만료까지 12개월 미만
        if (expiresDate) {
            const monthsLeft = expiresDate.diff(dayjs(), 'month');
            if (monthsLeft < 12) {
                console.warn('⚠️ 도메인 등록 기간이 1년 이하로 짧음');
                totalScore += ruleWeights.whoisShortRegistration;
                issues.push({ issue: '도메인 등록 기간이 1년 이하', severity: 2 });
            }
        } else {
            console.warn('⚠️ 도메인 만료일 확인 불가');
            totalScore += ruleWeights.whoisMissingExpiresDate;
            issues.push({ issue: '도메인 만료일을 확인할 수 없음', severity: 1 });
        }

        // 3) 등록자 공개 여부: privacy/redacted
        const registrantBlob = JSON.stringify(info).toLowerCase();
        if (registrantBlob.includes('privacy') || registrantBlob.includes('redacted')) {
            console.warn('⚠️ 등록자 정보가 비공개(Privacy/Redacted) 처리됨');
            totalScore += ruleWeights.whoisRegistrantPrivacy;
            issues.push({ issue: '등록자 정보가 비공개 처리됨', severity: 2 });
        }

        // 4) 위험 국가 등록
        // 참고: 국가 코드는 레지스트리/레지스트라 응답 포맷에 따라 없을 수 있음.
        const riskCountries = ['NG', 'RU', 'CN'];
        const countryCode = (info.country || info.Country || '').toString().trim().toUpperCase();
        if (countryCode && riskCountries.includes(countryCode)) {
            console.warn(`⚠️ 등록자 국가가 위험 국가로 분류됨: ${countryCode}`);
            totalScore += ruleWeights.whoisRiskyCountry;
            issues.push({ issue: `등록자 국가가 위험 국가(${countryCode})로 분류됨`, severity: 3 });
        }

        // 등급 산정
        let grade = '';
        if (totalScore >= 50) grade = '위험';
        else if (totalScore >= 20) grade = '주의';
        else grade = '양호';

        console.log(`➡️ WHOIS 기반 위험 점수: ${totalScore}점 (${grade})\n`);

        return {
            score: totalScore,
            grade,
            details: issues,
            meta: {
                domain,
                createdDate: createdDate ? createdDate.format('YYYY-MM-DD') : '확인 불가',
                expiresDate: expiresDate ? expiresDate.format('YYYY-MM-DD') : '확인 불가'
            }
        };
    } catch (err) {
        console.error('❌ WHOIS 분석 실패:', err.message);
        return {
            score: 50,
            grade: '위험',
            details: [{ issue: 'WHOIS 분석 실패', severity: 3 }]
        };
    }
}

module.exports = { checkWhoisRules };
