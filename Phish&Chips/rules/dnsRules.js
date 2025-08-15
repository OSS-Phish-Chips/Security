const dns = require('node:dns').promises;
const { parse } = require('tldts');
const ruleWeights = require('../config/ruleWeights'); // 점수 가중치 가져오기

const RELIABLE_NS_PROVIDERS = ['cloudflare', 'aws', 'azure', 'google'];
const RELIABLE_IP_PROVIDERS = ['amazonaws', 'azure', 'google']; // PTR에서 판별

function extractDomain(input) {
    const { domain } = parse(input);
    return domain || null;
}

async function checkDnsRules(urlOrDomain) {
    console.log('[DNS/도메인 신뢰도 분석]');

    let totalScore = 0;         // 누적 감점 점수
    const issues = [];          // 발견된 이슈 목록
    const meta = {              // 결과 보조정보
        domain: null,
        records: {
            spf: null,
            dmarc: null,
            ns: [],
            cnameOfWww: [],
            a: [],
            aPtr: [],
            mx: []
        }
    };

    try {
        const domain = extractDomain(urlOrDomain);
        if (!domain) {
            console.warn('❗ 유효하지 않은 입력: 도메인 추출 실패');
            return {
                score: 50,
                grade: '위험',
                details: [{ issue: '유효하지 않은 URL 또는 도메인 파싱 실패', severity: 3 }]
            };
        }
        meta.domain = domain;

        // 1) SPF (TXT: v=spf1)
        try {
            const txt = await dns.resolveTxt(domain);
            const hasSpf = (txt || []).some(rec => rec.join('').toLowerCase().startsWith('v=spf1'));
            meta.records.spf = !!hasSpf;
            if (!hasSpf) {
                console.warn('⚠️ SPF 레코드 없음');
                totalScore += ruleWeights.dnsSpfMissing;
                issues.push({ issue: 'SPF 레코드가 존재하지 않습니다.', severity: 2 });
            }
        } catch (e) {
            if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
                console.warn('⚠️ SPF 레코드 없음(ENODATA/ENOTFOUND)');
                totalScore += ruleWeights.dnsSpfMissing;
                issues.push({ issue: 'SPF 레코드가 존재하지 않습니다.', severity: 2 });
            } else {
                console.warn(`⚠️ SPF 조회 오류: ${e.message}`);
                issues.push({ issue: `SPF 조회 오류: ${e.message}`, severity: 1 });
            }
        }

        // 2) DMARC (TXT: _dmarc.domain)
        try {
            const txt = await dns.resolveTxt(`_dmarc.${domain}`);
            const hasDmarc = (txt || []).some(rec => rec.join('').toUpperCase().startsWith('V=DMARC1'));
            meta.records.dmarc = !!hasDmarc;
            if (!hasDmarc) {
                console.warn('⚠️ DMARC 레코드 없음');
                totalScore += ruleWeights.dnsDmarcMissing;
                issues.push({ issue: 'DMARC 레코드가 존재하지 않습니다.', severity: 2 });
            }
        } catch (e) {
            if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
                console.warn('⚠️ DMARC 레코드 없음(ENODATA/ENOTFOUND)');
                totalScore += ruleWeights.dnsDmarcMissing;
                issues.push({ issue: 'DMARC 레코드가 존재하지 않습니다.', severity: 2 });
            } else {
                console.warn(`⚠️ DMARC 조회 오류: ${e.message}`);
                issues.push({ issue: `DMARC 조회 오류: ${e.message}`, severity: 1 });
            }
        }

        // 3) NS 신뢰도
        try {
            const ns = await dns.resolveNs(domain);
            meta.records.ns = ns;
            const isReliable = ns.some(host =>
                RELIABLE_NS_PROVIDERS.some(p => host.toLowerCase().includes(p))
            );
            if (!isReliable) {
                console.warn('⚠️ 신뢰도 낮은 네임서버 사용 가능성');
                totalScore += ruleWeights.dnsNsUnreliable;
                issues.push({ issue: `무료/신뢰도 낮은 네임서버 사용 가능성 (${ns.join(', ')})`, severity: 3 });
            }
        } catch (e) {
            console.warn(`⚠️ NS 조회 오류: ${e.message}`);
            issues.push({ issue: `NS 조회 오류: ${e.message}`, severity: 1 });
        }

        // 4) CNAME(www 서브도메인)
        try {
            const cname = await dns.resolveCname(`www.${domain}`);
            meta.records.cnameOfWww = cname;
            // 정상 연결이면 감점 없음(정보만 기록)
        } catch (e) {
            if (e.code === 'ENODATA') {
                // CNAME 미존재: A 직접 사용일 수 있음(정보성)
                issues.push({ issue: 'www 서브도메인에 CNAME 없음(직접 A 사용 가능)', severity: 0 });
            } else if (e.code === 'ENOTFOUND') {
                console.warn('⚠️ CNAME이 폐기/비정상 대상일 가능성(ENOTFOUND)');
                totalScore += ruleWeights.dnsCnameDeprecated;
                issues.push({ issue: 'CNAME 레코드가 폐기된 서비스로 연결된 것으로 보임', severity: 2 });
            } else {
                console.warn(`⚠️ CNAME 조회 오류: ${e.message}`);
                issues.push({ issue: `CNAME 조회 오류: ${e.message}`, severity: 1 });
            }
        }

        // 5) A 레코드 및 안정성(PTR로 대형 클라우드 판별, Fast Flux 의심)
        try {
            const a = await dns.resolve4(domain);
            meta.records.a = a;

            if (!a || a.length === 0) {
                issues.push({ issue: 'A 레코드를 찾을 수 없음', severity: 1 });
            } else {
                if (a.length >= 5) {
                    console.warn(`⚠️ A 레코드가 다수(${a.length}) → Fast Flux 의심`);
                    totalScore += ruleWeights.dnsAUnstable;
                    issues.push({ issue: `IP 주소 다수(${a.length})로 Fast Flux 의심`, severity: 2 });
                } else {
                    // PTR 조회로 대형 클라우드 여부 판단(안정성 참고)
                    const ptrLists = await Promise.all(
                        a.map(ip => dns.reverse(ip).catch(() => []))
                    );
                    const flatPtrs = ptrLists.flat();
                    meta.records.aPtr = flatPtrs;

                    const hasTrustedPtr = flatPtrs.some(ptr =>
                        RELIABLE_IP_PROVIDERS.some(p => (ptr || '').toLowerCase().includes(p))
                    );
                    if (!hasTrustedPtr) {
                        // 대형 클라우드가 아니라도 문제는 아닐 수 있으므로 정보만
                        issues.push({
                            issue: `PTR에서 대형 클라우드 식별 불가 (PTR: ${flatPtrs.join(', ') || 'N/A'})`,
                            severity: 0
                        });
                    }
                }
            }
        } catch (e) {
            if (e.code !== 'ENODATA' && e.code !== 'ENOTFOUND') {
                console.warn(`⚠️ A 레코드 조회 오류: ${e.message}`);
                issues.push({ issue: `A 레코드 조회 오류: ${e.message}`, severity: 1 });
            } else {
                issues.push({ issue: 'A 레코드가 없음(ENODATA/ENOTFOUND)', severity: 1 });
            }
        }

        // 6) MX
        try {
            const mx = await dns.resolveMx(domain);
            meta.records.mx = mx;
            if (!mx || mx.length === 0) {
                console.warn('⚠️ MX 레코드 없음');
                totalScore += ruleWeights.dnsMxMissing;
                issues.push({ issue: 'MX 레코드가 존재하지 않습니다.', severity: 1 });
            }
        } catch (e) {
            if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
                console.warn('⚠️ MX 레코드 없음(ENODATA/ENOTFOUND)');
                totalScore += ruleWeights.dnsMxMissing;
                issues.push({ issue: 'MX 레코드가 존재하지 않습니다.', severity: 1 });
            } else {
                console.warn(`⚠️ MX 조회 오류: ${e.message}`);
                issues.push({ issue: `MX 조회 오류: ${e.message}`, severity: 1 });
            }
        }

        // 등급 산정
        let grade = '';
        if (totalScore >= 50) grade = '위험';
        else if (totalScore >= 20) grade = '주의';
        else grade = '양호';

        console.log(`➡️ DNS/도메인 위험 점수: ${totalScore}점 (${grade})\n`);

        return {
            score: totalScore,
            grade,
            details: issues,
            meta
        };
    } catch (err) {
        console.error('❌ DNS 분석 실패:', err.message);
        return {
            score: 50,
            grade: '위험',
            details: [{ issue: 'DNS 분석 실패', severity: 3 }]
        };
    }
}

module.exports = { checkDnsRules };
