// 최종 위험도 판단
function getGradeFromScore(score) {
    if (score <= 20) return '양호';
    if (score <= 50) return '주의';
    return '위험';
  }
  
  module.exports = { getGradeFromScore };
  