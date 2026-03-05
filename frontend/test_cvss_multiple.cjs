const cvss = require('ae-cvss-calculator');

function calculateScoreFromVector(vector) {
    if (!vector || vector.trim().length <= 5) return null;
    try {
        let v = vector.trim();
        let score = null;
        if (v.startsWith('CVSS:4.0')) {
            const c = new cvss.Cvss4P0(v);
            score = c.calculateScores().overall ?? null;
        } else if (v.startsWith('CVSS:3.')) {
            if (v.startsWith('CVSS:3.0')) v = v.replace('CVSS:3.0', 'CVSS:3.1');
            const c = new cvss.Cvss3P1(v);
            const s = c.calculateScores(false);
            score = s.overall ?? s.base ?? null;
        } else {
            const c = new cvss.Cvss2(v);
            const s = c.calculateScores();
            score = s.overall ?? s.base ?? null;
        }
        if (score !== null && !isNaN(score)) return parseFloat(score.toFixed(1));
    } catch (e) {
        console.error("Parse error:", e.message);
    }
    return null;
}

console.log("Test 1:", calculateScoreFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"));
console.log("Test 2:", calculateScoreFromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));

