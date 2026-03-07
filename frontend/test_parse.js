const fs = require('fs');

const details = "--- [Team: General] [State: IN_TRIAGE] [Assessed By: bob] [Rescored: 5.0] [Rescored Vector: CVSS:3.1/AV:N...] ---\n\n--- [Team: Sec] [State: EXPLOITABLE] [Assessed By: alice] [Rescored: 9.8] [Rescored Vector: CVSS:3.1/AV:L...] ---\n";

const match_score = details.match(/\[Rescored:\s*[\d\.]+\]/g);
const match_vector = details.match(/\[Rescored Vector:\s*[^\]]+\]/g);

console.log("Scores:", match_score);
console.log("Vectors:", match_vector);
