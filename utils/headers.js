export function analyzeHeaders(headersArray) {
  let hasCSP = false;
  let hasHSTS = false;
  let hasXFrame = false;
  let riskScore = 0;

  if (headersArray) {
    for (let i = 0; i < headersArray.length; i++) {
      const header = headersArray[i];
      if (header && header.name) {
        const name = header.name.toLowerCase();
        if (name === 'content-security-policy') {
          hasCSP = true;
        } else if (name === 'strict-transport-security') {
          hasHSTS = true;
        } else if (name === 'x-frame-options') {
          hasXFrame = true;
        }
      }
    }
  }

  if (!hasCSP) {
    riskScore += 15;
  }
  if (!hasHSTS) {
    riskScore += 10;
  }
  if (!hasXFrame) {
    riskScore += 10;
  }

  return {
    hasCSP,
    hasHSTS,
    hasXFrame,
    riskScore
  };
}
