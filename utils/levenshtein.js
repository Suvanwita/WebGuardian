export function calculateDistance(str1, str2) {
  if (str1 === str2) return 0;
  if (str1.length === 0) return str2.length;
  if (str2.length === 0) return str1.length;

  let s1 = str1;
  let s2 = str2;

  // Ensure s1 is the shorter string to optimize space
  if (s1.length > s2.length) {
    s1 = str2;
    s2 = str1;
  }

  const len1 = s1.length;
  const len2 = s2.length;
  let prevRow = Array.from({ length: len1 + 1 }, (_, i) => i);
  let currRow = new Array(len1 + 1);

  for (let j = 1; j <= len2; j++) {
    currRow[0] = j;
    const char2 = s2[j - 1];
    for (let i = 1; i <= len1; i++) {
      const char1 = s1[i - 1];
      const cost = char1 === char2 ? 0 : 1;
      currRow[i] = Math.min(
        prevRow[i] + 1,        // Deletion
        currRow[i - 1] + 1,    // Insertion
        prevRow[i - 1] + cost  // Substitution
      );
    }
    // Swap rows
    const temp = prevRow;
    prevRow = currRow;
    currRow = temp;
  }

  return prevRow[len1];
}

export function checkHomographAttack(domain, trustedDomainsArray) {
  if (!domain || !trustedDomainsArray || !Array.isArray(trustedDomainsArray)) {
    return false;
  }
  const cleanDomain = domain.toLowerCase().trim();
  for (const trustedDomain of trustedDomainsArray) {
    const cleanTrusted = trustedDomain.toLowerCase().trim();
    if (calculateDistance(cleanDomain, cleanTrusted) === 1) {
      return true;
    }
  }
  return false;
}
