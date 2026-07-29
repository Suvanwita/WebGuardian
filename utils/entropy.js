export function calculateEntropy(password) {
  if (!password || password.length === 0) {
    return "Weak";
  }

  const length = password.length;
  let poolSize = 0;

  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;

  if (poolSize === 0) {
    return "Weak";
  }

  const entropy = length * Math.log2(poolSize);

  if (entropy < 40) {
    return "Weak";
  } else if (entropy < 80) {
    return "Medium";
  } else {
    return "Strong";
  }
}
