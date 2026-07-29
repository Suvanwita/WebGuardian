export function hasIpAddress(url) {
  try {
    const host = new URL(url).hostname;
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;
    return ipv4Regex.test(host) || ipv6Regex.test(host);
  } catch (e) {
    return false;
  }
}

export function isExcessivelyLong(url) {
  return url.length > 75;
}

export function hasExcessiveSubdomains(url) {
  try {
    const host = new URL(url).hostname;
    const parts = host.split('.');
    // parts.length > 4 means more than 3 subdomains (e.g. one.two.three.domain.com has 4 parts, which is exactly 3 subdomains, so >4 is excessive)
    return parts.length > 4;
  } catch (e) {
    return false;
  }
}
