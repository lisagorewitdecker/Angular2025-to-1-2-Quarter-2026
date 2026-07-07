/**
 * Enforces that the vulnerable `ip` package (CVE-2023-42282) is not installed.
 *
 * The `ip` package has no patched release; all versions up to 2.0.1 incorrectly
 * classify certain private/internal IPv4 addresses as publicly routable, enabling
 * SSRF attacks. This project replaced it with a built-in SSRF protection module
 * (security/ssrf-protection.mjs). Running this script during CI or as part of
 * `npm run test:security` prevents accidental reintroduction via transitive deps.
 */

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

try {
  require.resolve('ip');
  console.error(
    'FAIL: vulnerable ip package (CVE-2023-42282) is present in node_modules. ' +
    'Remove any dependency that pulls in ip and use security/ssrf-protection.mjs instead.',
  );
  process.exit(1);
} catch {
  console.log('OK: ip package (CVE-2023-42282) is not installed.');
}
