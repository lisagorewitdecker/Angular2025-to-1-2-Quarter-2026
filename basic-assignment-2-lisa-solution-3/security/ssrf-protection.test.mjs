import test from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyIpAddress,
  isPrivateOrInternalIp,
  isPubliclyRoutableIp,
  normalizeDestinationHost,
  resolveAndValidateDestination,
  validateRedirectChain,
} from './ssrf-protection.mjs';

test('classifyIpAddress rejects private, loopback, link-local, multicast, unspecified, reserved, and unique-local addresses', () => {
  assert.equal(classifyIpAddress('10.0.0.5').private, true);
  assert.equal(classifyIpAddress('127.0.0.1').loopback, true);
  assert.equal(classifyIpAddress('169.254.10.20').linkLocal, true);
  assert.equal(classifyIpAddress('224.0.0.1').multicast, true);
  assert.equal(classifyIpAddress('0.0.0.0').unspecified, true);
  assert.equal(classifyIpAddress('100.64.0.1').reserved, true);
  assert.equal(classifyIpAddress('::1').loopback, true);
  assert.equal(classifyIpAddress('fe80::1').linkLocal, true);
  assert.equal(classifyIpAddress('fc00::1').uniqueLocal, true);
  assert.equal(classifyIpAddress('ff02::1').multicast, true);
  assert.equal(classifyIpAddress('::').unspecified, true);
  assert.equal(classifyIpAddress('2001:db8::1').reserved, true);
  assert.equal(classifyIpAddress('::ffff:127.0.0.1').loopback, true);
});

test('classifyIpAddress allows public IPv4 and IPv6 addresses', () => {
  assert.equal(classifyIpAddress('8.8.8.8').isRoutable, true);
  assert.equal(classifyIpAddress('2606:4700:4700::1111').isRoutable, true);
  assert.equal(isPubliclyRoutableIp('8.8.4.4'), true);
  assert.equal(isPrivateOrInternalIp('192.168.1.20'), true);
});

test('normalizeDestinationHost normalizes URLs, hostnames, and IPv6 literals', () => {
  assert.equal(normalizeDestinationHost('HTTPS://Example.COM./path?q=1'), 'example.com');
  assert.equal(normalizeDestinationHost('[2001:db8::1]'), '2001:db8::1');
  assert.equal(normalizeDestinationHost('2001:4860:4860::8888'), '2001:4860:4860::8888');
  assert.throws(() => normalizeDestinationHost('fe80::1%eth0'), /zone identifier/i);
});

test('resolveAndValidateDestination rejects direct internal IP destinations', async () => {
  await assert.rejects(
    () => resolveAndValidateDestination('http://127.0.0.1/admin'),
    /non-routable address 127\.0\.0\.1/i,
  );
});

test('resolveAndValidateDestination rejects hostnames that resolve to internal address space', async () => {
  const lookup = async () => [{ address: '10.10.10.10', family: 4 }];

  await assert.rejects(
    () => resolveAndValidateDestination('https://example.com/resource', { lookup }),
    /non-routable address 10\.10\.10\.10/i,
  );
});

test('resolveAndValidateDestination rejects mixed public/private DNS answers to guard against rebinding', async () => {
  const lookup = async () => [
    { address: '8.8.8.8', family: 4 },
    { address: '192.168.0.10', family: 4 },
  ];

  await assert.rejects(
    () => resolveAndValidateDestination('downloads.example.com', { lookup }),
    /192\.168\.0\.10/i,
  );
});

test('resolveAndValidateDestination returns normalized public destinations', async () => {
  const lookup = async () => [
    { address: '8.8.8.8', family: 4 },
    { address: '2606:4700:4700::1111', family: 6 },
  ];

  await assert.deepEqual(
    await resolveAndValidateDestination('HTTPS://Example.COM/download', { lookup }),
    {
      host: 'example.com',
      addresses: ['8.8.8.8', '2606:4700:4700::1111'],
    },
  );
});

test('validateRedirectChain re-validates every redirect target', async () => {
  const lookup = async (host) => {
    if (host === 'safe.example.com') {
      return [{ address: '8.8.8.8', family: 4 }];
    }

    return [{ address: '::1', family: 6 }];
  };

  await assert.rejects(
    () => validateRedirectChain([
      'https://safe.example.com/start',
      'https://redirected.example.com/private',
    ], { lookup }),
    /non-routable address ::1/i,
  );
});
