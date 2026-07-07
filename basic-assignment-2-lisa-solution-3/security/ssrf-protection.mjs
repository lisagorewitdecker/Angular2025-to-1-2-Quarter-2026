import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { domainToASCII, URL } from 'node:url';

function parseIpv4(address) {
  const octets = address.split('.');

  if (octets.length !== 4) {
    throw new Error(`Invalid IPv4 address: ${address}`);
  }

  let value = 0;

  for (const octet of octets) {
    if (!/^\d+$/.test(octet)) {
      throw new Error(`Invalid IPv4 address: ${address}`);
    }

    const parsed = Number(octet);

    if (parsed < 0 || parsed > 255) {
      throw new Error(`Invalid IPv4 address: ${address}`);
    }

    value = (value * 256) + parsed;
  }

  return value >>> 0;
}

function ipv4RangeStart(baseAddress) {
  return parseIpv4(baseAddress);
}

function isIpv4InCidr(address, baseAddress, prefixLength) {
  const addressValue = BigInt(parseIpv4(address));
  const baseValue = BigInt(ipv4RangeStart(baseAddress));
  const shift = 32n - BigInt(prefixLength);

  if (shift === 0n) {
    return addressValue === baseValue;
  }

  return (addressValue >> shift) === (baseValue >> shift);
}

function normalizeIpv6Parts(parts) {
  if (parts.length === 0) {
    return [];
  }

  const normalized = [...parts];
  const lastPart = normalized.at(-1);

  if (lastPart && lastPart.includes('.')) {
    const ipv4Value = parseIpv4(lastPart);
    const highWord = ((ipv4Value >>> 16) & 0xffff).toString(16);
    const lowWord = (ipv4Value & 0xffff).toString(16);
    normalized.splice(-1, 1, highWord, lowWord);
  }

  return normalized;
}

function parseIpv6(address) {
  if (address.includes('%')) {
    throw new Error(`IPv6 zone identifiers are not allowed: ${address}`);
  }

  const normalizedAddress = address.toLowerCase();
  const doubleColonIndex = normalizedAddress.indexOf('::');

  if (doubleColonIndex !== normalizedAddress.lastIndexOf('::')) {
    throw new Error(`Invalid IPv6 address: ${address}`);
  }

  let headParts = [];
  let tailParts = [];

  if (doubleColonIndex >= 0) {
    headParts = normalizeIpv6Parts(normalizedAddress.slice(0, doubleColonIndex).split(':').filter(Boolean));
    tailParts = normalizeIpv6Parts(normalizedAddress.slice(doubleColonIndex + 2).split(':').filter(Boolean));
  } else {
    headParts = normalizeIpv6Parts(normalizedAddress.split(':'));
  }

  const missingParts = 8 - (headParts.length + tailParts.length);

  if ((doubleColonIndex >= 0 && missingParts < 0) || (doubleColonIndex < 0 && headParts.length !== 8)) {
    throw new Error(`Invalid IPv6 address: ${address}`);
  }

  const parts = doubleColonIndex >= 0
    ? [...headParts, ...Array(missingParts).fill('0'), ...tailParts]
    : headParts;

  let value = 0n;

  for (const part of parts) {
    if (!/^[0-9a-f]{1,4}$/i.test(part)) {
      throw new Error(`Invalid IPv6 address: ${address}`);
    }

    value = (value << 16n) + BigInt(parseInt(part, 16));
  }

  return value;
}

function isIpv6InCidr(address, baseAddress, prefixLength) {
  const shift = 128n - BigInt(prefixLength);
  const addressValue = parseIpv6(address);
  const baseValue = parseIpv6(baseAddress);

  if (shift === 0n) {
    return addressValue === baseValue;
  }

  return (addressValue >> shift) === (baseValue >> shift);
}

function createClassification(address, version, flags, detail = {}) {
  return {
    address,
    version,
    ...flags,
    ...detail,
    isRoutable: !Object.values(flags).some(Boolean),
  };
}

function classifyIpv4(address) {
  const flags = {
    private: isIpv4InCidr(address, '10.0.0.0', 8)
      || isIpv4InCidr(address, '172.16.0.0', 12)
      || isIpv4InCidr(address, '192.168.0.0', 16),
    loopback: isIpv4InCidr(address, '127.0.0.0', 8),
    linkLocal: isIpv4InCidr(address, '169.254.0.0', 16),
    uniqueLocal: false,
    multicast: isIpv4InCidr(address, '224.0.0.0', 4),
    unspecified: isIpv4InCidr(address, '0.0.0.0', 8),
    reserved: isIpv4InCidr(address, '100.64.0.0', 10)
      || isIpv4InCidr(address, '192.0.0.0', 24)
      || isIpv4InCidr(address, '192.0.2.0', 24)
      || isIpv4InCidr(address, '198.18.0.0', 15)
      || isIpv4InCidr(address, '198.51.100.0', 24)
      || isIpv4InCidr(address, '203.0.113.0', 24)
      || isIpv4InCidr(address, '240.0.0.0', 4)
      || address === '255.255.255.255',
  };

  return createClassification(address, 4, flags);
}

function classifyIpv6(address) {
  const normalizedAddress = address.toLowerCase();

  if (isIpv6InCidr(normalizedAddress, '::ffff:0:0', 96)) {
    const embeddedIpv4 = normalizedAddress.slice(normalizedAddress.lastIndexOf(':') + 1);
    const ipv4Classification = classifyIpv4(embeddedIpv4);

    return {
      ...ipv4Classification,
      address,
      version: 6,
      ipv4Mapped: true,
    };
  }

  const flags = {
    private: false,
    loopback: isIpv6InCidr(normalizedAddress, '::1', 128),
    linkLocal: isIpv6InCidr(normalizedAddress, 'fe80::', 10),
    uniqueLocal: isIpv6InCidr(normalizedAddress, 'fc00::', 7),
    multicast: isIpv6InCidr(normalizedAddress, 'ff00::', 8),
    unspecified: isIpv6InCidr(normalizedAddress, '::', 128),
    reserved: isIpv6InCidr(normalizedAddress, 'fec0::', 10)
      || isIpv6InCidr(normalizedAddress, '100::', 64)
      || isIpv6InCidr(normalizedAddress, '2001:db8::', 32)
      || isIpv6InCidr(normalizedAddress, '2001:10::', 28),
  };

  return createClassification(address, 6, flags);
}

export function classifyIpAddress(address) {
  const version = isIP(address);

  if (version === 4) {
    return classifyIpv4(address);
  }

  if (version === 6) {
    return classifyIpv6(address);
  }

  throw new Error(`Invalid IP address: ${address}`);
}

export function isPrivateOrInternalIp(address) {
  return !classifyIpAddress(address).isRoutable;
}

export function isPubliclyRoutableIp(address) {
  return classifyIpAddress(address).isRoutable;
}

export function normalizeDestinationHost(value) {
  if (typeof value !== 'string') {
    throw new TypeError('Destination host must be a string.');
  }

  const trimmedValue = value.trim();

  if (!trimmedValue) {
    throw new Error('Destination host must not be empty.');
  }

  let hostname = trimmedValue;

  if (trimmedValue.includes('://')) {
    hostname = new URL(trimmedValue).hostname;
  } else if (trimmedValue.startsWith('[') && trimmedValue.endsWith(']')) {
    hostname = trimmedValue.slice(1, -1);
  } else if (!isIP(trimmedValue) && /[:/?#]/.test(trimmedValue)) {
    hostname = new URL(`http://${trimmedValue}`).hostname;
  }

  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    hostname = hostname.slice(1, -1);
  }

  if (hostname.includes('%')) {
    throw new Error('Destination host must not contain an IPv6 zone identifier.');
  }

  if (isIP(hostname)) {
    return hostname.toLowerCase();
  }

  const hostnameSansTrailingDot = hostname.endsWith('.') ? hostname.slice(0, -1) : hostname;
  const normalizedHostname = domainToASCII(hostnameSansTrailingDot);

  if (!normalizedHostname) {
    throw new Error(`Invalid destination host: ${value}`);
  }

  return normalizedHostname.toLowerCase();
}

export async function resolveAndValidateDestination(destination, options = {}) {
  const normalizedHost = normalizeDestinationHost(destination);
  const directIpVersion = isIP(normalizedHost);

  const addresses = directIpVersion > 0
    ? [{ address: normalizedHost, family: directIpVersion }]
    : await (options.lookup ?? dnsLookup)(normalizedHost, { all: true, verbatim: true });

  if (!Array.isArray(addresses) || addresses.length === 0) {
    throw new Error(`Unable to resolve destination host: ${normalizedHost}`);
  }

  const evaluatedAddresses = addresses.map(({ address, family }) => {
    const classification = classifyIpAddress(address);

    return {
      address,
      family: family ?? classification.version,
      classification,
    };
  });

  const blockedAddress = evaluatedAddresses.find(({ classification }) => !classification.isRoutable);

  if (blockedAddress) {
    throw new Error(`Refusing to connect to non-routable address ${blockedAddress.address}.`);
  }

  return {
    host: normalizedHost,
    addresses: evaluatedAddresses.map(({ address }) => address),
  };
}

export async function validateRedirectChain(destinations, options = {}) {
  const validations = [];

  for (const destination of destinations) {
    validations.push(await resolveAndValidateDestination(destination, options));
  }

  return validations;
}
