/**
 * IP addresses: which ones this server may connect to, and the key a client address is rate-limited under.
 */
import net from 'node:net';

/** The eight 16-bit groups of an IPv6 address in any spelling (embedded IPv4 included), or null. */
export function v6Groups(ip: string): number[] | null {
  let a = ip.toLowerCase().replace(/%.*$/, '');
  const dotted = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (dotted) {
    if (!net.isIPv4(dotted[2])) return null;
    const o = dotted[2].split('.').map(Number);
    a = `${dotted[1]}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  const halves = a.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0) return null;
  const groups = [...head, ...Array(fill).fill('0'), ...tail];
  if (groups.length !== 8 || !groups.every(g => /^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map(g => parseInt(g, 16));
}

/** Whether an IPv4 address is outside the public internet: private, loopback, link-local, shared, reserved. */
function blockedV4(ip: string): boolean {
  const [a, b, c] = ip.split('.').map(Number);
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

const v4Of = (hi: number, lo: number) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;

/**
 * Whether this server must not connect to an address. IPv6 forms that reach IPv4 are judged by the IPv4
 * they reach (mapped, compatible, SIIT), and those that reach arbitrary IPv4 are refused outright (NAT64,
 * 6to4, Teredo), as are unique-local, link-local, site-local, multicast and documentation ranges.
 */
export function isBlockedAddress(ip: string): boolean {
  if (net.isIPv4(ip)) return blockedV4(ip);
  const g = net.isIPv6(ip) ? v6Groups(ip) : null;
  if (!g) return true;
  const zeros = (n: number) => g.slice(0, n).every(x => x === 0);
  if (zeros(5) && g[5] === 0xffff) return blockedV4(v4Of(g[6], g[7])); // ::ffff:a.b.c.d
  if (zeros(6)) return g[6] === 0 ? true : blockedV4(v4Of(g[6], g[7])); // ::, ::1, ::a.b.c.d
  if (zeros(4) && g[4] === 0xffff && g[5] === 0) return blockedV4(v4Of(g[6], g[7])); // SIIT
  if (g[0] === 0x64 && g[1] === 0xff9b) return true; // NAT64, well-known and local-use
  if (g[0] === 0x2002) return true; // 6to4
  if (g[0] === 0x2001 && (g[1] === 0 || g[1] === 0xdb8)) return true; // Teredo, documentation
  if ((g[0] & 0xfe00) === 0xfc00) return true; // unique local
  if ((g[0] & 0xffc0) === 0xfe80 || (g[0] & 0xffc0) === 0xfec0) return true; // link and site local
  if ((g[0] & 0xff00) === 0xff00) return true; // multicast
  return false;
}

/** A network an operator trusts: an address range in CIDR notation, parsed. */
export interface Network {
  /** The network as written in canonical form: `100.64.0.0/10`, `fd7a:115c:a1e0:0:0:0:0:0/48`. */
  cidr: string;
  /** The address as 16-bit groups: two for IPv4, eight for IPv6. */
  groups: number[];
  prefix: number;
}

/** The narrowest prefix a trusted network may have: /8 and longer, for IPv4 and IPv6 alike. */
export const NARROWEST_TRUSTED_PREFIX = 8;

const v4Groups = (ip: string) => {
  const o = ip.split('.').map(Number);
  return [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
};

/**
 * A network from CIDR notation (`address/prefix`), or a reason it is refused: not CIDR, broader than /8,
 * with bits set after the prefix (`100.64.0.1/10` is a host, not a network), or IPv4 written as mapped
 * IPv6, which `inNetworks` judges as IPv4 and so would never match.
 */
export function parseNetwork(text: string): Network | string {
  const m = /^([^/]+)\/(\d{1,3})$/.exec(text.trim());
  if (!m) return `${text} is not address/prefix.`;
  const ip = m[1];
  const groups = net.isIPv4(ip) ? v4Groups(ip) : net.isIPv6(ip) ? v6Groups(ip) : null;
  if (!groups) return `${text} is not address/prefix.`;
  const prefix = Number(m[2]);
  if (prefix > groups.length * 16) return `${text}: the prefix is longer than the address.`;
  if (prefix < NARROWEST_TRUSTED_PREFIX) return `${text} is broader than /${NARROWEST_TRUSTED_PREFIX}.`;
  if (!groups.every((g, i) => (g & mask(prefix, i)) === g)) return `${text} has bits set after its prefix.`;
  if (groups.length === 8 && groups.slice(0, 5).every(x => x === 0) && groups[5] === 0xffff) {
    return `${text} is IPv4 written as IPv6; write it as IPv4.`;
  }
  const address =
    groups.length === 2
      ? `${groups[0] >> 8}.${groups[0] & 255}.${groups[1] >> 8}.${groups[1] & 255}`
      : groups.map(g => g.toString(16)).join(':');
  return { cidr: `${address}/${prefix}`, groups, prefix };
}

/** The bits of 16-bit group `i` inside a prefix. */
const mask = (prefix: number, i: number) => {
  const bits = Math.max(0, Math.min(16, prefix - i * 16));
  return (0xffff << (16 - bits)) & 0xffff;
};

/** Whether an address is inside one of the networks. An IPv4-mapped IPv6 address is judged as its IPv4. */
export function inNetworks(ip: string, networks: readonly Network[]): boolean {
  if (!networks.length) return false;
  let groups = net.isIPv4(ip) ? v4Groups(ip) : net.isIPv6(ip) ? v6Groups(ip) : null;
  if (groups?.length === 8 && groups.slice(0, 5).every(x => x === 0) && groups[5] === 0xffff) groups = groups.slice(6);
  return (
    !!groups &&
    networks.some(
      n => n.groups.length === groups.length && n.groups.every((g, i) => (groups[i] & mask(n.prefix, i)) === g),
    )
  );
}

/** Whether an address is this machine: allowed only in development. */
export const isLoopback = (ip: string) =>
  (net.isIPv4(ip) && ip.startsWith('127.')) || (net.isIPv6(ip) && v6Groups(ip)?.join() === '0,0,0,0,0,0,0,1');

/**
 * The key a client is rate-limited under: an IPv4 address as is, an IPv6 address by its /64, since one
 * subscriber holds a whole /64. An IPv4-mapped IPv6 address counts as its IPv4.
 */
export function clientKey(ip: string): string {
  const g = v6Groups(ip);
  if (!net.isIPv6(ip.replace(/%.*$/, '')) || !g) return ip;
  if (g.slice(0, 5).every(x => x === 0) && g[5] === 0xffff) return v4Of(g[6], g[7]);
  return `${g
    .slice(0, 4)
    .map(x => x.toString(16))
    .join(':')}::/64`;
}

/**
 * The network a client is in, wider than `clientKey`: an IPv4 address by its /24, an IPv6 address by its /48.
 * What one party needs many of to look like many, so a bound kept per network holds for carriers it makes up.
 */
export function networkKey(ip: string): string {
  const client = clientKey(ip);
  if (net.isIPv4(client)) return `${client.split('.').slice(0, 3).join('.')}.0/24`;
  const g = v6Groups(ip);
  return g
    ? `${g
        .slice(0, 3)
        .map(x => x.toString(16))
        .join(':')}::/48`
    : client;
}
