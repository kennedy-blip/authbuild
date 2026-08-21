import { DecodedJwt, JwtHeader, JwtPayload, SamplePresetId, SignatureStatus } from '../types/auth';

export const DEFAULT_HMAC_SECRET = 'authpulse-dev-secret-2025';

export function stripBearerPrefix(input: string): string {
  const trimmed = input.trim();
  if (/^bearer\s+/i.test(trimmed)) {
    return trimmed.replace(/^bearer\s+/i, '').trim();
  }
  return trimmed;
}

export function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlEncodeString(str: string): string {
  const encoder = new TextEncoder();
  return base64UrlEncodeBytes(encoder.encode(str));
}

export function base64UrlDecodeToBytes(b64url: string): Uint8Array {
  let base64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(padLength);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function base64UrlDecodeToString(b64url: string): string {
  const bytes = base64UrlDecodeToBytes(b64url);
  const decoder = new TextDecoder('utf-8', { fatal: false });
  return decoder.decode(bytes);
}

export function decodeJwt(tokenInput: string): DecodedJwt {
  const raw = stripBearerPrefix(tokenInput);
  if (!raw) {
    return {
      raw: '',
      headerRaw: '',
      payloadRaw: '',
      signatureRaw: '',
      header: null,
      payload: null,
      isValidFormat: false,
    };
  }

  const parts = raw.split('.');
  if (parts.length !== 3) {
    return {
      raw,
      headerRaw: parts[0] || '',
      payloadRaw: parts[1] || '',
      signatureRaw: parts[2] || '',
      header: null,
      payload: null,
      isValidFormat: false,
      parseError: `Expected 3 dot-separated Base64URL segments (header.payload.signature), found ${parts.length}.`,
    };
  }

  const [headerRaw, payloadRaw, signatureRaw] = parts;

  let header: JwtHeader | null = null;
  let payload: JwtPayload | null = null;

  try {
    const headerJson = base64UrlDecodeToString(headerRaw);
    const parsedHeader = JSON.parse(headerJson);
    if (typeof parsedHeader !== 'object' || parsedHeader === null || Array.isArray(parsedHeader)) {
      throw new Error('JWT header must decode to a JSON object.');
    }
    header = parsedHeader as JwtHeader;
  } catch (err) {
    return {
      raw,
      headerRaw,
      payloadRaw,
      signatureRaw,
      header: null,
      payload: null,
      isValidFormat: false,
      parseError: `Invalid Header Base64URL/JSON: ${err instanceof Error ? err.message : 'Malformed header'}`,
    };
  }

  try {
    const payloadJson = base64UrlDecodeToString(payloadRaw);
    const parsedPayload = JSON.parse(payloadJson);
    if (typeof parsedPayload !== 'object' || parsedPayload === null || Array.isArray(parsedPayload)) {
      throw new Error('JWT payload must decode to a JSON object.');
    }
    payload = parsedPayload as JwtPayload;
  } catch (err) {
    return {
      raw,
      headerRaw,
      payloadRaw,
      signatureRaw,
      header,
      payload: null,
      isValidFormat: false,
      parseError: `Invalid Payload Base64URL/JSON: ${err instanceof Error ? err.message : 'Malformed payload'}`,
    };
  }

  return {
    raw,
    headerRaw,
    payloadRaw,
    signatureRaw,
    header,
    payload,
    isValidFormat: true,
  };
}

function getHmacHashAlgorithm(alg: string): 'SHA-256' | 'SHA-384' | 'SHA-512' | null {
  switch (alg.toUpperCase()) {
    case 'HS256':
      return 'SHA-256';
    case 'HS384':
      return 'SHA-384';
    case 'HS512':
      return 'SHA-512';
    default:
      return null;
  }
}

function getSecretBytes(secret: string, isBase64Secret = false): Uint8Array {
  if (isBase64Secret) {
    try {
      return base64UrlDecodeToBytes(secret.trim());
    } catch {
      return new TextEncoder().encode(secret);
    }
  }
  return new TextEncoder().encode(secret);
}

export async function signJwtHmac(
  header: JwtHeader,
  payload: JwtPayload,
  secret: string,
  isBase64Secret = false
): Promise<string> {
  const headerEncoded = base64UrlEncodeString(JSON.stringify(header));
  const payloadEncoded = base64UrlEncodeString(JSON.stringify(payload));
  const signingInput = `${headerEncoded}.${payloadEncoded}`;

  const hashAlg = getHmacHashAlgorithm(header.alg || 'HS256');
  if (!hashAlg) {
    // Deterministic simulated asymmetric signature for RS256/ES256 preview
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(`${signingInput}.${secret || 'asymmetric-key'}`)
    );
    const sig = base64UrlEncodeBytes(new Uint8Array(digest));
    return `${signingInput}.${sig}`;
  }

  const keyBytes = getSecretBytes(secret, isBase64Secret);
  const keyBuffer = new Uint8Array(keyBytes).buffer;
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: { name: hashAlg } },
    false,
    ['sign']
  );

  const dataBytes = new TextEncoder().encode(signingInput);
  const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, dataBytes);
  const signatureEncoded = base64UrlEncodeBytes(new Uint8Array(signatureBuffer));

  return `${signingInput}.${signatureEncoded}`;
}

export async function verifyJwtHmac(
  tokenInput: string,
  secret: string,
  isBase64Secret = false
): Promise<SignatureStatus> {
  const decoded = decodeJwt(tokenInput);
  if (!decoded.raw) return 'empty';
  if (!decoded.isValidFormat || !decoded.header) return 'invalid';

  const hashAlg = getHmacHashAlgorithm(decoded.header.alg || '');
  if (!hashAlg) {
    return 'unsupported';
  }

  if (!secret || !decoded.signatureRaw) {
    return 'invalid';
  }

  try {
    const keyBytes = getSecretBytes(secret, isBase64Secret);
    const keyBuffer = new Uint8Array(keyBytes).buffer;
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'HMAC', hash: { name: hashAlg } },
      false,
      ['verify']
    );

    const signingInput = `${decoded.headerRaw}.${decoded.payloadRaw}`;
    const signatureBytes = base64UrlDecodeToBytes(decoded.signatureRaw);
    const sigBuffer = new Uint8Array(signatureBytes).buffer;
    const dataBuffer = new TextEncoder().encode(signingInput).buffer;

    const isValid = await crypto.subtle.verify('HMAC', cryptoKey, sigBuffer, dataBuffer);
    return isValid ? 'valid' : 'invalid';
  } catch {
    return 'invalid';
  }
}

export function generateCodeVerifier(): string {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  return base64UrlEncodeBytes(randomBytes);
}

export async function generateCodeChallengeS256(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncodeBytes(new Uint8Array(digest));
}

export async function createSampleToken(
  preset: SamplePresetId,
  secret: string = DEFAULT_HMAC_SECRET
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  if (preset === 'admin_valid') {
    // Expires in 3 hours 42 minutes (13,320 seconds)
    return signJwtHmac(
      { alg: 'HS256', typ: 'JWT', kid: 'ap-key-2025-01' },
      {
        sub: 'usr_849201_elena',
        name: 'Elena Vance',
        email: 'elena.vance@authpulse.dev',
        iss: 'https://auth.authpulse.dev/',
        aud: ['https://api.authpulse.dev/v1', 'https://console.authpulse.dev'],
        iat: now - 1080,
        exp: now + 3 * 3600 + 42 * 60,
        jti: 'tok_99a41f0c82e1',
        roles: ['admin', 'moderator'],
        scopes: ['users:read', 'users:write', 'users:delete', 'audit:read', 'tokens:revoke'],
        tenant_id: 'org_acme_prod',
      },
      secret
    );
  }

  if (preset === 'moderator_expiring') {
    // Expires in 8 minutes 15 seconds (warning state)
    return signJwtHmac(
      { alg: 'HS256', typ: 'JWT', kid: 'ap-key-2025-01' },
      {
        sub: 'usr_302914_marcus',
        name: 'Marcus Chen',
        email: 'm.chen@authpulse.dev',
        iss: 'https://auth.authpulse.dev/',
        aud: 'https://api.authpulse.dev/v1',
        iat: now - 3105,
        exp: now + 8 * 60 + 15,
        jti: 'tok_44c81b9201fa',
        roles: ['moderator'],
        scopes: ['users:read', 'users:suspend', 'audit:read', 'content:moderate'],
        tenant_id: 'org_acme_prod',
      },
      secret
    );
  }

  if (preset === 'guest_expired') {
    // Expired 47 minutes ago
    return signJwtHmac(
      { alg: 'HS256', typ: 'JWT', kid: 'ap-key-2024-11' },
      {
        sub: 'usr_100492_guest',
        name: 'Preview Sandbox User',
        email: 'guest@authpulse.dev',
        iss: 'https://auth.authpulse.dev/',
        aud: 'https://api.authpulse.dev/v1',
        iat: now - 6420,
        exp: now - 47 * 60,
        jti: 'tok_11e029a841bc',
        roles: ['guest'],
        scopes: ['public:read', 'profile:read'],
        tenant_id: 'org_sandbox',
      },
      secret
    );
  }

  // service_m2m
  return signJwtHmac(
    { alg: 'HS512', typ: 'JWT', kid: 'ap-m2m-2025-02' },
    {
      sub: 'svc_billing_sync@clients.authpulse.dev',
      iss: 'https://auth.authpulse.dev/',
      aud: 'https://api.authpulse.dev/v1',
      iat: now - 300,
      exp: now + 24 * 3600,
      jti: 'm2m_7819bc3019de',
      grant_type: 'client_credentials',
      client_id: 'cli_billing_worker_09',
      roles: ['service_account'],
      scopes: ['billing:sync', 'webhooks:ingest', 'users:read'],
      tenant_id: 'org_acme_prod',
    },
    secret
  );
}

export function formatDurationBreakdown(diffSeconds: number): string {
  const abs = Math.abs(Math.floor(diffSeconds));
  const days = Math.floor(abs / 86400);
  const hours = Math.floor((abs % 86400) / 3600);
  const minutes = Math.floor((abs % 3600) / 60);
  const seconds = abs % 60;

  const parts: string[] = [];
  if (days > 0) parts.push(`${days} ${days === 1 ? 'day' : 'days'}`);
  if (hours > 0) parts.push(`${hours} ${hours === 1 ? 'hour' : 'hours'}`);
  if (minutes > 0) parts.push(`${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`);
  if (days === 0 && hours === 0) {
    parts.push(`${seconds} ${seconds === 1 ? 'second' : 'seconds'}`);
  } else if (days === 0 && minutes === 0) {
    parts.push(`${seconds}s`);
  }

  return parts.join(' ');
}

export function formatUnixTimestamp(ts?: number): string {
  if (typeof ts !== 'number' || Number.isNaN(ts)) return '—';
  return new Date(ts * 1000).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export const CLAIM_DESCRIPTIONS: Record<string, { label: string; spec: string; description: string }> = {
  sub: {
    label: 'Subject',
    spec: 'RFC 7519 §4.1.2',
    description: 'Unique principal identifier (user ID or service client ID) that is the subject of the JWT.',
  },
  iss: {
    label: 'Issuer',
    spec: 'RFC 7519 §4.1.1',
    description: 'Authorization server URI or identifier that signed and issued this token.',
  },
  aud: {
    label: 'Audience',
    spec: 'RFC 7519 §4.1.3',
    description: 'Intended recipient API(s) or resource server(s) permitted to accept this token.',
  },
  exp: {
    label: 'Expiration Time',
    spec: 'RFC 7519 §4.1.4',
    description: 'NumericDate (Unix epoch seconds) on or after which the JWT must be rejected.',
  },
  iat: {
    label: 'Issued At',
    spec: 'RFC 7519 §4.1.6',
    description: 'NumericDate indicating the exact timestamp when the JWT was minted.',
  },
  nbf: {
    label: 'Not Before',
    spec: 'RFC 7519 §4.1.5',
    description: 'NumericDate before which the JWT must not be accepted for processing.',
  },
  jti: {
    label: 'JWT ID',
    spec: 'RFC 7519 §4.1.7',
    description: 'Case-sensitive unique token identifier used to prevent replay attacks and support revocation.',
  },
  roles: {
    label: 'RBAC Roles',
    spec: 'Custom Claim',
    description: 'Assigned authorization roles evaluated by API gateway and RBAC middleware.',
  },
  role: {
    label: 'RBAC Role',
    spec: 'Custom Claim',
    description: 'Primary authorization role assigned to the authenticated principal.',
  },
  scopes: {
    label: 'OAuth2 Scopes',
    spec: 'RFC 8693',
    description: 'Fine-grained delegated permission strings granted during OAuth2 consent.',
  },
  scope: {
    label: 'OAuth2 Scope',
    spec: 'RFC 6749 §3.3',
    description: 'Space-delimited OAuth2 access scopes granted to the client.',
  },
  tenant_id: {
    label: 'Tenant / Org ID',
    spec: 'Multi-Tenant Claim',
    description: 'Workspace or organization boundary isolating tenant resources.',
  },
  azp: {
    label: 'Authorized Party',
    spec: 'OIDC Core §2',
    description: 'Client ID to which the ID Token was issued when multiple audiences exist.',
  },
  amr: {
    label: 'Auth Methods',
    spec: 'RFC 8176',
    description: 'Authentication Methods References indicating how the user authenticated (e.g. pwd, mfa).',
  },
};
