export type NavTab = 'inspector' | 'oauth' | 'rbac' | 'generator';

export type JwtAlgorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'ES256';

export interface JwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

export interface JwtPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  nbf?: number;
  jti?: string;
  name?: string;
  email?: string;
  roles?: string[];
  role?: string;
  scope?: string;
  scopes?: string[];
  tenant_id?: string;
  [key: string]: unknown;
}

export interface DecodedJwt {
  raw: string;
  headerRaw: string;
  payloadRaw: string;
  signatureRaw: string;
  header: JwtHeader | null;
  payload: JwtPayload | null;
  isValidFormat: boolean;
  parseError?: string;
}

export type SignatureStatus = 'empty' | 'verifying' | 'valid' | 'invalid' | 'unsupported';

export type SamplePresetId = 'admin_valid' | 'moderator_expiring' | 'guest_expired' | 'service_m2m';

export type OAuthFlowType = 'pkce' | 'client_credentials' | 'implicit';

export type OAuthActor = 'user_agent' | 'auth_server' | 'resource_server';

export interface OAuthStep {
  id: string;
  stepNumber: number;
  title: string;
  subtitle: string;
  from: OAuthActor;
  to: OAuthActor;
  method: 'GET' | 'POST' | '302' | '200' | 'VERIFY';
  endpoint: string;
  description: string;
  requestHeaders?: Record<string, string>;
  requestParams?: Record<string, string>;
  requestBody?: Record<string, unknown>;
  responseStatus: string;
  responseHeaders?: Record<string, string>;
  responseBody: Record<string, unknown>;
  securityNote: string;
}

export type RbacRoleId = 'admin' | 'moderator' | 'guest' | 'service_account';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface RbacEndpoint {
  id: string;
  method: HttpMethod;
  path: string;
  domain: 'Users' | 'Auth & Tokens' | 'Content & Audit' | 'System & Billing';
  requiredPermission: string;
  description: string;
  allowedRoles: RbacRoleId[];
}
