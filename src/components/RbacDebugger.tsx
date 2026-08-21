import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  Filter,
  Key,
  Link2,
  Lock,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  User,
  UserCheck,
  XCircle,
} from 'lucide-react';
import { DecodedJwt, HttpMethod, RbacEndpoint, RbacRoleId } from '../types/auth';
import { JsonViewer } from './JsonViewer';

interface RbacDebuggerProps {
  decodedJwt: DecodedJwt;
  sessionResetKey: number;
}

interface RoleDefinition {
  id: RbacRoleId;
  label: string;
  badgeColor: string;
  description: string;
  permissions: string[];
  icon: React.ReactNode;
}

const ROLE_DEFINITIONS: Record<RbacRoleId, RoleDefinition> = {
  admin: {
    id: 'admin',
    label: 'admin',
    badgeColor: 'border-violet-500/40 bg-violet-500/15 text-violet-300',
    description: 'Full tenant & system governance including destructive user & token actions.',
    permissions: [
      'users:read',
      'users:write',
      'users:suspend',
      'users:delete',
      'tokens:revoke',
      'audit:read',
      'content:moderate',
      'billing:read',
      'billing:sync',
      'webhooks:ingest',
      'system:config',
      'public:read',
    ],
    icon: <ShieldCheck className="h-4 w-4 text-violet-400" />,
  },
  moderator: {
    id: 'moderator',
    label: 'moderator',
    badgeColor: 'border-cyan-500/40 bg-cyan-500/15 text-cyan-300',
    description: 'Trust & safety operations: read directory, suspend accounts, inspect audit trails.',
    permissions: ['users:read', 'users:suspend', 'audit:read', 'content:moderate', 'public:read'],
    icon: <UserCheck className="h-4 w-4 text-cyan-400" />,
  },
  guest: {
    id: 'guest',
    label: 'guest',
    badgeColor: 'border-slate-600/60 bg-slate-800/80 text-slate-300',
    description: 'Unprivileged read-only sandbox session restricted to public & own profile routes.',
    permissions: ['public:read'],
    icon: <User className="h-4 w-4 text-slate-400" />,
  },
  service_account: {
    id: 'service_account',
    label: 'service_account',
    badgeColor: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300',
    description: 'Headless M2M worker identity for webhook ingestion, billing sync & user lookups.',
    permissions: ['users:read', 'billing:sync', 'webhooks:ingest', 'public:read'],
    icon: <Bot className="h-4 w-4 text-emerald-400" />,
  },
};

const INITIAL_ENDPOINTS: RbacEndpoint[] = [
  {
    id: 'ep-1',
    method: 'GET',
    path: '/api/v1/users',
    domain: 'Users',
    requiredPermission: 'users:read',
    description: 'List organization users & role assignments',
    allowedRoles: ['admin', 'moderator', 'service_account'],
  },
  {
    id: 'ep-2',
    method: 'POST',
    path: '/api/v1/users',
    domain: 'Users',
    requiredPermission: 'users:write',
    description: 'Provision a new user account or invite member',
    allowedRoles: ['admin'],
  },
  {
    id: 'ep-3',
    method: 'PATCH',
    path: '/api/v1/users/:id/suspend',
    domain: 'Users',
    requiredPermission: 'users:suspend',
    description: 'Temporarily lock user login & active sessions',
    allowedRoles: ['admin', 'moderator'],
  },
  {
    id: 'ep-4',
    method: 'DELETE',
    path: '/api/v1/users/:id',
    domain: 'Users',
    requiredPermission: 'users:delete',
    description: 'Permanently purge user PII & identity record',
    allowedRoles: ['admin'],
  },
  {
    id: 'ep-5',
    method: 'POST',
    path: '/api/v1/tokens/revoke',
    domain: 'Auth & Tokens',
    requiredPermission: 'tokens:revoke',
    description: 'Revoke active refresh tokens & JTI allowlist entries',
    allowedRoles: ['admin'],
  },
  {
    id: 'ep-6',
    method: 'GET',
    path: '/api/v1/audit/logs',
    domain: 'Content & Audit',
    requiredPermission: 'audit:read',
    description: 'Query immutable authentication & RBAC audit trail',
    allowedRoles: ['admin', 'moderator'],
  },
  {
    id: 'ep-7',
    method: 'PUT',
    path: '/api/v1/content/:id/moderation',
    domain: 'Content & Audit',
    requiredPermission: 'content:moderate',
    description: 'Approve, flag, or quarantine user-submitted content',
    allowedRoles: ['admin', 'moderator'],
  },
  {
    id: 'ep-8',
    method: 'GET',
    path: '/api/v1/billing/invoices',
    domain: 'System & Billing',
    requiredPermission: 'billing:read',
    description: 'Read organization subscription & invoice history',
    allowedRoles: ['admin'],
  },
  {
    id: 'ep-9',
    method: 'POST',
    path: '/api/v1/webhooks/ingest',
    domain: 'System & Billing',
    requiredPermission: 'webhooks:ingest',
    description: 'Ingest signed asynchronous billing & telemetry events',
    allowedRoles: ['admin', 'service_account'],
  },
  {
    id: 'ep-10',
    method: 'GET',
    path: '/api/v1/public/health',
    domain: 'System & Billing',
    requiredPermission: 'public:read',
    description: 'Read public service status & OIDC discovery metadata',
    allowedRoles: ['admin', 'moderator', 'guest', 'service_account'],
  },
];

const METHOD_BADGE_STYLES: Record<HttpMethod, string> = {
  GET: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  POST: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  PUT: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  PATCH: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
  DELETE: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
};

export const RbacDebugger: React.FC<RbacDebuggerProps> = ({ decodedJwt, sessionResetKey }) => {
  const [selectedRole, setSelectedRole] = useState<RbacRoleId>('admin');
  const [syncedFromJwt, setSyncedFromJwt] = useState<boolean>(false);
  const [endpoints, setEndpoints] = useState<RbacEndpoint[]>(INITIAL_ENDPOINTS);

  // Live Endpoint Checker inputs
  const [checkMethod, setCheckMethod] = useState<HttpMethod>('GET');
  const [checkPath, setCheckPath] = useState<string>('/api/v1/users');
  const [domainFilter, setDomainFilter] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Extract roles from active JWT if present
  const jwtRoles = useMemo<RbacRoleId[]>(() => {
    const validRoleIds: RbacRoleId[] = ['admin', 'moderator', 'guest', 'service_account'];
    const found: RbacRoleId[] = [];
    if (decodedJwt.payload) {
      const rawRoles = Array.isArray(decodedJwt.payload.roles)
        ? decodedJwt.payload.roles
        : typeof decodedJwt.payload.role === 'string'
        ? [decodedJwt.payload.role]
        : [];
      rawRoles.forEach((r) => {
        if (typeof r === 'string' && validRoleIds.includes(r as RbacRoleId)) {
          found.push(r as RbacRoleId);
        }
      });
    }
    return found;
  }, [decodedJwt]);

  const isJwtExpired = useMemo(() => {
    if (typeof decodedJwt.payload?.exp !== 'number') return false;
    return decodedJwt.payload.exp <= Math.floor(Date.now() / 1000);
  }, [decodedJwt]);

  // Reset overrides when global Clear All Sessions is clicked
  useEffect(() => {
    if (sessionResetKey > 0) {
      setEndpoints(INITIAL_ENDPOINTS);
      setSyncedFromJwt(false);
      setSelectedRole('guest');
      setCheckMethod('GET');
      setCheckPath('/api/v1/users');
    }
  }, [sessionResetKey]);

  const handleSyncFromJwt = () => {
    if (jwtRoles.length > 0) {
      setSelectedRole(jwtRoles[0]);
      setSyncedFromJwt(true);
    }
  };

  const toggleRolePermissionOnEndpoint = (endpointId: string, role: RbacRoleId) => {
    setEndpoints((prev) =>
      prev.map((ep) => {
        if (ep.id !== endpointId) return ep;
        const hasRole = ep.allowedRoles.includes(role);
        return {
          ...ep,
          allowedRoles: hasRole
            ? ep.allowedRoles.filter((r) => r !== role)
            : [...ep.allowedRoles, role],
        };
      })
    );
  };

  // Match the Live Route Evaluator against known endpoints (or infer rule for custom paths)
  const evaluation = useMemo(() => {
    const normalizedPath = checkPath.trim() || '/';
    const matchedEndpoint = endpoints.find(
      (ep) =>
        ep.method === checkMethod &&
        (ep.path.toLowerCase() === normalizedPath.toLowerCase() ||
          normalizedPath
            .toLowerCase()
            .startsWith(ep.path.split('/:')[0].toLowerCase() + '/'))
    );

    const effectiveRoles: RbacRoleId[] =
      syncedFromJwt && jwtRoles.length > 0 ? jwtRoles : [selectedRole];

    if (matchedEndpoint) {
      const matchingRoles = effectiveRoles.filter((r) =>
        matchedEndpoint.allowedRoles.includes(r)
      );
      const isAllowed = matchingRoles.length > 0 && !(syncedFromJwt && isJwtExpired);

      let reason = '';
      if (syncedFromJwt && isJwtExpired) {
        reason = `Token expired (exp: ${decodedJwt.payload?.exp}). Gateway rejects request with 401/403 before RBAC evaluation.`;
      } else if (isAllowed) {
        reason = `Principal role [${matchingRoles.join(', ')}] satisfies required permission "${matchedEndpoint.requiredPermission}" for ${matchedEndpoint.method} ${matchedEndpoint.path}.`;
      } else {
        reason = `Access Denied: Principal role [${effectiveRoles.join(', ')}] lacks required permission "${matchedEndpoint.requiredPermission}". Allowed roles: [${matchedEndpoint.allowedRoles.join(', ')}].`;
      }

      return {
        isAllowed,
        statusCode: syncedFromJwt && isJwtExpired ? 401 : isAllowed ? 200 : 403,
        statusText: syncedFromJwt && isJwtExpired ? 'Unauthorized (Expired JWT)' : isAllowed ? 'Allowed' : 'Denied',
        requiredPermission: matchedEndpoint.requiredPermission,
        allowedRoles: matchedEndpoint.allowedRoles,
        effectiveRoles,
        reason,
        matchedEndpoint,
      };
    }

    // Custom route fallback evaluation
    const isReadMethod = checkMethod === 'GET';
    const isAllowed =
      !(syncedFromJwt && isJwtExpired) &&
      (effectiveRoles.includes('admin') ||
        (isReadMethod &&
          (effectiveRoles.includes('moderator') || effectiveRoles.includes('service_account'))));

    return {
      isAllowed,
      statusCode: syncedFromJwt && isJwtExpired ? 401 : isAllowed ? 200 : 403,
      statusText: syncedFromJwt && isJwtExpired ? 'Unauthorized' : isAllowed ? 'Allowed' : 'Denied',
      requiredPermission: isReadMethod ? 'custom:read' : 'custom:write (admin)',
      allowedRoles: isReadMethod ? (['admin', 'moderator', 'service_account'] as RbacRoleId[]) : (['admin'] as RbacRoleId[]),
      effectiveRoles,
      reason: isAllowed
        ? `Custom route ${checkMethod} ${normalizedPath} permitted for role [${effectiveRoles.join(', ')}].`
        : `Custom route ${checkMethod} ${normalizedPath} denied for role [${effectiveRoles.join(', ')}].`,
      matchedEndpoint: null,
    };
  }, [checkMethod, checkPath, endpoints, selectedRole, syncedFromJwt, jwtRoles, isJwtExpired, decodedJwt.payload?.exp]);

  const filteredEndpoints = useMemo(() => {
    return endpoints.filter((ep) => {
      const matchesDomain = domainFilter === 'All' || ep.domain === domainFilter;
      const q = searchQuery.trim().toLowerCase();
      const matchesQuery =
        !q ||
        ep.path.toLowerCase().includes(q) ||
        ep.requiredPermission.toLowerCase().includes(q) ||
        ep.description.toLowerCase().includes(q);
      return matchesDomain && matchesQuery;
    });
  }, [endpoints, domainFilter, searchQuery]);

  const activeRoleDef = ROLE_DEFINITIONS[selectedRole];

  return (
    <div className="space-y-5">
      {/* Top Role Selector & Active JWT Sync Card */}
      <div className="rounded-xl border border-slate-800/90 bg-[#111827] p-4 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              RBAC Principal Role Selector
            </h2>
            <p className="text-xs text-slate-400">
              Select a role profile or bind directly to the active JWT&apos;s <code className="text-emerald-300">roles</code> claim
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {jwtRoles.length > 0 && (
              <button
                type="button"
                onClick={handleSyncFromJwt}
                className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                  syncedFromJwt
                    ? 'border-emerald-500/50 bg-emerald-500/20 text-emerald-200'
                    : 'border-violet-500/40 bg-violet-500/15 text-violet-200 hover:bg-violet-500/25'
                }`}
              >
                <Link2 className="h-3.5 w-3.5" />
                <span>
                  {syncedFromJwt
                    ? `Synced to JWT (${jwtRoles.join(', ')})`
                    : `Sync Role from JWT (${jwtRoles.join(', ')})`}
                </span>
              </button>
            )}

            <button
              type="button"
              onClick={() => setEndpoints(INITIAL_ENDPOINTS)}
              title="Reset custom matrix policy overrides"
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-[#0d1320] px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-600 transition-colors"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              <span>Reset Matrix</span>
            </button>
          </div>
        </div>

        {/* 4 Interactive Role Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {(['admin', 'moderator', 'guest', 'service_account'] as RbacRoleId[]).map((roleId) => {
            const role = ROLE_DEFINITIONS[roleId];
            const isSelected = selectedRole === roleId;
            const isJwtMember = syncedFromJwt && jwtRoles.includes(roleId);

            return (
              <button
                key={roleId}
                type="button"
                onClick={() => {
                  setSelectedRole(roleId);
                  setSyncedFromJwt(false);
                }}
                className={`text-left rounded-xl border p-3.5 transition-all ${
                  isSelected || isJwtMember
                    ? 'border-violet-500/60 bg-[#151e31] shadow-sm shadow-violet-950/30'
                    : 'border-slate-800 bg-[#0d1320] hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {role.icon}
                    <span className="font-mono text-xs font-bold text-slate-100">
                      {role.label}
                    </span>
                  </div>
                  {isJwtMember ? (
                    <span className="rounded-full bg-emerald-500/20 border border-emerald-500/40 px-2 py-0.5 font-mono text-[10px] text-emerald-300">
                      JWT Active
                    </span>
                  ) : isSelected ? (
                    <span className="rounded-full bg-violet-500/20 border border-violet-500/40 px-2 py-0.5 font-mono text-[10px] text-violet-300">
                      Selected
                    </span>
                  ) : null}
                </div>

                <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">
                  {role.description}
                </p>

                <div className="mt-2.5 flex flex-wrap gap-1">
                  {role.permissions.slice(0, 3).map((perm) => (
                    <span
                      key={perm}
                      className="rounded bg-slate-900/90 border border-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300"
                    >
                      {perm}
                    </span>
                  ))}
                  {role.permissions.length > 3 && (
                    <span className="rounded bg-slate-900/90 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">
                      +{role.permissions.length - 3} more
                    </span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Live Endpoint Permission Checker & Policy Trace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left (7 cols): Interactive Route Evaluator */}
        <div className="lg:col-span-7 rounded-xl border border-slate-800/90 bg-[#111827] overflow-hidden">
          <div className="border-b border-slate-800/80 px-4 py-3 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Endpoint Permission Checker
              </h3>
              <p className="text-xs text-slate-400">
                Test any HTTP method &amp; API route against role{' '}
                <code className="text-violet-300">
                  {evaluation.effectiveRoles.join(', ')}
                </code>
              </p>
            </div>
            <span className="font-mono text-xs text-slate-400">Middleware Simulator</span>
          </div>

          <div className="p-4 space-y-4">
            {/* Method + Endpoint Input Bar */}
            <div className="flex flex-col sm:flex-row gap-2">
              <select
                value={checkMethod}
                onChange={(e) => setCheckMethod(e.target.value as HttpMethod)}
                aria-label="HTTP Method"
                className="rounded-lg border border-slate-700/80 bg-[#0d1320] px-3 py-2 font-mono text-xs font-semibold text-cyan-300 focus:border-violet-500/70 focus:outline-none"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="PATCH">PATCH</option>
                <option value="DELETE">DELETE</option>
              </select>

              <input
                type="text"
                value={checkPath}
                onChange={(e) => setCheckPath(e.target.value)}
                placeholder="/api/v1/users"
                className="flex-1 rounded-lg border border-slate-700/80 bg-[#0d1320] px-3 py-2 font-mono text-xs text-slate-100 placeholder-slate-600 focus:border-violet-500/70 focus:outline-none"
              />
            </div>

            {/* Quick Route Preset Pills */}
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] text-slate-400 mr-1">Quick test:</span>
              {[
                { m: 'GET' as HttpMethod, p: '/api/v1/users' },
                { m: 'DELETE' as HttpMethod, p: '/api/v1/users/:id' },
                { m: 'POST' as HttpMethod, p: '/api/v1/tokens/revoke' },
                { m: 'POST' as HttpMethod, p: '/api/v1/webhooks/ingest' },
                { m: 'GET' as HttpMethod, p: '/api/v1/public/health' },
              ].map((item) => (
                <button
                  key={`${item.m}-${item.p}`}
                  type="button"
                  onClick={() => {
                    setCheckMethod(item.m);
                    setCheckPath(item.p);
                  }}
                  className="rounded-md border border-slate-800 bg-[#0d1320] hover:border-slate-700 px-2 py-1 font-mono text-[11px] text-slate-300 transition-colors"
                >
                  <span className="text-cyan-400 font-semibold">{item.m}</span> {item.p}
                </button>
              ))}
            </div>

            {/* Verdict Result Banner */}
            <div
              className={`rounded-xl border p-4 transition-colors ${
                evaluation.isAllowed
                  ? 'border-emerald-500/40 bg-emerald-950/20'
                  : 'border-rose-500/40 bg-rose-950/20'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  {evaluation.isAllowed ? (
                    <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
                  ) : (
                    <XCircle className="h-5 w-5 text-rose-400 shrink-0" />
                  )}
                  <div>
                    <div className="flex items-center gap-2 font-mono text-xs">
                      <span className="font-bold text-slate-200">
                        {checkMethod} {checkPath}
                      </span>
                      <span className="text-slate-500">→</span>
                      <span
                        className={`font-bold ${
                          evaluation.isAllowed ? 'text-emerald-400' : 'text-rose-400'
                        }`}
                      >
                        {evaluation.statusText.toUpperCase()} ({evaluation.statusCode})
                      </span>
                    </div>
                  </div>
                </div>

                <span className="rounded-md border border-slate-700/80 bg-[#0d1320] px-2 py-0.5 font-mono text-[11px] text-slate-300">
                  scope: {evaluation.requiredPermission}
                </span>
              </div>

              <p className="mt-2 text-xs leading-relaxed text-slate-300">{evaluation.reason}</p>

              {syncedFromJwt && isJwtExpired && (
                <div className="mt-2.5 flex items-center gap-1.5 text-xs text-amber-300">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  <span>
                    Active JWT is expired. Switch to a role card above or load an active token.
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right (5 cols): Simulated Gateway JSON Decision Payload */}
        <div className="lg:col-span-5 rounded-xl border border-slate-800/90 bg-[#111827] overflow-hidden">
          <div className="border-b border-slate-800/80 px-4 py-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Key className="h-4 w-4 text-violet-400" />
              <h3 className="text-sm font-semibold text-slate-100">
                Policy Decision Payload
              </h3>
            </div>
            <span
              className={`rounded-full px-2 py-0.5 font-mono text-[11px] font-semibold ${
                evaluation.isAllowed
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                  : 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
              }`}
            >
              HTTP {evaluation.statusCode}
            </span>
          </div>

          <div className="p-4 space-y-3">
            <JsonViewer
              accentColor={evaluation.isAllowed ? 'emerald' : 'violet'}
              data={{
                decision: evaluation.isAllowed ? 'ALLOW' : 'DENY',
                http_status: evaluation.statusCode,
                request: `${checkMethod} ${checkPath}`,
                principal: {
                  sub:
                    syncedFromJwt && decodedJwt.payload?.sub
                      ? decodedJwt.payload.sub
                      : `role:${selectedRole}`,
                  roles: evaluation.effectiveRoles,
                  token_bound: syncedFromJwt,
                },
                policy: {
                  required_permission: evaluation.requiredPermission,
                  permitted_roles: evaluation.allowedRoles,
                },
                ...(evaluation.isAllowed
                  ? {}
                  : {
                      error:
                        evaluation.statusCode === 401 ? 'token_expired' : 'insufficient_permissions',
                      message: evaluation.reason,
                    }),
              }}
            />

            <div className="rounded-lg border border-slate-800 bg-[#0d1320] px-3 py-2 text-[11px] text-slate-400 flex items-center justify-between">
              <span>Active Role Capabilities ({activeRoleDef.label}):</span>
              <span className="font-mono text-slate-300">
                {activeRoleDef.permissions.length} permissions granted
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Full Interactive RBAC Matrix Table */}
      <div className="rounded-xl border border-slate-800/90 bg-[#111827] overflow-hidden">
        <div className="border-b border-slate-800/80 px-4 py-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <Shield className="h-4 w-4 text-violet-400" />
              <span>Interactive Endpoint &amp; Role Permission Matrix</span>
            </h3>
            <p className="text-xs text-slate-400">
              Click any row to test in the route checker, or click any role cell to toggle a live policy override
            </p>
          </div>

          {/* Search & Domain Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="h-3.5 w-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter routes or scopes..."
                className="rounded-lg border border-slate-800 bg-[#0d1320] pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-violet-500/60 focus:outline-none"
              />
            </div>

            <div className="inline-flex items-center rounded-lg border border-slate-800 bg-[#0d1320] p-0.5 text-xs">
              <Filter className="h-3 w-3 text-slate-500 mx-2" />
              {['All', 'Users', 'Auth & Tokens', 'Content & Audit', 'System & Billing'].map(
                (domain) => (
                  <button
                    key={domain}
                    type="button"
                    onClick={() => setDomainFilter(domain)}
                    className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
                      domainFilter === domain
                        ? 'bg-violet-500/20 text-violet-300'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {domain}
                  </button>
                )
              )}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-[#0d1320]/80 text-[11px] uppercase tracking-wider text-slate-400">
                <th className="py-3 px-4 font-semibold">API Endpoint</th>
                <th className="py-3 px-3 font-semibold">Required Scope</th>
                {(['admin', 'moderator', 'guest', 'service_account'] as RbacRoleId[]).map((r) => (
                  <th
                    key={r}
                    className={`py-3 px-3 font-mono font-semibold text-center ${
                      evaluation.effectiveRoles.includes(r) ? 'text-violet-300 bg-violet-500/5' : ''
                    }`}
                  >
                    {r}
                  </th>
                ))}
                <th className="py-3 px-4 font-semibold text-right">Current Verdict</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-xs">
              {filteredEndpoints.map((ep) => {
                const isRowAllowed =
                  !(syncedFromJwt && isJwtExpired) &&
                  evaluation.effectiveRoles.some((r) => ep.allowedRoles.includes(r));
                const isSelectedRow = checkMethod === ep.method && checkPath === ep.path;

                return (
                  <tr
                    key={ep.id}
                    onClick={() => {
                      setCheckMethod(ep.method);
                      setCheckPath(ep.path);
                    }}
                    className={`cursor-pointer transition-colors ${
                      isSelectedRow
                        ? 'bg-violet-500/10'
                        : 'hover:bg-slate-800/35'
                    }`}
                  >
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <span
                          className={`inline-block w-14 text-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold ${
                            METHOD_BADGE_STYLES[ep.method]
                          }`}
                        >
                          {ep.method}
                        </span>
                        <code className="font-mono text-xs font-medium text-slate-100">
                          {ep.path}
                        </code>
                      </div>
                      <div className="mt-0.5 pl-16 text-[11px] text-slate-400">
                        {ep.description}
                      </div>
                    </td>

                    <td className="py-3 px-3">
                      <span className="rounded bg-[#0d1320] border border-slate-800 px-2 py-0.5 font-mono text-[11px] text-cyan-300">
                        {ep.requiredPermission}
                      </span>
                    </td>

                    {(['admin', 'moderator', 'guest', 'service_account'] as RbacRoleId[]).map(
                      (roleId) => {
                        const allowed = ep.allowedRoles.includes(roleId);
                        const isHighlightedCol = evaluation.effectiveRoles.includes(roleId);

                        return (
                          <td
                            key={roleId}
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleRolePermissionOnEndpoint(ep.id, roleId);
                            }}
                            title={`Click to toggle ${roleId} access for ${ep.method} ${ep.path}`}
                            className={`py-3 px-3 text-center ${
                              isHighlightedCol ? 'bg-violet-500/5' : ''
                            }`}
                          >
                            <span
                              className={`inline-flex items-center justify-center h-6 w-6 rounded-md border transition-colors ${
                                allowed
                                  ? 'border-emerald-500/35 bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/25'
                                  : 'border-slate-800 bg-[#0d1320] text-slate-600 hover:border-rose-500/30 hover:text-rose-400'
                              }`}
                            >
                              {allowed ? (
                                <CheckCircle2 className="h-3.5 w-3.5" />
                              ) : (
                                <Lock className="h-3 w-3" />
                              )}
                            </span>
                          </td>
                        );
                      }
                    )}

                    <td className="py-3 px-4 text-right">
                      {isRowAllowed ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 border border-emerald-500/35 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-emerald-300">
                          <CheckCircle2 className="h-3 w-3" />
                          Allowed
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full bg-rose-500/15 border border-rose-500/35 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-rose-300">
                          <ShieldAlert className="h-3 w-3" />
                          Denied
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
