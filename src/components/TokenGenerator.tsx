import React, { useEffect, useState } from 'react';
import {
  ArrowRight,
  Check,
  Clock,
  Copy,
  KeyRound,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Wand2,
} from 'lucide-react';
import { JwtAlgorithm, JwtHeader, JwtPayload, RbacRoleId } from '../types/auth';
import { DEFAULT_HMAC_SECRET, signJwtHmac } from '../utils/jwtCrypto';

interface TokenGeneratorProps {
  sharedSecret: string;
  onUseTokenInInspector: (token: string, signingSecret: string) => void;
}

const ALL_ROLES: RbacRoleId[] = ['admin', 'moderator', 'guest', 'service_account'];

export const TokenGenerator: React.FC<TokenGeneratorProps> = ({
  sharedSecret,
  onUseTokenInInspector,
}) => {
  const [alg, setAlg] = useState<JwtAlgorithm>('HS256');
  const [kid, setKid] = useState<string>('ap-key-2025-01');
  const [signingSecret, setSigningSecret] = useState<string>(sharedSecret || DEFAULT_HMAC_SECRET);

  const [payloadText, setPayloadText] = useState<string>(() => {
    const now = Math.floor(Date.now() / 1000);
    return JSON.stringify(
      {
        sub: 'usr_90214_dev',
        name: 'Devon Brooks',
        email: 'devon@authpulse.dev',
        iss: 'https://auth.authpulse.dev/',
        aud: 'https://api.authpulse.dev/v1',
        iat: now,
        exp: now + 3600,
        jti: `tok_${Math.random().toString(36).substring(2, 10)}`,
        roles: ['admin'],
        scopes: ['users:read', 'users:write', 'audit:read'],
        tenant_id: 'org_acme_prod',
      },
      null,
      2
    );
  });

  const [jsonError, setJsonError] = useState<string | null>(null);
  const [generatedToken, setGeneratedToken] = useState<string>('');
  const [copiedType, setCopiedType] = useState<'raw' | 'bearer' | null>(null);

  // Keep signing secret synced if sharedSecret updates
  useEffect(() => {
    if (sharedSecret) {
      setSigningSecret(sharedSecret);
    }
  }, [sharedSecret]);

  // Sign token whenever header, payload, or secret changes
  useEffect(() => {
    let active = true;
    try {
      const parsed = JSON.parse(payloadText);
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        setJsonError('Payload must be a valid JSON object.');
        return;
      }
      setJsonError(null);

      const header: JwtHeader = {
        alg,
        typ: 'JWT',
        ...(kid.trim() ? { kid: kid.trim() } : {}),
      };

      signJwtHmac(header, parsed as JwtPayload, signingSecret).then((jwt) => {
        if (active) setGeneratedToken(jwt);
      });
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : 'Invalid JSON syntax');
    }

    return () => {
      active = false;
    };
  }, [alg, kid, payloadText, signingSecret]);

  const updatePayloadObject = (updater: (obj: Record<string, unknown>) => Record<string, unknown>) => {
    try {
      const current = JSON.parse(payloadText);
      if (typeof current === 'object' && current !== null && !Array.isArray(current)) {
        const updated = updater({ ...current });
        setPayloadText(JSON.stringify(updated, null, 2));
        setJsonError(null);
      }
    } catch {
      // ignore if user currently has invalid JSON
    }
  };

  const applyTtlOffset = (secondsOffset: number) => {
    const now = Math.floor(Date.now() / 1000);
    updatePayloadObject((obj) => ({
      ...obj,
      iat: now,
      exp: now + secondsOffset,
    }));
  };

  const toggleRole = (role: RbacRoleId) => {
    updatePayloadObject((obj) => {
      const existing = Array.isArray(obj.roles)
        ? obj.roles.filter((r): r is string => typeof r === 'string')
        : [];
      const nextRoles = existing.includes(role)
        ? existing.filter((r) => r !== role)
        : [...existing, role];
      return {
        ...obj,
        roles: nextRoles,
      };
    });
  };

  const regenerateJti = () => {
    updatePayloadObject((obj) => ({
      ...obj,
      jti: `tok_${Math.random().toString(36).substring(2, 12)}`,
    }));
  };

  let activeRolesInJson: string[] = [];
  try {
    const parsed = JSON.parse(payloadText);
    if (Array.isArray(parsed?.roles)) {
      activeRolesInJson = parsed.roles;
    }
  } catch {
    // ignore
  }

  const tokenParts = generatedToken.split('.');

  const handleCopy = async (mode: 'raw' | 'bearer') => {
    if (!generatedToken) return;
    const text = mode === 'bearer' ? `Bearer ${generatedToken}` : generatedToken;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedType(mode);
      setTimeout(() => setCopiedType(null), 1600);
    } catch {
      // ignore
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
      {/* LEFT (7 cols): Claims & Header Builder */}
      <div className="lg:col-span-7 rounded-xl border border-slate-800/90 bg-[#111827] overflow-hidden">
        <div className="border-b border-slate-800/80 px-4 py-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Wand2 className="h-4 w-4 text-violet-400" />
            <div>
              <h2 className="text-sm font-semibold text-slate-100">JWT Claims &amp; Header Builder</h2>
              <p className="text-xs text-slate-400">
                Craft custom signed tokens with Web Crypto HMAC-SHA signing
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={regenerateJti}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-[#0d1320] px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-600 transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>New JTI</span>
          </button>
        </div>

        <div className="p-4 space-y-4">
          {/* Header Settings Row */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider text-cyan-400 mb-1">
                Signing Algorithm (alg)
              </label>
              <select
                value={alg}
                onChange={(e) => setAlg(e.target.value as JwtAlgorithm)}
                className="w-full rounded-lg border border-slate-700/80 bg-[#0d1320] px-3 py-2 font-mono text-xs text-slate-100 focus:border-cyan-500/70 focus:outline-none"
              >
                <option value="HS256">HS256 (HMAC SHA-256)</option>
                <option value="HS384">HS384 (HMAC SHA-384)</option>
                <option value="HS512">HS512 (HMAC SHA-512)</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider text-cyan-400 mb-1">
                Key ID (kid)
              </label>
              <input
                type="text"
                value={kid}
                onChange={(e) => setKid(e.target.value)}
                placeholder="ap-key-2025-01"
                className="w-full rounded-lg border border-slate-700/80 bg-[#0d1320] px-3 py-2 font-mono text-xs text-slate-100 focus:border-cyan-500/70 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider text-violet-400 mb-1">
                HMAC Secret Key
              </label>
              <input
                type="text"
                value={signingSecret}
                onChange={(e) => setSigningSecret(e.target.value)}
                className="w-full rounded-lg border border-slate-700/80 bg-[#0d1320] px-3 py-2 font-mono text-xs text-slate-100 focus:border-violet-500/70 focus:outline-none"
              />
            </div>
          </div>

          {/* Quick TTL / Expiration Presets */}
          <div className="rounded-lg border border-slate-800/80 bg-[#0d1320] p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5 text-emerald-400" />
                <span>Quick Expiration (exp) Presets</span>
              </span>
              <span className="text-[11px] text-slate-500">Updates iat &amp; exp</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {[
                { label: '+5m (Warning)', sec: 300, cls: 'border-amber-500/30 bg-amber-500/10 text-amber-300' },
                { label: '+1 Hour', sec: 3600, cls: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' },
                { label: '+3h 42m', sec: 3 * 3600 + 42 * 60, cls: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' },
                { label: '+24 Hours', sec: 86400, cls: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300' },
                { label: '-15m (Expired)', sec: -900, cls: 'border-rose-500/30 bg-rose-500/10 text-rose-300' },
              ].map((preset) => (
                <button
                  key={preset.label}
                  type="button"
                  onClick={() => applyTtlOffset(preset.sec)}
                  className={`rounded-md border px-2.5 py-1 font-mono text-[11px] font-medium hover:brightness-110 transition-all ${preset.cls}`}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          {/* Role Toggle Chips */}
          <div className="rounded-lg border border-slate-800/80 bg-[#0d1320] p-3 space-y-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Sparkles className="h-3.5 w-3.5 text-violet-400" />
              <span>Assign RBAC Roles (roles claim)</span>
            </span>
            <div className="flex flex-wrap gap-2">
              {ALL_ROLES.map((r) => {
                const active = activeRolesInJson.includes(r);
                return (
                  <button
                    key={r}
                    type="button"
                    onClick={() => toggleRole(r)}
                    className={`rounded-lg border px-3 py-1 font-mono text-xs font-medium transition-colors ${
                      active
                        ? 'border-violet-500/60 bg-violet-500/20 text-violet-200'
                        : 'border-slate-800 bg-slate-900/80 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                    }`}
                  >
                    {active ? `✓ ${r}` : `+ ${r}`}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Editable Payload JSON */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-[11px] font-semibold uppercase tracking-wider text-emerald-400">
                Payload Claims JSON
              </label>
              {jsonError ? (
                <span className="text-xs font-mono text-rose-400">{jsonError}</span>
              ) : (
                <span className="text-[11px] font-mono text-emerald-400">Valid JSON</span>
              )}
            </div>
            <textarea
              value={payloadText}
              onChange={(e) => setPayloadText(e.target.value)}
              rows={12}
              spellCheck={false}
              className="w-full rounded-lg border border-slate-700/80 bg-[#0d1320] p-3 font-mono text-xs leading-relaxed text-emerald-200 focus:border-emerald-500/70 focus:outline-none focus:ring-1 focus:ring-emerald-500/30"
            />
          </div>
        </div>
      </div>

      {/* RIGHT (5 cols): Live Signed JWT Output */}
      <div className="lg:col-span-5 rounded-xl border border-slate-800/90 bg-[#111827] overflow-hidden">
        <div className="border-b border-slate-800/80 px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Signed Output Token</h2>
              <p className="text-xs text-slate-400">Real-time {alg} compact serialization</p>
            </div>
          </div>
          <span className="rounded-full bg-emerald-500/15 border border-emerald-500/35 px-2.5 py-0.5 font-mono text-[11px] font-semibold text-emerald-300">
            Signed ({alg})
          </span>
        </div>

        <div className="p-4 space-y-4">
          {/* Tri-Color Token Box */}
          <div className="rounded-xl border border-slate-800 bg-[#0d1320] p-4 font-mono text-xs leading-relaxed break-all select-all">
            {tokenParts.length === 3 ? (
              <>
                <span className="text-cyan-400">{tokenParts[0]}</span>
                <span className="text-slate-500 font-bold">.</span>
                <span className="text-emerald-400">{tokenParts[1]}</span>
                <span className="text-slate-500 font-bold">.</span>
                <span className="text-violet-400">{tokenParts[2]}</span>
              </>
            ) : (
              <span className="text-slate-500">Fix JSON syntax to generate signed JWT...</span>
            )}
          </div>

          {/* Segment Legend */}
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 px-1">
            <span className="text-cyan-400">■ Header ({tokenParts[0]?.length || 0}B)</span>
            <span className="text-emerald-400">■ Payload ({tokenParts[1]?.length || 0}B)</span>
            <span className="text-violet-400">■ Signature ({tokenParts[2]?.length || 0}B)</span>
          </div>

          {/* Action Buttons */}
          <div className="grid grid-cols-2 gap-2.5">
            <button
              type="button"
              onClick={() => handleCopy('raw')}
              disabled={!generatedToken}
              className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-[#0d1320] hover:border-slate-600 px-3 py-2 text-xs font-medium text-slate-200 disabled:opacity-40 transition-colors"
            >
              {copiedType === 'raw' ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Copied JWT</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" />
                  <span>Copy Raw JWT</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => handleCopy('bearer')}
              disabled={!generatedToken}
              className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-[#0d1320] hover:border-slate-600 px-3 py-2 text-xs font-medium text-slate-200 disabled:opacity-40 transition-colors"
            >
              {copiedType === 'bearer' ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Copied Bearer</span>
                </>
              ) : (
                <>
                  <KeyRound className="h-3.5 w-3.5" />
                  <span>Copy Bearer Header</span>
                </>
              )}
            </button>
          </div>

          <button
            type="button"
            disabled={!generatedToken || Boolean(jsonError)}
            onClick={() => onUseTokenInInspector(generatedToken, signingSecret)}
            className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:opacity-40 px-4 py-2.5 text-xs font-semibold text-white shadow-sm shadow-violet-600/30 transition-colors"
          >
            <span>Open &amp; Verify in JWT Inspector</span>
            <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
