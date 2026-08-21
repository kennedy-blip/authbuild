import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  ClipboardPaste,
  Clock,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
} from 'lucide-react';
import { DecodedJwt, SamplePresetId, SignatureStatus } from '../types/auth';
import {
  CLAIM_DESCRIPTIONS,
  DEFAULT_HMAC_SECRET,
  formatDurationBreakdown,
  formatUnixTimestamp,
  signJwtHmac,
} from '../utils/jwtCrypto';
import { JsonViewer } from './JsonViewer';

interface JwtInspectorProps {
  tokenInput: string;
  onTokenChange: (newToken: string) => void;
  decoded: DecodedJwt;
  secret: string;
  onSecretChange: (newSecret: string) => void;
  isBase64Secret: boolean;
  onBase64SecretChange: (val: boolean) => void;
  signatureStatus: SignatureStatus;
  onLoadPreset: (preset: SamplePresetId) => void;
  onTestInRbac: () => void;
}

export const JwtInspector: React.FC<JwtInspectorProps> = ({
  tokenInput,
  onTokenChange,
  decoded,
  secret,
  onSecretChange,
  isBase64Secret,
  onBase64SecretChange,
  signatureStatus,
  onLoadPreset,
  onTestInRbac,
}) => {
  const [nowSec, setNowSec] = useState<number>(() => Math.floor(Date.now() / 1000));
  const [showSecret, setShowSecret] = useState<boolean>(true);
  const [copiedRaw, setCopiedRaw] = useState<boolean>(false);
  const [highlightedPart, setHighlightedPart] = useState<'header' | 'payload' | 'signature' | null>(null);
  const [payloadViewMode, setPayloadViewMode] = useState<'json' | 'claims'>('json');

  useEffect(() => {
    const interval = setInterval(() => {
      setNowSec(Math.floor(Date.now() / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleCopyToken = async () => {
    if (!decoded.raw) return;
    try {
      await navigator.clipboard.writeText(decoded.raw);
      setCopiedRaw(true);
      setTimeout(() => setCopiedRaw(false), 1600);
    } catch {
      // ignore clipboard errors
    }
  };

  const handlePasteToken = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) onTokenChange(text);
    } catch {
      // ignore clipboard errors
    }
  };

  const handleResignToken = async () => {
    if (!decoded.header || !decoded.payload) return;
    const resigned = await signJwtHmac(decoded.header, decoded.payload, secret, isBase64Secret);
    onTokenChange(resigned);
  };

  // Expiration calculations
  const exp = typeof decoded.payload?.exp === 'number' ? decoded.payload.exp : undefined;
  const iat = typeof decoded.payload?.iat === 'number' ? decoded.payload.iat : undefined;
  const diffSeconds = exp !== undefined ? exp - nowSec : undefined;

  let expStatus: 'valid' | 'expiring' | 'expired' | 'none' = 'none';
  if (diffSeconds !== undefined) {
    if (diffSeconds <= 0) {
      expStatus = 'expired';
    } else if (diffSeconds <= 900) {
      expStatus = 'expiring';
    } else {
      expStatus = 'valid';
    }
  }

  const detectedRoles: string[] = [];
  if (decoded.payload) {
    if (Array.isArray(decoded.payload.roles)) {
      decoded.payload.roles.forEach((r) => {
        if (typeof r === 'string') detectedRoles.push(r);
      });
    } else if (typeof decoded.payload.role === 'string') {
      detectedRoles.push(decoded.payload.role);
    }
  }

  return (
    <div className="space-y-5">
      {/* Top Telemetry Banner: Expiration Countdown Timer + Signature Status */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Expiration Countdown Timer Card */}
        <div
          className={`lg:col-span-7 rounded-xl border px-4 py-3.5 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
            expStatus === 'expired'
              ? 'border-rose-500/40 bg-rose-950/20'
              : expStatus === 'expiring'
              ? 'border-amber-500/40 bg-amber-950/20'
              : expStatus === 'valid'
              ? 'border-emerald-500/30 bg-emerald-950/15'
              : 'border-slate-800 bg-[#111827]'
          }`}
        >
          <div className="flex items-start sm:items-center gap-3">
            <div
              className={`mt-0.5 sm:mt-0 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border ${
                expStatus === 'expired'
                  ? 'border-rose-500/40 bg-rose-500/15 text-rose-400'
                  : expStatus === 'expiring'
                  ? 'border-amber-500/40 bg-amber-500/15 text-amber-400'
                  : expStatus === 'valid'
                  ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-400'
                  : 'border-slate-700 bg-slate-800/80 text-slate-400'
              }`}
            >
              {expStatus === 'expired' ? (
                <ShieldAlert className="h-4 w-4" />
              ) : expStatus === 'expiring' ? (
                <AlertTriangle className="h-4 w-4" />
              ) : (
                <Clock className="h-4 w-4" />
              )}
            </div>

            <div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  Expiration Countdown
                </span>
                {expStatus === 'valid' && (
                  <span className="inline-flex items-center rounded-full bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-300 border border-emerald-500/30">
                    Active TTL
                  </span>
                )}
                {expStatus === 'expiring' && (
                  <span className="inline-flex items-center rounded-full bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-300 border border-amber-500/30 animate-pulse">
                    Expiring Soon
                  </span>
                )}
                {expStatus === 'expired' && (
                  <span className="inline-flex items-center rounded-full bg-rose-500/15 px-2 py-0.5 text-[11px] font-medium text-rose-300 border border-rose-500/30">
                    Expired Token
                  </span>
                )}
              </div>

              <div className="mt-0.5 font-mono text-sm sm:text-[15px] font-semibold tabular-nums">
                {!decoded.raw ? (
                  <span className="text-slate-400 font-sans font-normal text-sm">
                    Paste a JWT or load a sample token to inspect TTL
                  </span>
                ) : expStatus === 'valid' && diffSeconds !== undefined ? (
                  <span className="text-emerald-300">
                    Expires in {formatDurationBreakdown(diffSeconds)}
                  </span>
                ) : expStatus === 'expiring' && diffSeconds !== undefined ? (
                  <span className="text-amber-300">
                    Expires in {formatDurationBreakdown(diffSeconds)} (renew recommended)
                  </span>
                ) : expStatus === 'expired' && diffSeconds !== undefined ? (
                  <span className="text-rose-400">
                    Expired {formatDurationBreakdown(diffSeconds)} ago
                  </span>
                ) : (
                  <span className="text-slate-300 font-sans font-normal text-sm">
                    No <code className="text-emerald-300">exp</code> claim present in payload
                  </span>
                )}
              </div>
            </div>
          </div>

          {decoded.isValidFormat && (
            <div className="flex sm:flex-col items-end justify-between sm:justify-center text-right font-mono text-[11px] text-slate-400 border-t sm:border-t-0 border-slate-800/70 pt-2 sm:pt-0">
              {exp !== undefined && (
                <div>
                  <span className="text-slate-500">exp:</span>{' '}
                  <span className="text-slate-300 tabular-nums">{formatUnixTimestamp(exp)}</span>
                </div>
              )}
              {iat !== undefined && (
                <div>
                  <span className="text-slate-500">iat:</span>{' '}
                  <span className="text-slate-400 tabular-nums">{formatUnixTimestamp(iat)}</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Signature Status Summary Card */}
        <div
          className={`lg:col-span-5 rounded-xl border px-4 py-3.5 flex items-center justify-between gap-3 transition-colors ${
            signatureStatus === 'valid'
              ? 'border-emerald-500/30 bg-[#111827]'
              : signatureStatus === 'invalid'
              ? 'border-rose-500/40 bg-rose-950/15'
              : signatureStatus === 'unsupported'
              ? 'border-amber-500/30 bg-[#111827]'
              : 'border-slate-800 bg-[#111827]'
          }`}
        >
          <div className="flex items-center gap-3">
            <div
              className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border ${
                signatureStatus === 'valid'
                  ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-400'
                  : signatureStatus === 'invalid'
                  ? 'border-rose-500/40 bg-rose-500/15 text-rose-400'
                  : signatureStatus === 'unsupported'
                  ? 'border-amber-500/40 bg-amber-500/15 text-amber-400'
                  : 'border-slate-700 bg-slate-800/80 text-slate-400'
              }`}
            >
              {signatureStatus === 'valid' ? (
                <ShieldCheck className="h-4 w-4" />
              ) : signatureStatus === 'invalid' ? (
                <ShieldAlert className="h-4 w-4" />
              ) : (
                <Lock className="h-4 w-4" />
              )}
            </div>
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Cryptographic Signature
              </div>
              <div className="mt-0.5 text-sm font-semibold">
                {signatureStatus === 'valid' && (
                  <span className="text-emerald-400">
                    Signature Verified ({decoded.header?.alg || 'HS256'})
                  </span>
                )}
                {signatureStatus === 'invalid' && (
                  <span className="text-rose-400">Invalid Signature / Secret Mismatch</span>
                )}
                {signatureStatus === 'unsupported' && (
                  <span className="text-amber-300">
                    Asymmetric ({decoded.header?.alg}) — Structure Decoded
                  </span>
                )}
                {signatureStatus === 'verifying' && (
                  <span className="text-violet-300">Verifying HMAC digest...</span>
                )}
                {signatureStatus === 'empty' && (
                  <span className="text-slate-400 font-normal">Awaiting JWT input</span>
                )}
              </div>
            </div>
          </div>

          {detectedRoles.length > 0 && (
            <button
              type="button"
              onClick={onTestInRbac}
              className="inline-flex items-center gap-1.5 rounded-lg border border-violet-500/40 bg-violet-500/15 px-3 py-1.5 text-xs font-medium text-violet-200 hover:bg-violet-500/25 transition-colors shrink-0"
            >
              <span>Test RBAC</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Main 2-Column Inspector Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* LEFT COLUMN (5 cols): Encoded Token Input & Tri-Color Segmented Breakdown */}
        <div className="lg:col-span-5 rounded-xl border border-slate-800/90 bg-[#111827] overflow-hidden">
          <div className="border-b border-slate-800/80 px-4 py-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Encoded JWT Input</h2>
              <p className="text-xs text-slate-400">
                Accepts raw compact JWS or <code className="text-slate-300">Bearer &lt;token&gt;</code>
              </p>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={handlePasteToken}
                title="Paste from clipboard"
                className="inline-flex items-center gap-1 rounded-md border border-slate-700/80 bg-slate-800/80 px-2.5 py-1 text-xs font-medium text-slate-300 hover:border-slate-600 hover:text-white transition-colors"
              >
                <ClipboardPaste className="h-3.5 w-3.5" />
                <span>Paste</span>
              </button>
              <button
                type="button"
                onClick={handleCopyToken}
                disabled={!decoded.raw}
                title="Copy raw JWT"
                className="inline-flex items-center gap-1 rounded-md border border-slate-700/80 bg-slate-800/80 px-2.5 py-1 text-xs font-medium text-slate-300 hover:border-slate-600 hover:text-white disabled:opacity-40 transition-colors"
              >
                {copiedRaw ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    <span>Copy</span>
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={() => onTokenChange('')}
                disabled={!tokenInput}
                title="Clear token input"
                className="inline-flex items-center gap-1 rounded-md border border-slate-700/80 bg-slate-800/80 px-2 py-1 text-xs font-medium text-slate-400 hover:border-rose-500/40 hover:text-rose-300 disabled:opacity-40 transition-colors"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Preset Token Quick Switcher */}
          <div className="border-b border-slate-800/70 bg-[#0d1320]/70 px-4 py-2.5 flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-medium text-slate-400 mr-1 flex items-center gap-1">
              <Sparkles className="h-3 w-3 text-violet-400" />
              Presets:
            </span>
            <button
              type="button"
              onClick={() => onLoadPreset('admin_valid')}
              className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-300 hover:bg-emerald-500/20 transition-colors"
            >
              Admin (Valid 3h 42m)
            </button>
            <button
              type="button"
              onClick={() => onLoadPreset('moderator_expiring')}
              className="rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-300 hover:bg-amber-500/20 transition-colors"
            >
              Expiring (8m)
            </button>
            <button
              type="button"
              onClick={() => onLoadPreset('guest_expired')}
              className="rounded-md border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[11px] font-medium text-rose-300 hover:bg-rose-500/20 transition-colors"
            >
              Expired Guest
            </button>
            <button
              type="button"
              onClick={() => onLoadPreset('service_m2m')}
              className="rounded-md border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-[11px] font-medium text-cyan-300 hover:bg-cyan-500/20 transition-colors"
            >
              Service M2M
            </button>
          </div>

          <div className="p-4 space-y-4">
            {/* Raw Token Textarea */}
            <div>
              <textarea
                value={tokenInput}
                onChange={(e) => onTokenChange(e.target.value)}
                rows={5}
                spellCheck={false}
                placeholder="Paste a JWT here (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)"
                className="w-full rounded-lg border border-slate-700/80 bg-[#0d1320] p-3 font-mono text-xs leading-relaxed text-slate-200 placeholder-slate-600 focus:border-violet-500/70 focus:outline-none focus:ring-1 focus:ring-violet-500/40 resize-y"
              />
              {decoded.parseError && (
                <div className="mt-2 rounded-lg border border-rose-500/40 bg-rose-950/30 px-3 py-2 text-xs text-rose-300 flex items-start gap-2">
                  <ShieldAlert className="h-4 w-4 shrink-0 mt-0.5 text-rose-400" />
                  <span>{decoded.parseError}</span>
                </div>
              )}
            </div>

            {/* Interactive Tri-Color Segmented Breakdown */}
            {decoded.raw && (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="font-semibold uppercase tracking-wider text-slate-400">
                    Tri-Color Segment Map
                  </span>
                  <div className="flex items-center gap-3 font-mono">
                    <span className="text-cyan-400">● Header</span>
                    <span className="text-emerald-400">● Payload</span>
                    <span className="text-violet-400">● Signature</span>
                  </div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-[#0d1320] p-3 font-mono text-xs leading-relaxed break-all select-all">
                  <span
                    onMouseEnter={() => setHighlightedPart('header')}
                    onMouseLeave={() => setHighlightedPart(null)}
                    className={`cursor-pointer rounded px-0.5 transition-colors ${
                      highlightedPart === 'header'
                        ? 'bg-cyan-500/25 text-cyan-200'
                        : 'text-cyan-400 hover:bg-cyan-500/15'
                    }`}
                    title="Header (Base64URL)"
                  >
                    {decoded.headerRaw}
                  </span>
                  <span className="text-slate-500 font-bold">.</span>
                  <span
                    onMouseEnter={() => setHighlightedPart('payload')}
                    onMouseLeave={() => setHighlightedPart(null)}
                    className={`cursor-pointer rounded px-0.5 transition-colors ${
                      highlightedPart === 'payload'
                        ? 'bg-emerald-500/25 text-emerald-200'
                        : 'text-emerald-400 hover:bg-emerald-500/15'
                    }`}
                    title="Payload (Base64URL)"
                  >
                    {decoded.payloadRaw}
                  </span>
                  <span className="text-slate-500 font-bold">.</span>
                  <span
                    onMouseEnter={() => setHighlightedPart('signature')}
                    onMouseLeave={() => setHighlightedPart(null)}
                    className={`cursor-pointer rounded px-0.5 transition-colors ${
                      highlightedPart === 'signature'
                        ? 'bg-violet-500/25 text-violet-200'
                        : 'text-violet-400 hover:bg-violet-500/15'
                    }`}
                    title="Signature (Base64URL)"
                  >
                    {decoded.signatureRaw || '<empty>'}
                  </span>
                </div>

                {/* Compact Token Telemetry Footer */}
                <div className="grid grid-cols-3 gap-2 pt-1">
                  <div className="rounded-lg border border-slate-800/80 bg-[#0d1320] px-2.5 py-2">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500">Algorithm</div>
                    <div className="mt-0.5 font-mono text-xs font-semibold text-cyan-300">
                      {decoded.header?.alg || '—'}
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-800/80 bg-[#0d1320] px-2.5 py-2">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500">Token Size</div>
                    <div className="mt-0.5 font-mono text-xs font-semibold text-slate-200 tabular-nums">
                      {decoded.raw.length} chars
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-800/80 bg-[#0d1320] px-2.5 py-2">
                    <div className="text-[10px] uppercase tracking-wider text-slate-500">RBAC Roles</div>
                    <div className="mt-0.5 font-mono text-xs font-semibold text-emerald-300 truncate">
                      {detectedRoles.length > 0 ? detectedRoles.join(', ') : 'none'}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN (7 cols): Tri-Color Decoded Cards (Header, Payload, Signature) */}
        <div className="lg:col-span-7 space-y-4">
          {/* 1. HEADER CARD (Cyan) */}
          <div
            className={`rounded-xl border bg-[#111827] overflow-hidden transition-all ${
              highlightedPart === 'header'
                ? 'border-cyan-400/70 ring-1 ring-cyan-400/30'
                : 'border-slate-800/90'
            }`}
          >
            <div className="border-b border-slate-800/80 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 bg-gradient-to-r from-cyan-500/10 via-transparent to-transparent">
              <div className="flex items-center gap-2.5">
                <span className="inline-flex items-center rounded-md bg-cyan-500/20 border border-cyan-500/40 px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-cyan-300">
                  HEADER
                </span>
                <span className="text-xs font-medium text-slate-300">
                  Algorithm &amp; Token Type
                </span>
              </div>

              {decoded.header && (
                <div className="flex items-center gap-1.5 font-mono text-xs">
                  <span className="rounded bg-cyan-950/60 border border-cyan-500/30 px-2 py-0.5 text-cyan-300">
                    alg: {decoded.header.alg}
                  </span>
                  {decoded.header.typ && (
                    <span className="rounded bg-slate-800/90 border border-slate-700 px-2 py-0.5 text-slate-300">
                      typ: {decoded.header.typ}
                    </span>
                  )}
                  {decoded.header.kid && (
                    <span className="rounded bg-slate-800/90 border border-slate-700 px-2 py-0.5 text-slate-400">
                      kid: {decoded.header.kid}
                    </span>
                  )}
                </div>
              )}
            </div>

            <div className="p-4">
              <JsonViewer
                data={decoded.header}
                accentColor="cyan"
                emptyMessage="Enter a valid JWT to decode the JOSE Header."
              />
            </div>
          </div>

          {/* 2. PAYLOAD CARD (Emerald) */}
          <div
            className={`rounded-xl border bg-[#111827] overflow-hidden transition-all ${
              highlightedPart === 'payload'
                ? 'border-emerald-400/70 ring-1 ring-emerald-400/30'
                : 'border-slate-800/90'
            }`}
          >
            <div className="border-b border-slate-800/80 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 bg-gradient-to-r from-emerald-500/10 via-transparent to-transparent">
              <div className="flex items-center gap-2.5">
                <span className="inline-flex items-center rounded-md bg-emerald-500/20 border border-emerald-500/40 px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-emerald-300">
                  PAYLOAD
                </span>
                <span className="text-xs font-medium text-slate-300">
                  Claims &amp; Identity Data
                </span>
              </div>

              <div className="inline-flex rounded-lg border border-slate-800 bg-[#0d1320] p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setPayloadViewMode('json')}
                  className={`rounded-md px-2.5 py-1 font-medium transition-colors ${
                    payloadViewMode === 'json'
                      ? 'bg-emerald-500/20 text-emerald-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  JSON View
                </button>
                <button
                  type="button"
                  onClick={() => setPayloadViewMode('claims')}
                  className={`rounded-md px-2.5 py-1 font-medium transition-colors ${
                    payloadViewMode === 'claims'
                      ? 'bg-emerald-500/20 text-emerald-300'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Claims Table
                </button>
              </div>
            </div>

            <div className="p-4">
              {payloadViewMode === 'json' ? (
                <JsonViewer
                  data={decoded.payload}
                  accentColor="emerald"
                  showClaimHints
                  emptyMessage="Enter a valid JWT to decode Payload claims."
                />
              ) : decoded.payload ? (
                <div className="overflow-x-auto rounded-lg border border-slate-800/90 bg-[#0d1320]">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400">
                        <th className="py-2.5 px-3 font-semibold">Claim</th>
                        <th className="py-2.5 px-3 font-semibold">Decoded Value</th>
                        <th className="py-2.5 px-3 font-semibold hidden sm:table-cell">Specification</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-xs">
                      {Object.entries(decoded.payload).map(([key, val]) => {
                        const meta = CLAIM_DESCRIPTIONS[key];
                        const isTime =
                          (key === 'exp' || key === 'iat' || key === 'nbf') &&
                          typeof val === 'number';
                        return (
                          <tr key={key} className="hover:bg-slate-800/30">
                            <td className="py-2.5 px-3 font-mono font-semibold text-emerald-300 align-top">
                              <div>{key}</div>
                              {meta && (
                                <div className="font-sans text-[11px] font-normal text-slate-400">
                                  {meta.label}
                                </div>
                              )}
                            </td>
                            <td className="py-2.5 px-3 font-mono text-slate-200 align-top break-all">
                              <div>
                                {Array.isArray(val)
                                  ? val.join(', ')
                                  : typeof val === 'object' && val !== null
                                  ? JSON.stringify(val)
                                  : String(val)}
                              </div>
                              {isTime && (
                                <div className="mt-0.5 text-[11px] text-slate-400">
                                  {formatUnixTimestamp(val as number)}
                                </div>
                              )}
                            </td>
                            <td className="py-2.5 px-3 text-slate-400 align-top hidden sm:table-cell">
                              {meta ? (
                                <div>
                                  <span className="inline-block rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">
                                    {meta.spec}
                                  </span>
                                  <p className="mt-1 text-[11px] leading-snug text-slate-400">
                                    {meta.description}
                                  </p>
                                </div>
                              ) : (
                                <span className="text-[11px] text-slate-500">Application claim</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="rounded-lg border border-slate-800/80 bg-[#0d1320] p-4 font-mono text-xs text-slate-500">
                  Enter a valid JWT to inspect individual claims.
                </div>
              )}
            </div>
          </div>

          {/* 3. SIGNATURE VERIFICATION CARD (Cyber Violet) */}
          <div
            className={`rounded-xl border bg-[#111827] overflow-hidden transition-all ${
              highlightedPart === 'signature'
                ? 'border-violet-400/70 ring-1 ring-violet-400/30'
                : 'border-slate-800/90'
            }`}
          >
            <div className="border-b border-slate-800/80 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 bg-gradient-to-r from-violet-500/15 via-transparent to-transparent">
              <div className="flex items-center gap-2.5">
                <span className="inline-flex items-center rounded-md bg-violet-500/20 border border-violet-500/40 px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider text-violet-300">
                  VERIFY SIGNATURE
                </span>
                <span className="text-xs font-medium text-slate-300">
                  HMAC Secret Key Check
                </span>
              </div>

              {signatureStatus === 'valid' && (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/40 px-2.5 py-0.5 text-xs font-semibold text-emerald-300">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Signature Verified
                </span>
              )}
              {signatureStatus === 'invalid' && (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-rose-500/15 border border-rose-500/40 px-2.5 py-0.5 text-xs font-semibold text-rose-300">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  Invalid Signature
                </span>
              )}
            </div>

            <div className="p-4 space-y-3.5">
              {/* HMAC Signing Formula */}
              <div className="rounded-lg border border-slate-800/90 bg-[#0d1320] px-3.5 py-2.5 font-mono text-xs text-slate-300 overflow-x-auto">
                <span className="text-violet-400">
                  HMAC{decoded.header?.alg?.replace('HS', 'SHA') || 'SHA256'}
                </span>
                <span className="text-slate-500">(</span>
                <span className="text-cyan-300">base64UrlEncode(header)</span>
                <span className="text-slate-500"> + "." + </span>
                <span className="text-emerald-300">base64UrlEncode(payload)</span>
                <span className="text-slate-500">, </span>
                <span className="text-amber-300">secret</span>
                <span className="text-slate-500">)</span>
              </div>

              {/* Secret Key Input Row */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="jwt-hmac-secret"
                    className="text-xs font-medium text-slate-300 flex items-center gap-1.5"
                  >
                    <KeyRound className="h-3.5 w-3.5 text-violet-400" />
                    <span>HMAC Signing Secret</span>
                  </label>
                  <div className="flex items-center gap-3">
                    <label className="inline-flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={isBase64Secret}
                        onChange={(e) => onBase64SecretChange(e.target.checked)}
                        className="rounded border-slate-700 bg-slate-900 text-violet-500 focus:ring-violet-500/40"
                      />
                      <span>secret base64 encoded</span>
                    </label>
                    {secret !== DEFAULT_HMAC_SECRET && (
                      <button
                        type="button"
                        onClick={() => onSecretChange(DEFAULT_HMAC_SECRET)}
                        className="text-[11px] font-medium text-violet-400 hover:text-violet-300 transition-colors"
                      >
                        Reset default
                      </button>
                    )}
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row gap-2">
                  <div className="relative flex-1">
                    <input
                      id="jwt-hmac-secret"
                      type={showSecret ? 'text' : 'password'}
                      value={secret}
                      onChange={(e) => onSecretChange(e.target.value)}
                      placeholder="Enter HMAC secret key..."
                      className="w-full rounded-lg border border-slate-700/80 bg-[#0d1320] py-2 pl-3 pr-9 font-mono text-xs text-slate-100 placeholder-slate-600 focus:border-violet-500/70 focus:outline-none focus:ring-1 focus:ring-violet-500/40"
                    />
                    <button
                      type="button"
                      onClick={() => setShowSecret(!showSecret)}
                      title={showSecret ? 'Hide secret' : 'Show secret'}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                    >
                      {showSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </button>
                  </div>

                  {decoded.isValidFormat && signatureStatus === 'invalid' && (
                    <button
                      type="button"
                      onClick={handleResignToken}
                      className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-violet-500/40 bg-violet-500/15 px-3 py-2 text-xs font-medium text-violet-200 hover:bg-violet-500/25 transition-colors shrink-0"
                    >
                      <RefreshCw className="h-3.5 w-3.5" />
                      <span>Re-sign with Secret</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
