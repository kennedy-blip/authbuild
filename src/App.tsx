import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  GitBranch,
  KeyRound,
  Lock,
  Shield,
  ShieldCheck,
  Sparkles,
  Trash2,
  Wand2,
} from 'lucide-react';
import { JwtInspector } from './components/JwtInspector';
import { OAuthSimulator } from './components/OAuthSimulator';
import { RbacDebugger } from './components/RbacDebugger';
import { TokenGenerator } from './components/TokenGenerator';
import { NavTab, SamplePresetId, SignatureStatus } from './types/auth';
import {
  createSampleToken,
  decodeJwt,
  DEFAULT_HMAC_SECRET,
  verifyJwtHmac,
} from './utils/jwtCrypto';

export function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('inspector');
  const [tokenInput, setTokenInput] = useState<string>('');
  const [secret, setSecret] = useState<string>(DEFAULT_HMAC_SECRET);
  const [isBase64Secret, setIsBase64Secret] = useState<boolean>(false);
  const [signatureStatus, setSignatureStatus] = useState<SignatureStatus>('empty');
  const [sessionResetKey, setSessionResetKey] = useState<number>(0);
  const [statusToast, setStatusToast] = useState<string | null>(null);

  const showToast = useCallback((msg: string) => {
    setStatusToast(msg);
  }, []);

  useEffect(() => {
    if (!statusToast) return;
    const t = setTimeout(() => setStatusToast(null), 2400);
    return () => clearTimeout(t);
  }, [statusToast]);

  // Initialize with a live signed sample token on startup
  useEffect(() => {
    let mounted = true;
    createSampleToken('admin_valid', DEFAULT_HMAC_SECRET).then((sample) => {
      if (mounted) {
        setTokenInput(sample);
      }
    });
    return () => {
      mounted = false;
    };
  }, []);

  const decoded = useMemo(() => decodeJwt(tokenInput), [tokenInput]);

  // Verify HMAC signature asynchronously using Web Crypto API whenever token or secret changes
  useEffect(() => {
    let cancelled = false;
    if (!decoded.raw) {
      setSignatureStatus('empty');
      return;
    }
    setSignatureStatus('verifying');
    verifyJwtHmac(decoded.raw, secret, isBase64Secret).then((status) => {
      if (!cancelled) {
        setSignatureStatus(status);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [decoded.raw, secret, isBase64Secret]);

  const handleLoadPreset = async (preset: SamplePresetId) => {
    const activeSecret = secret || DEFAULT_HMAC_SECRET;
    if (!secret) setSecret(DEFAULT_HMAC_SECRET);
    const sample = await createSampleToken(preset, activeSecret);
    setTokenInput(sample);
    const labelMap: Record<SamplePresetId, string> = {
      admin_valid: 'Loaded Active Admin JWT (3h 42m TTL)',
      moderator_expiring: 'Loaded Expiring Moderator JWT (8m TTL)',
      guest_expired: 'Loaded Expired Guest JWT',
      service_m2m: 'Loaded Service Account M2M JWT (HS512)',
    };
    showToast(labelMap[preset]);
  };

  const handleQuickLoadSample = async () => {
    await handleLoadPreset('admin_valid');
    if (activeTab === 'generator') {
      setActiveTab('inspector');
    }
  };

  const handleClearAllSessions = () => {
    setTokenInput('');
    setSignatureStatus('empty');
    setSessionResetKey((prev) => prev + 1);
    showToast('All active token & flow sessions cleared');
  };

  const handleInspectMintedToken = (mintedJwt: string) => {
    setTokenInput(mintedJwt);
    setActiveTab('inspector');
    showToast('Minted OAuth2 token loaded into JWT Inspector');
  };

  const handleUseGeneratedToken = (generatedJwt: string, signingSecret: string) => {
    setSecret(signingSecret);
    setTokenInput(generatedJwt);
    setActiveTab('inspector');
    showToast('Custom signed token loaded into JWT Inspector');
  };

  const navItems: { id: NavTab; label: string; icon: React.ReactNode; badge?: string }[] = [
    {
      id: 'inspector',
      label: 'JWT Inspector',
      icon: <KeyRound className="h-4 w-4" />,
      badge: decoded.header?.alg,
    },
    {
      id: 'oauth',
      label: 'OAuth2 Simulator',
      icon: <GitBranch className="h-4 w-4" />,
      badge: 'PKCE',
    },
    {
      id: 'rbac',
      label: 'RBAC Matrix',
      icon: <Shield className="h-4 w-4" />,
    },
    {
      id: 'generator',
      label: 'Token Generator',
      icon: <Wand2 className="h-4 w-4" />,
    },
  ];

  return (
    <div className="min-h-screen bg-[#080c14] bg-auth-grid text-slate-100 flex flex-col">
      {/* Top Header & Navigation Bar */}
      <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-[#080c14]/90 backdrop-blur-md">
        <div className="mx-auto max-w-7xl px-4 sm:px-6">
          {/* Primary Header Row */}
          <div className="flex flex-wrap items-center justify-between gap-3 py-3.5">
            {/* Brand Logo + Live Status Badge */}
            <div className="flex items-center gap-3.5">
              <div className="relative flex h-10 w-10 items-center justify-center rounded-xl border border-violet-500/40 bg-gradient-to-br from-violet-600/30 via-violet-950/60 to-cyan-500/20 shadow-[0_0_24px_-4px_rgba(139,92,246,0.55)]">
                <ShieldCheck className="h-5 w-5 text-violet-300" />
                <Lock className="h-2.5 w-2.5 text-cyan-300 absolute bottom-1.5 right-1.5" />
              </div>

              <div>
                <div className="flex items-center gap-2.5">
                  <h1 className="text-base sm:text-lg font-bold tracking-tight text-white">
                    AuthPulse
                  </h1>
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/35 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-medium text-emerald-300">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    Auth Engine: Active
                  </span>
                </div>
                <p className="hidden sm:block text-xs text-slate-400">
                  JWT Token Inspector, OAuth2/OIDC Flow Simulator &amp; RBAC Permissions Debugger
                </p>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="flex items-center gap-2">
              {statusToast && (
                <span className="hidden xl:inline-flex items-center gap-1.5 rounded-lg border border-violet-500/30 bg-violet-500/10 px-2.5 py-1 text-xs text-violet-200">
                  <Activity className="h-3.5 w-3.5 text-violet-400" />
                  {statusToast}
                </span>
              )}

              <button
                type="button"
                onClick={handleQuickLoadSample}
                className="inline-flex items-center gap-1.5 rounded-lg border border-violet-500/40 bg-violet-500/15 hover:bg-violet-500/25 px-3 py-1.5 text-xs font-semibold text-violet-200 transition-colors"
              >
                <Sparkles className="h-3.5 w-3.5 text-violet-300" />
                <span>Load Sample Token</span>
              </button>

              <button
                type="button"
                onClick={handleClearAllSessions}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-[#111827] hover:border-rose-500/40 hover:text-rose-300 px-3 py-1.5 text-xs font-medium text-slate-300 transition-colors"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>Clear All Sessions</span>
              </button>
            </div>
          </div>

          {/* Navigation Tabs Row */}
          <nav
            aria-label="Workspace Views"
            className="flex items-center gap-1 overflow-x-auto pb-px -mb-px"
          >
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActiveTab(item.id)}
                  className={`group inline-flex items-center gap-2 border-b-2 px-3.5 py-2.5 text-xs sm:text-sm font-medium whitespace-nowrap transition-all ${
                    isActive
                      ? 'border-violet-500 text-white'
                      : 'border-transparent text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}
                >
                  <span
                    className={
                      isActive
                        ? 'text-violet-400'
                        : 'text-slate-500 group-hover:text-slate-300'
                    }
                  >
                    {item.icon}
                  </span>
                  <span>{item.label}</span>
                  {item.badge && (
                    <span
                      className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
                        isActive
                          ? 'bg-violet-500/20 text-violet-300 border border-violet-500/30'
                          : 'bg-slate-800/90 text-slate-400'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      {/* Main Content Workspace */}
      <main className="flex-1 mx-auto w-full max-w-7xl px-4 sm:px-6 py-6">
        {activeTab === 'inspector' && (
          <JwtInspector
            tokenInput={tokenInput}
            onTokenChange={setTokenInput}
            decoded={decoded}
            secret={secret}
            onSecretChange={setSecret}
            isBase64Secret={isBase64Secret}
            onBase64SecretChange={setIsBase64Secret}
            signatureStatus={signatureStatus}
            onLoadPreset={handleLoadPreset}
            onTestInRbac={() => setActiveTab('rbac')}
          />
        )}

        {activeTab === 'oauth' && (
          <OAuthSimulator
            secret={secret}
            sessionResetKey={sessionResetKey}
            onInspectMintedToken={handleInspectMintedToken}
          />
        )}

        {activeTab === 'rbac' && (
          <RbacDebugger decodedJwt={decoded} sessionResetKey={sessionResetKey} />
        )}

        {activeTab === 'generator' && (
          <TokenGenerator
            sharedSecret={secret}
            onUseTokenInInspector={handleUseGeneratedToken}
          />
        )}
      </main>

      {/* Minimal Security Telemetry Footer */}
      <footer className="border-t border-slate-800/70 bg-[#080c14]/90 py-3 px-4 sm:px-6">
        <div className="mx-auto max-w-7xl flex flex-col sm:flex-row items-center justify-between gap-2 text-[11px] text-slate-500">
          <div className="flex items-center gap-2 font-mono">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500/80" />
            <span>
              Zero-Trust Local Execution: All JWT decoding, HMAC-SHA signing, and PKCE SHA-256 hashing run locally via Web Crypto API.
            </span>
          </div>
          <div className="font-mono text-slate-500">
            RFC 7519 · RFC 7636 · RFC 6749
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
