import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Globe,
  KeyRound,
  Play,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldCheck,
  Sparkles,
  StepForward,
} from 'lucide-react';
import { OAuthActor, OAuthFlowType, OAuthStep } from '../types/auth';
import {
  DEFAULT_HMAC_SECRET,
  generateCodeChallengeS256,
  generateCodeVerifier,
  signJwtHmac,
} from '../utils/jwtCrypto';
import { JsonViewer } from './JsonViewer';

interface OAuthSimulatorProps {
  secret: string;
  sessionResetKey: number;
  onInspectMintedToken: (token: string) => void;
}

const ACTOR_META: Record<
  OAuthActor,
  { label: string; sublabel: string; colorClass: string; badgeClass: string; icon: React.ReactNode }
> = {
  user_agent: {
    label: 'User Agent / Client',
    sublabel: 'Browser SPA / Backend Client',
    colorClass: 'text-cyan-300 border-cyan-500/40 bg-cyan-500/10',
    badgeClass: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
    icon: <Globe className="h-4 w-4 text-cyan-400" />,
  },
  auth_server: {
    label: 'Authorization Server',
    sublabel: 'auth.authpulse.dev',
    colorClass: 'text-violet-300 border-violet-500/40 bg-violet-500/10',
    badgeClass: 'bg-violet-500/20 text-violet-300 border-violet-500/40',
    icon: <ShieldCheck className="h-4 w-4 text-violet-400" />,
  },
  resource_server: {
    label: 'Resource Server',
    sublabel: 'api.authpulse.dev/v1',
    colorClass: 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10',
    badgeClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
    icon: <Server className="h-4 w-4 text-emerald-400" />,
  },
};

export const OAuthSimulator: React.FC<OAuthSimulatorProps> = ({
  secret,
  sessionResetKey,
  onInspectMintedToken,
}) => {
  const [flowType, setFlowType] = useState<OAuthFlowType>('pkce');
  const [clientId, setClientId] = useState<string>('ap_web_console_prod');
  const [scopes, setScopes] = useState<string>('openid profile email users:read');
  const [codeVerifier, setCodeVerifier] = useState<string>(() => generateCodeVerifier());
  const [codeChallenge, setCodeChallenge] = useState<string>('');
  const [authCode, setAuthCode] = useState<string>('ac_99f18c42b0e7a11d');
  const [stateNonce, setStateNonce] = useState<string>('st_74e91a02c5');

  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [selectedStepIndex, setSelectedStepIndex] = useState<number>(0);
  const [isAutoPlaying, setIsAutoPlaying] = useState<boolean>(false);
  const [mintedToken, setMintedToken] = useState<string>('');

  // Compute SHA-256 PKCE code_challenge whenever codeVerifier changes
  useEffect(() => {
    let active = true;
    generateCodeChallengeS256(codeVerifier).then((challenge) => {
      if (active) setCodeChallenge(challenge);
    });
    return () => {
      active = false;
    };
  }, [codeVerifier]);

  // Reset simulation when global Clear All Sessions is triggered
  useEffect(() => {
    if (sessionResetKey > 0) {
      setCurrentStepIndex(0);
      setSelectedStepIndex(0);
      setIsAutoPlaying(false);
      setMintedToken('');
    }
  }, [sessionResetKey]);

  const handleRegeneratePkce = () => {
    const newVerifier = generateCodeVerifier();
    setCodeVerifier(newVerifier);
    setAuthCode(`ac_${Math.random().toString(36).substring(2, 14)}`);
    setStateNonce(`st_${Math.random().toString(36).substring(2, 10)}`);
  };

  // Switch sensible defaults when flow changes
  const handleSelectFlow = (newFlow: OAuthFlowType) => {
    setFlowType(newFlow);
    setCurrentStepIndex(0);
    setSelectedStepIndex(0);
    setIsAutoPlaying(false);
    setMintedToken('');
    if (newFlow === 'client_credentials') {
      setClientId('svc_billing_worker_09');
      setScopes('billing:sync webhooks:ingest users:read');
    } else if (newFlow === 'pkce') {
      setClientId('ap_web_console_prod');
      setScopes('openid profile email users:read');
    } else {
      setClientId('ap_legacy_spa_v1');
      setScopes('openid profile users:read');
    }
  };

  // Build steps dynamically based on selected flow
  const steps = useMemo<OAuthStep[]>(() => {
    const displayToken = mintedToken || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...<signed_jwt>';

    if (flowType === 'pkce') {
      const pkceSteps: OAuthStep[] = [
        {
          id: 'pkce-1',
          stepNumber: 1,
          title: 'Generate PKCE Verifier & Redirect to /authorize',
          subtitle: 'Client creates S256 challenge & initiates OIDC login',
          from: 'user_agent',
          to: 'auth_server',
          method: 'GET',
          endpoint: '/oauth2/authorize',
          description:
            'The client generates a high-entropy random code_verifier, hashes it with SHA-256 to derive code_challenge, and redirects the browser to the Authorization Server.',
          requestParams: {
            response_type: 'code',
            client_id: clientId,
            redirect_uri: 'https://console.authpulse.dev/callback',
            scope: scopes,
            state: stateNonce,
            code_challenge: codeChallenge || 'computing...',
            code_challenge_method: 'S256',
          },
          responseStatus: '200 OK (Login & Consent UI)',
          responseBody: {
            session_id: 'sess_8812ab90ef',
            prompt: 'consent',
            pkce_enforced: true,
            challenge_stored: codeChallenge || 'computing...',
          },
          securityNote:
            'PKCE (RFC 7636) binds the authorization request to the token exchange without embedding a client_secret in public browser code.',
        },
        {
          id: 'pkce-2',
          stepNumber: 2,
          title: 'Authorization Code Redirect Callback',
          subtitle: 'Auth Server returns single-use authorization code',
          from: 'auth_server',
          to: 'user_agent',
          method: '302',
          endpoint: '/callback?code=...&state=...',
          description:
            'After user authentication and MFA verification, the Authorization Server redirects back to redirect_uri with a short-lived single-use authorization code and matching state.',
          requestParams: {
            location: `https://console.authpulse.dev/callback?code=${authCode}&state=${stateNonce}`,
          },
          responseStatus: '302 Found',
          responseBody: {
            code: authCode,
            state: stateNonce,
            expires_in_seconds: 60,
            single_use: true,
          },
          securityNote:
            'The client validates that the returned state matches its local CSRF nonce before exchanging the code.',
        },
        {
          id: 'pkce-3',
          stepNumber: 3,
          title: 'Token Exchange + PKCE SHA-256 Verification',
          subtitle: 'Client sends code + raw code_verifier to /oauth/token',
          from: 'user_agent',
          to: 'auth_server',
          method: 'POST',
          endpoint: '/oauth2/token',
          description:
            'The client exchanges the authorization code along with the original plaintext code_verifier. The Authorization Server computes SHA256(code_verifier) and verifies it matches the stored code_challenge.',
          requestHeaders: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          requestBody: {
            grant_type: 'authorization_code',
            client_id: clientId,
            code: authCode,
            redirect_uri: 'https://console.authpulse.dev/callback',
            code_verifier: codeVerifier,
          },
          responseStatus: '200 OK (Tokens Minted)',
          responseBody: {
            token_type: 'Bearer',
            expires_in: 3600,
            scope: scopes,
            pkce_verification: 'SHA256(code_verifier) === code_challenge (MATCH)',
            access_token: displayToken,
          },
          securityNote:
            'Even if an attacker intercepts the authorization code on the redirect URI, they cannot redeem it without the secret code_verifier.',
        },
        {
          id: 'pkce-4',
          stepNumber: 4,
          title: 'Authenticated API Request to Resource Server',
          subtitle: 'Bearer JWT validated via signature & claims',
          from: 'user_agent',
          to: 'resource_server',
          method: 'GET',
          endpoint: '/api/v1/users',
          description:
            'The client attaches the minted JWT in the Authorization: Bearer header. The Resource Server verifies the cryptographic signature, exp claim, aud, and RBAC scopes.',
          requestHeaders: {
            Authorization: `Bearer ${displayToken}`,
            Accept: 'application/json',
          },
          responseStatus: '200 OK',
          responseBody: {
            authenticated: true,
            subject: 'usr_849201_elena',
            roles: ['admin', 'moderator'],
            granted_scopes: scopes.split(' '),
            data: [
              { id: 'usr_849201_elena', email: 'elena.vance@authpulse.dev', role: 'admin' },
              { id: 'usr_302914_marcus', email: 'm.chen@authpulse.dev', role: 'moderator' },
            ],
          },
          securityNote:
            'Stateless JWT validation allows the Resource Server to authorize requests in <1ms without round-tripping to the Authorization Server.',
        },
      ];
      return pkceSteps;
    }

    if (flowType === 'client_credentials') {
      const ccSteps: OAuthStep[] = [
        {
          id: 'cc-1',
          stepNumber: 1,
          title: 'Authenticate Confidential Client Credentials',
          subtitle: 'Backend service authenticates directly with client_id & secret',
          from: 'user_agent',
          to: 'auth_server',
          method: 'POST',
          endpoint: '/oauth2/token',
          description:
            'In Machine-to-Machine (M2M) communication, there is no end-user browser redirect. The backend daemon authenticates directly to /oauth2/token using its client credentials.',
          requestHeaders: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${btoa(`${clientId}:ap_sec_live_9821f0a4`)}`,
          },
          requestBody: {
            grant_type: 'client_credentials',
            client_id: clientId,
            scope: scopes,
            audience: 'https://api.authpulse.dev/v1',
          },
          responseStatus: '200 OK',
          responseBody: {
            client_authenticated: true,
            grant_type: 'client_credentials',
            assigned_role: 'service_account',
          },
          securityNote:
            'Client Credentials must ONLY be used by confidential backend services capable of securely storing client_secret.',
        },
        {
          id: 'cc-2',
          stepNumber: 2,
          title: 'Issue M2M Service Account Access Token',
          subtitle: 'Auth Server mints scoped service_account JWT',
          from: 'auth_server',
          to: 'user_agent',
          method: '200',
          endpoint: '/oauth2/token (Response)',
          description:
            'The Authorization Server verifies the client secret and returns a signed JWT containing sub = client_id, roles = ["service_account"], and requested M2M scopes. No refresh_token is issued.',
          responseStatus: '200 OK (M2M JWT Issued)',
          responseBody: {
            token_type: 'Bearer',
            expires_in: 86400,
            scope: scopes,
            access_token: displayToken,
          },
          securityNote:
            'Per RFC 6749 §4.4.3, refresh tokens should NOT be issued in Client Credentials grants; the service simply re-authenticates when the JWT expires.',
        },
        {
          id: 'cc-3',
          stepNumber: 3,
          title: 'Invoke Protected Microservice Endpoint',
          subtitle: 'Service worker calls internal ingestion API with Bearer JWT',
          from: 'user_agent',
          to: 'resource_server',
          method: 'POST',
          endpoint: '/api/v1/webhooks/ingest',
          description:
            'The worker service calls the Resource Server API with the M2M Bearer JWT. The API gateway checks roles: ["service_account"] and scope "webhooks:ingest".',
          requestHeaders: {
            Authorization: `Bearer ${displayToken}`,
            'Content-Type': 'application/json',
          },
          requestBody: {
            event: 'invoice.settled',
            batch_id: 'bat_20250512_04',
            records: 128,
          },
          responseStatus: '200 OK (Accepted)',
          responseBody: {
            status: 'ingested',
            actor_type: 'service_account',
            client_id: clientId,
            processed_records: 128,
          },
          securityNote:
            'Separate M2M tokens with narrow service_account roles limit blast radius if a single worker node is compromised.',
        },
      ];
      return ccSteps;
    }

    // Implicit Flow (Legacy)
    const implicitSteps: OAuthStep[] = [
      {
        id: 'imp-1',
        stepNumber: 1,
        title: 'Redirect to /authorize with response_type=token',
        subtitle: 'Legacy browser flow requests token directly in URL fragment',
        from: 'user_agent',
        to: 'auth_server',
        method: 'GET',
        endpoint: '/oauth2/authorize',
        description:
          'The legacy SPA redirects the browser to /oauth2/authorize requesting response_type=token id_token directly without an intermediate authorization code.',
        requestParams: {
          response_type: 'token id_token',
          client_id: clientId,
          redirect_uri: 'https://legacy.authpulse.dev/callback',
          scope: scopes,
          nonce: 'n_819204ab',
          state: stateNonce,
        },
        responseStatus: '200 OK (User Login)',
        responseBody: {
          warning: 'DEPRECATED_FLOW',
          recommendation: 'Migrate to Authorization Code + PKCE (OAuth 2.1)',
        },
        securityNote:
          'OAuth 2.1 deprecates the Implicit Flow because returning access tokens in URL fragments exposes them to browser history, Referer headers, and XSS.',
      },
      {
        id: 'imp-2',
        stepNumber: 2,
        title: 'Token Returned Directly in URI Fragment (#access_token=...)',
        subtitle: 'Auth Server redirects with raw JWT exposed in URL hash',
        from: 'auth_server',
        to: 'user_agent',
        method: '302',
        endpoint: '/callback#access_token=...',
        description:
          'The Authorization Server appends the signed access_token directly to the URL hash fragment (#) rather than exchanging a code over a back-channel POST.',
        requestParams: {
          location: `https://legacy.authpulse.dev/callback#access_token=${displayToken.slice(0, 36)}...&token_type=Bearer&expires_in=900`,
        },
        responseStatus: '302 Found (Fragment Exposure)',
        responseBody: {
          token_type: 'Bearer',
          expires_in: 900,
          refresh_token: null,
          access_token: displayToken,
        },
        securityNote:
          'Implicit flow cannot issue refresh tokens and offers no sender-constraining proof like PKCE code_verifier.',
      },
      {
        id: 'imp-3',
        stepNumber: 3,
        title: 'Resource Server API Call',
        subtitle: 'Browser attaches fragment-extracted JWT to API call',
        from: 'user_agent',
        to: 'resource_server',
        method: 'GET',
        endpoint: '/api/v1/profile',
        description:
          'The SPA parses window.location.hash to extract the access_token and sends it to the Resource Server.',
        requestHeaders: {
          Authorization: `Bearer ${displayToken}`,
        },
        responseStatus: '200 OK',
        responseBody: {
          sub: 'usr_552019_legacy',
          roles: ['guest'],
          flow_warning: 'Short TTL (15m) enforced due to Implicit grant risk profile',
        },
        securityNote:
          'Always prefer Authorization Code + PKCE even for pure client-side SPAs.',
      },
    ];
    return implicitSteps;
  }, [flowType, clientId, scopes, codeChallenge, codeVerifier, authCode, stateNonce, mintedToken]);

  // Mint a real signed JWT when reaching the token step
  const tokenIssuanceStepIndex = flowType === 'pkce' ? 2 : 1;

  useEffect(() => {
    if (currentStepIndex >= tokenIssuanceStepIndex) {
      const now = Math.floor(Date.now() / 1000);
      const signingKey = secret || DEFAULT_HMAC_SECRET;

      if (flowType === 'pkce') {
        signJwtHmac(
          { alg: 'HS256', typ: 'JWT', kid: 'ap-oidc-2025' },
          {
            sub: 'usr_849201_elena',
            name: 'Elena Vance',
            email: 'elena.vance@authpulse.dev',
            iss: 'https://auth.authpulse.dev/',
            aud: 'https://api.authpulse.dev/v1',
            azp: clientId,
            iat: now,
            exp: now + 3600,
            auth_time: now,
            amr: ['pwd', 'mfa'],
            jti: `tok_pkce_${now.toString(36)}`,
            roles: ['admin', 'moderator'],
            scope: scopes,
            pkce_method: 'S256',
          },
          signingKey
        ).then(setMintedToken);
      } else if (flowType === 'client_credentials') {
        signJwtHmac(
          { alg: 'HS256', typ: 'JWT', kid: 'ap-m2m-2025' },
          {
            sub: `${clientId}@clients.authpulse.dev`,
            iss: 'https://auth.authpulse.dev/',
            aud: 'https://api.authpulse.dev/v1',
            iat: now,
            exp: now + 86400,
            jti: `tok_m2m_${now.toString(36)}`,
            grant_type: 'client_credentials',
            client_id: clientId,
            roles: ['service_account'],
            scope: scopes,
          },
          signingKey
        ).then(setMintedToken);
      } else {
        signJwtHmac(
          { alg: 'HS256', typ: 'JWT', kid: 'ap-legacy-2025' },
          {
            sub: 'usr_552019_legacy',
            name: 'Legacy SPA Session',
            iss: 'https://auth.authpulse.dev/',
            aud: 'https://api.authpulse.dev/v1',
            azp: clientId,
            iat: now,
            exp: now + 900,
            jti: `tok_imp_${now.toString(36)}`,
            grant_type: 'implicit',
            roles: ['guest'],
            scope: scopes,
          },
          signingKey
        ).then(setMintedToken);
      }
    }
  }, [currentStepIndex, tokenIssuanceStepIndex, flowType, clientId, scopes, secret]);

  // Auto-play timer
  useEffect(() => {
    if (!isAutoPlaying) return;
    if (currentStepIndex >= steps.length - 1) {
      setIsAutoPlaying(false);
      return;
    }
    const timer = setTimeout(() => {
      const next = currentStepIndex + 1;
      setCurrentStepIndex(next);
      setSelectedStepIndex(next);
    }, 850);
    return () => clearTimeout(timer);
  }, [isAutoPlaying, currentStepIndex, steps.length]);

  const handleRunFullFlow = () => {
    setCurrentStepIndex(0);
    setSelectedStepIndex(0);
    setIsAutoPlaying(true);
  };

  const handleStepForward = () => {
    setIsAutoPlaying(false);
    if (currentStepIndex < steps.length - 1) {
      const next = currentStepIndex + 1;
      setCurrentStepIndex(next);
      setSelectedStepIndex(next);
    }
  };

  const handleReset = () => {
    setIsAutoPlaying(false);
    setCurrentStepIndex(0);
    setSelectedStepIndex(0);
    setMintedToken('');
  };

  const activeStep = steps[selectedStepIndex] || steps[0];

  const getLaneColumnIndex = (actor: OAuthActor): number => {
    if (actor === 'user_agent') return 0;
    if (actor === 'auth_server') return 1;
    return 2;
  };

  return (
    <div className="space-y-5">
      {/* Top Flow Selector & Playback Controls */}
      <div className="rounded-xl border border-slate-800/90 bg-[#111827] p-4 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Flow Type Tabs */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 flex-1">
            <button
              type="button"
              onClick={() => handleSelectFlow('pkce')}
              className={`text-left rounded-lg border px-3.5 py-2.5 transition-all ${
                flowType === 'pkce'
                  ? 'border-violet-500/60 bg-violet-500/15 shadow-sm shadow-violet-500/10'
                  : 'border-slate-800 bg-[#0d1320] hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-100">
                  Authorization Code + PKCE
                </span>
                <span className="rounded bg-emerald-500/15 border border-emerald-500/30 px-1.5 py-0.5 font-mono text-[10px] text-emerald-300">
                  RFC 7636
                </span>
              </div>
              <p className="mt-0.5 text-[11px] text-slate-400">
                OIDC + SHA-256 code challenge for SPAs &amp; Apps
              </p>
            </button>

            <button
              type="button"
              onClick={() => handleSelectFlow('client_credentials')}
              className={`text-left rounded-lg border px-3.5 py-2.5 transition-all ${
                flowType === 'client_credentials'
                  ? 'border-violet-500/60 bg-violet-500/15 shadow-sm shadow-violet-500/10'
                  : 'border-slate-800 bg-[#0d1320] hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-100">Client Credentials</span>
                <span className="rounded bg-cyan-500/15 border border-cyan-500/30 px-1.5 py-0.5 font-mono text-[10px] text-cyan-300">
                  M2M
                </span>
              </div>
              <p className="mt-0.5 text-[11px] text-slate-400">
                Direct service-to-service daemon authentication
              </p>
            </button>

            <button
              type="button"
              onClick={() => handleSelectFlow('implicit')}
              className={`text-left rounded-lg border px-3.5 py-2.5 transition-all ${
                flowType === 'implicit'
                  ? 'border-amber-500/60 bg-amber-500/10 shadow-sm shadow-amber-500/10'
                  : 'border-slate-800 bg-[#0d1320] hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-100">Implicit Flow</span>
                <span className="rounded bg-amber-500/15 border border-amber-500/30 px-1.5 py-0.5 font-mono text-[10px] text-amber-300">
                  Legacy
                </span>
              </div>
              <p className="mt-0.5 text-[11px] text-slate-400">
                Direct fragment token return (OAuth 2.1 deprecated)
              </p>
            </button>
          </div>

          {/* Simulation Playback Buttons */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={handleRunFullFlow}
              className="inline-flex items-center gap-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 px-3.5 py-2 text-xs font-semibold text-white shadow-sm shadow-violet-600/30 transition-colors"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>{isAutoPlaying ? 'Simulating...' : 'Simulate Full Flow'}</span>
            </button>

            <button
              type="button"
              onClick={handleStepForward}
              disabled={currentStepIndex >= steps.length - 1}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/90 hover:bg-slate-800 px-3 py-2 text-xs font-medium text-slate-200 disabled:opacity-40 transition-colors"
            >
              <StepForward className="h-3.5 w-3.5" />
              <span>Next Step</span>
            </button>

            <button
              type="button"
              onClick={handleReset}
              title="Reset sequence"
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700/80 bg-[#0d1320] hover:border-slate-600 px-2.5 py-2 text-xs font-medium text-slate-300 transition-colors"
            >
              <RotateCcw className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        {/* Client Configuration & Live PKCE Cryptography Bar */}
        <div className="border-t border-slate-800/80 pt-3.5 grid grid-cols-1 md:grid-cols-12 gap-3">
          <div className="md:col-span-3">
            <label className="block text-[11px] font-medium uppercase tracking-wider text-slate-400 mb-1">
              client_id
            </label>
            <input
              type="text"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-[#0d1320] px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:border-violet-500/60 focus:outline-none"
            />
          </div>

          <div className="md:col-span-4">
            <label className="block text-[11px] font-medium uppercase tracking-wider text-slate-400 mb-1">
              scope
            </label>
            <input
              type="text"
              value={scopes}
              onChange={(e) => setScopes(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-[#0d1320] px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:border-violet-500/60 focus:outline-none"
            />
          </div>

          {flowType === 'pkce' ? (
            <div className="md:col-span-5 rounded-lg border border-violet-500/30 bg-[#0d1320] px-3 py-2 flex items-center justify-between gap-2">
              <div className="min-w-0 flex-1 space-y-0.5 font-mono text-[11px]">
                <div className="flex items-center gap-1.5">
                  <span className="text-violet-400 font-semibold shrink-0">PKCE S256:</span>
                  <span className="text-slate-300 truncate" title={codeChallenge}>
                    challenge={codeChallenge}
                  </span>
                </div>
                <div className="text-slate-500 truncate" title={codeVerifier}>
                  verifier={codeVerifier}
                </div>
              </div>
              <button
                type="button"
                onClick={handleRegeneratePkce}
                title="Generate new cryptographic PKCE verifier & SHA-256 challenge"
                className="inline-flex items-center gap-1 rounded-md border border-violet-500/40 bg-violet-500/15 px-2 py-1 text-[11px] font-medium text-violet-200 hover:bg-violet-500/25 shrink-0 transition-colors"
              >
                <RefreshCw className="h-3 w-3" />
                <span>New PKCE</span>
              </button>
            </div>
          ) : (
            <div className="md:col-span-5 rounded-lg border border-slate-800 bg-[#0d1320] px-3 py-2 flex items-center gap-2.5 text-xs text-slate-400">
              {flowType === 'client_credentials' ? (
                <>
                  <Cpu className="h-4 w-4 text-cyan-400 shrink-0" />
                  <span>
                    Uses <code className="text-cyan-300">Basic</code> client authentication over TLS; no user redirect or PKCE needed.
                  </span>
                </>
              ) : (
                <>
                  <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
                  <span className="text-amber-200/90">
                    Security Notice: Implicit flow exposes tokens in URL fragments. Prefer PKCE.
                  </span>
                </>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Main Sequence Diagram & Wire Payload Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* LEFT (7 cols): Interactive 3-Actor Sequence Diagram */}
        <div className="lg:col-span-7 rounded-xl border border-slate-800/90 bg-[#111827] overflow-hidden">
          <div className="border-b border-slate-800/80 px-4 py-3 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Interactive Protocol Sequence Diagram
              </h2>
              <p className="text-xs text-slate-400">
                Click any message exchange step to inspect wire-level HTTP payloads
              </p>
            </div>
            <span className="font-mono text-xs text-slate-400 tabular-nums">
              Step {currentStepIndex + 1} / {steps.length}
            </span>
          </div>

          <div className="p-4 space-y-4">
            {/* 3 Actor Swimlane Headers */}
            <div className="grid grid-cols-3 gap-2.5">
              {(['user_agent', 'auth_server', 'resource_server'] as OAuthActor[]).map((actor) => {
                const meta = ACTOR_META[actor];
                return (
                  <div
                    key={actor}
                    className={`rounded-lg border px-3 py-2.5 text-center ${meta.colorClass}`}
                  >
                    <div className="flex items-center justify-center gap-1.5 font-semibold text-xs">
                      {meta.icon}
                      <span className="truncate">{meta.label}</span>
                    </div>
                    <div className="mt-0.5 font-mono text-[10px] opacity-80 truncate">
                      {meta.sublabel}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Sequence Steps */}
            <div className="relative space-y-3 pt-1">
              {/* Vertical Swimlane Guide Lines */}
              <div className="pointer-events-none absolute inset-0 grid grid-cols-3 gap-2.5">
                <div className="flex justify-center">
                  <div className="h-full w-px border-l border-dashed border-cyan-500/25" />
                </div>
                <div className="flex justify-center">
                  <div className="h-full w-px border-l border-dashed border-violet-500/25" />
                </div>
                <div className="flex justify-center">
                  <div className="h-full w-px border-l border-dashed border-emerald-500/25" />
                </div>
              </div>

              {steps.map((step, idx) => {
                const isReached = idx <= currentStepIndex;
                const isSelected = idx === selectedStepIndex;
                const fromCol = getLaneColumnIndex(step.from);
                const toCol = getLaneColumnIndex(step.to);
                const isRightward = toCol > fromCol;
                const spanCols = Math.abs(toCol - fromCol);

                return (
                  <div
                    key={step.id}
                    onClick={() => {
                      if (idx > currentStepIndex) {
                        setCurrentStepIndex(idx);
                      }
                      setSelectedStepIndex(idx);
                    }}
                    className={`relative z-10 cursor-pointer rounded-xl border p-3 transition-all ${
                      isSelected
                        ? 'border-violet-400/70 bg-[#151e31] shadow-md shadow-violet-950/40'
                        : isReached
                        ? 'border-slate-700/80 bg-[#0d1320]/95 hover:border-slate-600'
                        : 'border-slate-800/60 bg-[#0d1320]/50 opacity-60 hover:opacity-90'
                    }`}
                  >
                    {/* Step Header Row */}
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full font-mono text-[11px] font-bold ${
                            isReached
                              ? 'bg-violet-500 text-white'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {step.stepNumber}
                        </span>
                        <span className="text-xs font-semibold text-slate-100 truncate">
                          {step.title}
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5 shrink-0">
                        <span
                          className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${
                            step.method === 'POST'
                              ? 'bg-violet-500/20 text-violet-300 border border-violet-500/30'
                              : step.method === '302'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                          }`}
                        >
                          {step.method}
                        </span>
                        {isReached && <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />}
                      </div>
                    </div>

                    {/* Visual Directional Arrow Across Lanes */}
                    <div className="grid grid-cols-3 gap-2.5 items-center my-1.5">
                      {[0, 1, 2].map((colIdx) => {
                        const isSource = colIdx === fromCol;
                        const isTarget = colIdx === toCol;
                        const isBetween =
                          colIdx > Math.min(fromCol, toCol) && colIdx < Math.max(fromCol, toCol);

                        return (
                          <div key={colIdx} className="flex items-center justify-center h-6">
                            {isSource && (
                              <div className="flex items-center w-full">
                                {!isRightward && (
                                  <div className="flex-1 h-0.5 bg-gradient-to-l from-violet-400 to-cyan-400" />
                                )}
                                <span
                                  className={`h-2.5 w-2.5 rounded-full shrink-0 ${
                                    colIdx === 0
                                      ? 'bg-cyan-400'
                                      : colIdx === 1
                                      ? 'bg-violet-400'
                                      : 'bg-emerald-400'
                                  }`}
                                />
                                {isRightward && (
                                  <div className="flex-1 h-0.5 bg-gradient-to-r from-cyan-400 to-violet-400" />
                                )}
                              </div>
                            )}

                            {isBetween && (
                              <div className="w-full h-0.5 bg-violet-400/80" />
                            )}

                            {isTarget && (
                              <div className="flex items-center w-full">
                                {isRightward && (
                                  <>
                                    <div className="flex-1 h-0.5 bg-gradient-to-r from-violet-400 to-emerald-400" />
                                    <ArrowRight className="h-4 w-4 text-emerald-400 -ml-1 shrink-0" />
                                  </>
                                )}
                                {!isRightward && (
                                  <>
                                    <ArrowLeft className="h-4 w-4 text-cyan-400 -mr-1 shrink-0" />
                                    <div className="flex-1 h-0.5 bg-gradient-to-l from-violet-400 to-cyan-400" />
                                  </>
                                )}
                              </div>
                            )}

                            {!isSource && !isBetween && !isTarget && spanCols > 0 && (
                              <div className="w-1.5 h-1.5 rounded-full bg-slate-800" />
                            )}
                          </div>
                        );
                      })}
                    </div>

                    {/* Endpoint & Subtitle */}
                    <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                      <code className="text-emerald-300 font-mono">{step.endpoint}</code>
                      <span className="text-slate-400">{step.subtitle}</span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Minted Token Ready Banner */}
            {mintedToken && currentStepIndex >= tokenIssuanceStepIndex && (
              <div className="rounded-xl border border-emerald-500/40 bg-emerald-950/20 p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-300">
                    <Sparkles className="h-3.5 w-3.5" />
                    <span>Real Signed JWT Minted by AuthPulse Engine</span>
                  </div>
                  <p className="mt-0.5 font-mono text-[11px] text-slate-300 truncate">
                    {mintedToken}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => onInspectMintedToken(mintedToken)}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-3 py-1.5 text-xs font-semibold text-slate-950 transition-colors shrink-0"
                >
                  <span>Inspect in JWT Decoder</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </div>
            )}
          </div>
        </div>

        {/* RIGHT (5 cols): Active Step Wire Payload & Security Trace */}
        <div className="lg:col-span-5 rounded-xl border border-slate-800/90 bg-[#111827] overflow-hidden">
          <div className="border-b border-slate-800/80 px-4 py-3 flex items-center justify-between gap-2">
            <div>
              <span className="text-[11px] font-mono uppercase tracking-wider text-violet-400">
                Step {activeStep.stepNumber} Wire Trace
              </span>
              <h3 className="text-sm font-semibold text-slate-100">{activeStep.title}</h3>
            </div>
            <span className="rounded-md border border-slate-700 bg-[#0d1320] px-2 py-1 font-mono text-[11px] text-emerald-300">
              {activeStep.responseStatus}
            </span>
          </div>

          <div className="p-4 space-y-4">
            <p className="text-xs leading-relaxed text-slate-300">{activeStep.description}</p>

            {/* Request Parameters or Body */}
            {(activeStep.requestParams || activeStep.requestBody || activeStep.requestHeaders) && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-cyan-400">
                    HTTP Request ({activeStep.method} {activeStep.endpoint})
                  </span>
                </div>
                <JsonViewer
                  data={{
                    ...(activeStep.requestHeaders ? { headers: activeStep.requestHeaders } : {}),
                    ...(activeStep.requestParams ? { query: activeStep.requestParams } : {}),
                    ...(activeStep.requestBody ? { body: activeStep.requestBody } : {}),
                  }}
                  accentColor="cyan"
                />
              </div>
            )}

            {/* Response Body */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-emerald-400">
                  Server Response ({activeStep.responseStatus})
                </span>
              </div>
              <JsonViewer data={activeStep.responseBody} accentColor="emerald" />
            </div>

            {/* Security Architecture Note */}
            <div className="rounded-lg border border-violet-500/30 bg-violet-950/15 p-3 flex items-start gap-2.5">
              <KeyRound className="h-4 w-4 text-violet-400 shrink-0 mt-0.5" />
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wider text-violet-300">
                  Security Architecture Note
                </div>
                <p className="mt-0.5 text-xs leading-relaxed text-slate-300">
                  {activeStep.securityNote}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
