import React, { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { CLAIM_DESCRIPTIONS, formatUnixTimestamp } from '../utils/jwtCrypto';

interface JsonViewerProps {
  data: Record<string, unknown> | null;
  accentColor?: 'cyan' | 'emerald' | 'violet' | 'slate';
  showClaimHints?: boolean;
  emptyMessage?: string;
}

export const JsonViewer: React.FC<JsonViewerProps> = ({
  data,
  accentColor = 'slate',
  showClaimHints = false,
  emptyMessage = 'No valid JSON data to display.',
}) => {
  const [copied, setCopied] = useState(false);

  if (!data) {
    return (
      <div className="rounded-lg border border-slate-800/80 bg-[#0d1320] p-4 font-mono text-xs text-slate-500">
        {emptyMessage}
      </div>
    );
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      // ignore clipboard errors
    }
  };

  const keyColorClass =
    accentColor === 'cyan'
      ? 'text-cyan-300'
      : accentColor === 'emerald'
      ? 'text-emerald-300'
      : accentColor === 'violet'
      ? 'text-violet-300'
      : 'text-sky-300';

  const renderValue = (val: unknown, keyName?: string): React.ReactNode => {
    if (val === null) {
      return <span className="text-slate-500 italic">null</span>;
    }
    if (typeof val === 'boolean') {
      return <span className="text-amber-400">{val ? 'true' : 'false'}</span>;
    }
    if (typeof val === 'number') {
      const isTimestamp =
        (keyName === 'exp' || keyName === 'iat' || keyName === 'nbf' || keyName === 'auth_time') &&
        val > 1000000000;
      return (
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="text-violet-300 tabular-nums">{val}</span>
          {isTimestamp && (
            <span className="rounded bg-slate-800/90 px-1.5 py-0.5 text-[11px] text-slate-400 border border-slate-700/60">
              {formatUnixTimestamp(val)}
            </span>
          )}
        </span>
      );
    }
    if (typeof val === 'string') {
      return <span className="text-emerald-300/95 break-all">"{val}"</span>;
    }
    if (Array.isArray(val)) {
      if (val.length === 0) return <span className="text-slate-400">[]</span>;
      return (
        <span>
          <span className="text-slate-400">[</span>
          <span className="inline-flex flex-wrap gap-1.5 mx-1">
            {val.map((item, idx) => (
              <span key={idx}>
                {typeof item === 'string' ? (
                  <span className="rounded bg-slate-800/90 px-1.5 py-0.5 text-emerald-300 border border-slate-700/50">
                    "{item}"
                  </span>
                ) : (
                  renderValue(item)
                )}
                {idx < val.length - 1 && <span className="text-slate-500">,</span>}
              </span>
            ))}
          </span>
          <span className="text-slate-400">]</span>
        </span>
      );
    }
    if (typeof val === 'object') {
      return (
        <span className="text-slate-300">{JSON.stringify(val)}</span>
      );
    }
    return <span className="text-slate-300">{String(val)}</span>;
  };

  const entries = Object.entries(data);

  return (
    <div className="relative group rounded-lg border border-slate-800/90 bg-[#0d1320] overflow-hidden">
      <button
        type="button"
        onClick={handleCopy}
        title="Copy JSON"
        className="absolute right-2.5 top-2.5 z-10 inline-flex items-center gap-1 rounded-md border border-slate-700/80 bg-slate-900/90 px-2 py-1 text-[11px] font-medium text-slate-300 hover:border-slate-600 hover:text-white transition-colors"
      >
        {copied ? (
          <>
            <Check className="h-3 w-3 text-emerald-400" />
            <span className="text-emerald-400">Copied</span>
          </>
        ) : (
          <>
            <Copy className="h-3 w-3" />
            <span>JSON</span>
          </>
        )}
      </button>

      <div className="p-3.5 pr-20 font-mono text-[13px] leading-relaxed overflow-x-auto">
        <div className="text-slate-500">{'{'}</div>
        <div className="pl-4 space-y-1">
          {entries.map(([key, value], index) => {
            const hint = showClaimHints ? CLAIM_DESCRIPTIONS[key] : undefined;
            return (
              <div
                key={key}
                className="group/row flex flex-wrap items-baseline gap-x-1.5 rounded px-1 -mx-1 hover:bg-slate-800/40 transition-colors"
              >
                <span className={keyColorClass}>"{key}"</span>
                <span className="text-slate-500">:</span>
                <div className="flex-1 min-w-[140px]">
                  {renderValue(value, key)}
                  {index < entries.length - 1 && <span className="text-slate-500">,</span>}
                </div>
                {hint && (
                  <span
                    title={`${hint.label} (${hint.spec}): ${hint.description}`}
                    className="hidden sm:inline-block text-[11px] text-slate-500 group-hover/row:text-slate-400 select-none"
                  >
                    // {hint.label}
                  </span>
                )}
              </div>
            );
          })}
        </div>
        <div className="text-slate-500">{'}'}</div>
      </div>
    </div>
  );
};
