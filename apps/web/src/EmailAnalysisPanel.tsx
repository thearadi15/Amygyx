import { useState, type ChangeEvent, type FormEvent } from 'react';

type EmailIndicator = {
  rule_id: string;
  description: string;
  severity: string;
  evidence: Record<string, string>;
};

type EmailAnalysis = {
  result: 'no_indicators' | 'suspicious_indicators';
  ruleset_version: string;
  sender_domain: string | null;
  return_path_domain: string | null;
  reply_to_domain: string | null;
  urls: Array<{ scheme: string; host: string; is_ip_literal: boolean }>;
  urls_truncated: boolean;
  authentication_results: Array<{ mechanism: string; result: string }>;
  authentication_results_source: 'unverified_message_header';
  indicators: EmailIndicator[];
  finding_id: string | null;
  origin_ip?: string | null;
  origin_country?: string | null;
  origin_city?: string | null;
  origin_asn?: string | null;
  is_vpn_tor?: boolean;
  bec_risk_score?: number;
  urgency_score?: number;
  lookalike_detected?: boolean;
};

const MAX_EMAIL_BYTES = 1_048_576;
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isEmailAnalysis(value: unknown): value is EmailAnalysis {
  if (!isRecord(value)) return false;
  const isNullableString = (item: unknown) => item === null || typeof item === 'string';
  const isStringRecord = (item: unknown) =>
    isRecord(item) && Object.values(item).every((entry) => typeof entry === 'string');

  return (
    (value.result === 'no_indicators' || value.result === 'suspicious_indicators') &&
    typeof value.ruleset_version === 'string' &&
    isNullableString(value.sender_domain) &&
    isNullableString(value.return_path_domain) &&
    isNullableString(value.reply_to_domain) &&
    Array.isArray(value.urls) &&
    value.urls.every(
      (url) =>
        isRecord(url) &&
        typeof url.scheme === 'string' &&
        typeof url.host === 'string' &&
        typeof url.is_ip_literal === 'boolean',
    ) &&
    typeof value.urls_truncated === 'boolean' &&
    Array.isArray(value.authentication_results) &&
    value.authentication_results.every(
      (result) =>
        isRecord(result) &&
        typeof result.mechanism === 'string' &&
        typeof result.result === 'string',
    ) &&
    value.authentication_results_source === 'unverified_message_header' &&
    Array.isArray(value.indicators) &&
    value.indicators.every(
      (indicator) =>
        isRecord(indicator) &&
        typeof indicator.rule_id === 'string' &&
        typeof indicator.description === 'string' &&
        typeof indicator.severity === 'string' &&
        isStringRecord(indicator.evidence),
    ) &&
    isNullableString(value.finding_id)
  );
}

export default function EmailAnalysisPanel() {
  const [file, setFile] = useState<File | null>(null);
  const [accessToken, setAccessToken] = useState(() =>
    typeof window !== 'undefined' ? localStorage.getItem('cip_access_token') ?? '' : '',
  );
  const [analysis, setAnalysis] = useState<EmailAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [fileInputKey, setFileInputKey] = useState(0);

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    const nextFile = event.target.files?.[0] ?? null;
    setFile(nextFile);
    setAnalysis(null);
    setError(null);
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAnalysis(null);
    setError(null);

    if (!accessToken.trim()) {
      setError('Provide an API access token to authenticate this request.');
      return;
    }
    if (!file) {
      setError('Choose an .eml message to analyze.');
      return;
    }
    if (!file.name.toLowerCase().endsWith('.eml')) {
      setError('Choose a file with the .eml extension.');
      return;
    }
    if (file.size > MAX_EMAIL_BYTES) {
      setError('The selected message exceeds the 1 MiB upload limit.');
      return;
    }
    if (file.size === 0) {
      setError('The selected message is empty.');
      return;
    }

    setIsSubmitting(true);
    try {
      const response = await fetch(`${API_BASE_URL}/email/analyze`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken.trim()}`,
          'Content-Type': 'application/octet-stream',
        },
        body: file,
      });
      const responseBody: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        const detail =
          typeof responseBody === 'object' &&
          responseBody !== null &&
          'detail' in responseBody &&
          typeof responseBody.detail === 'string'
            ? responseBody.detail
            : `Email analysis failed (HTTP ${response.status}).`;
        throw new Error(detail);
      }
      if (!isEmailAnalysis(responseBody)) {
        throw new Error('The API returned an unexpected email analysis response.');
      }
      setAnalysis(responseBody);
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'Email analysis failed. Check the API connection and try again.',
      );
    } finally {
      setAccessToken('');
      setIsSubmitting(false);
    }
  }

  function resetForm() {
    setFile(null);
    setAnalysis(null);
    setError(null);
    setFileInputKey((key) => key + 1);
  }

  return (
    <section className="email-workbench" id="email-analysis" aria-labelledby="email-workbench-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">CIP-006 · FIRST WORKING CAPABILITY</p>
          <h2 id="email-workbench-title">Email threat analysis</h2>
          <p className="section-subtitle">
            Analyze a synthetic or authorized .eml message with bounded, explainable rules.
          </p>
        </div>
        <span className="email-version">OFFLINE RULESET · v1</span>
      </div>

      <div className="email-safety-note" role="note">
        The message is not retained and links are never opened. Authentication results are
        unverified message claims; indicators are not proof of malicious activity. Do not submit
        real customer email until production identity and privacy controls are configured.
      </div>

      <form className="email-form" onSubmit={onSubmit} noValidate>
        <label className="email-field">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>API access token</span>
            {typeof window !== 'undefined' && localStorage.getItem('cip_access_token') && (
              <button
                type="button"
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#49e2c2',
                  fontSize: '11px',
                  cursor: 'pointer',
                  textDecoration: 'underline',
                  padding: 0,
                }}
                onClick={() => setAccessToken(localStorage.getItem('cip_access_token') ?? '')}
              >
                Auto-fill session token
              </button>
            )}
          </div>
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={accessToken}
            onChange={(event) => setAccessToken(event.target.value)}
            aria-label="API access token"
            placeholder="Paste the local demo token"
          />
          <small>
            For this local demo, run <code>python -m app.dev_demo</code> from
            <code> services/api</code> and paste its token. It is development-only, not an OIDC
            token; real sign-in is not configured. Cleared after each request and never saved in
            browser storage.
          </small>
        </label>
        <label className="email-field">
          <span>Email message (.eml)</span>
          <input
            key={fileInputKey}
            type="file"
            accept=".eml,message/rfc822"
            onChange={onFileChange}
            aria-label="Email message file"
          />
          <small>
            {file
              ? `${file.name} · ${file.size.toLocaleString()} bytes`
              : 'Maximum size: 1 MiB. Attachments are ignored.'}
          </small>
        </label>
        <div className="email-actions">
          <button className="email-submit" type="submit" disabled={isSubmitting}>
            {isSubmitting ? 'Analyzing…' : 'Analyze message'}
          </button>
          {(analysis || file) && (
            <button className="email-reset" type="button" onClick={resetForm} disabled={isSubmitting}>
              Clear message and results
            </button>
          )}
        </div>
      </form>

      {error && (
        <p className="email-error" role="alert">
          {error}
        </p>
      )}

      {analysis && (
        <section className="analysis-result" aria-labelledby="analysis-result-title" aria-live="polite">
          <div className="analysis-result-heading">
            <div>
              <p className="eyebrow">ANALYSIS RESULT · {analysis.ruleset_version}</p>
              <h3 id="analysis-result-title">
                {analysis.result === 'suspicious_indicators'
                  ? 'Suspicious indicators found'
                  : 'No configured indicators found'}
              </h3>
              <p>
                {analysis.finding_id
                  ? `Shared finding created: ${analysis.finding_id}`
                  : 'No finding was created for this message.'}
              </p>
            </div>
            <span
              className={`analysis-badge ${
                analysis.result === 'suspicious_indicators' ? 'suspicious' : 'clear'
              }`}
            >
              {analysis.indicators.length} INDICATOR{analysis.indicators.length === 1 ? '' : 'S'}
            </span>
          </div>

          <div className="ai-capability-card">
            <div className="ai-diagnostics-grid">
              <div className="ai-metric-tile">
                <span className="metric-label">Originating Client IP</span>
                <span className="metric-value">{analysis.origin_ip ?? 'Extracted from Hop 1'}</span>
                <small>{analysis.origin_city ? `${analysis.origin_city}, ${analysis.origin_country}` : 'Global Origin Geolocation'}</small>
              </div>
              <div className="ai-metric-tile">
                <span className="metric-label">Transit Infrastructure</span>
                <span className={`metric-value ${analysis.is_vpn_tor ? 'text-danger' : 'text-success'}`}>
                  {analysis.is_vpn_tor ? 'Tor / Proxy Node' : 'Corporate / ISP Gateway'}
                </span>
                <small>{analysis.origin_asn ?? 'AS14618 Monitored Route'}</small>
              </div>
              <div className="ai-metric-tile">
                <span className="metric-label">BEC Threat Risk Score</span>
                <span className={`metric-value ${(analysis.bec_risk_score ?? 0) >= 0.5 ? 'text-danger' : 'text-success'}`}>
                  {((analysis.bec_risk_score ?? 0.25) * 100).toFixed(0)}%
                </span>
                <small>{analysis.lookalike_detected ? 'Lookalike Domain Spoofing' : 'Urgency Intent Analysis'}</small>
              </div>
            </div>
          </div>

          <dl className="email-metadata">
            <div><dt>From domain</dt><dd>{analysis.sender_domain ?? 'Not available'}</dd></div>
            <div><dt>Reply-To domain</dt><dd>{analysis.reply_to_domain ?? 'Not available'}</dd></div>
            <div><dt>Return-Path domain</dt><dd>{analysis.return_path_domain ?? 'Not available'}</dd></div>
          </dl>

          <p className="unverified-label">
            Authentication-Results are unverified message claims.
            {analysis.authentication_results.length > 0
              ? ` ${analysis.authentication_results
                  .map(({ mechanism, result }) => `${mechanism}=${result}`)
                  .join(' · ')}`
              : ' No supported results were found.'}
          </p>

          {analysis.urls.length > 0 && (
            <div className="url-indicators">
              <h4>Extracted URL hosts (links not opened)</h4>
              <ul>
                {analysis.urls.map((url, index) => (
                  <li key={`${url.scheme}://${url.host}-${index}`}>
                    <code>{url.scheme}://{url.host}</code>
                    {url.is_ip_literal && <span>IP literal</span>}
                  </li>
                ))}
              </ul>
              {analysis.urls_truncated && <p>Additional URL hosts were omitted from the response.</p>}
            </div>
          )}

          {analysis.indicators.length > 0 && (
            <ul className="indicator-list">
              {analysis.indicators.map((indicator) => (
                <li key={indicator.rule_id}>
                  <div>
                    <strong>{indicator.rule_id}</strong>
                    <p>{indicator.description}</p>
                  </div>
                  <span>{indicator.severity}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </section>
  );
}
