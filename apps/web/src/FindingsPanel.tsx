import { useState, type FormEvent } from 'react';

type Finding = {
  id: string;
  source_type: string;
  title: string;
  summary: string | null;
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  business_impact: 'low' | 'moderate' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved' | 'false_positive';
  rule_id: string | null;
  detector_version: string | null;
  evidence: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
};

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isFinding(value: unknown): value is Finding {
  if (!isRecord(value)) return false;
  return (
    typeof value.id === 'string' &&
    typeof value.source_type === 'string' &&
    typeof value.title === 'string' &&
    (value.summary === null || typeof value.summary === 'string') &&
    ['informational', 'low', 'medium', 'high', 'critical'].includes(String(value.severity)) &&
    typeof value.confidence === 'number' &&
    ['low', 'moderate', 'high', 'critical'].includes(String(value.business_impact)) &&
    ['open', 'investigating', 'resolved', 'false_positive'].includes(String(value.status)) &&
    (value.rule_id === null || typeof value.rule_id === 'string') &&
    (value.detector_version === null || typeof value.detector_version === 'string') &&
    (value.evidence === null || isRecord(value.evidence)) &&
    typeof value.created_at === 'string' &&
    typeof value.updated_at === 'string'
  );
}

function formatLabel(value: string): string {
  return value.replaceAll('_', ' ');
}

export default function FindingsPanel() {
  const [accessToken, setAccessToken] = useState('');
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFindings(null);
    setError(null);
    if (!accessToken.trim()) {
      setError('Provide an API access token to load tenant findings.');
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/findings?limit=100`, {
        headers: { Authorization: `Bearer ${accessToken.trim()}` },
      });
      const responseBody: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        const detail =
          isRecord(responseBody) && typeof responseBody.detail === 'string'
            ? responseBody.detail
            : `Could not load findings (HTTP ${response.status}).`;
        throw new Error(detail);
      }
      if (!Array.isArray(responseBody) || !responseBody.every(isFinding)) {
        throw new Error('The API returned an unexpected findings response.');
      }
      setFindings(responseBody);
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'Could not load findings. Check the API connection and try again.',
      );
    } finally {
      setAccessToken('');
      setIsLoading(false);
    }
  }

  return (
    <section className="findings-workbench" id="findings" aria-labelledby="findings-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">SHARED ANALYST WORKFLOW</p>
          <h2 id="findings-title">Tenant findings</h2>
          <p className="section-subtitle">
            Review findings from every active analyzer in one tenant-scoped list.
          </p>
        </div>
        <span className="email-version">SHARED API</span>
      </div>

      <div className="email-safety-note" role="note">
        Results are loaded from the authenticated tenant only. Up to 100 most recent findings are
        shown; this view is read-only. A development token works only with the local synthetic demo.
      </div>

      <form className="findings-form" onSubmit={onSubmit} noValidate>
        <label className="email-field">
          <span>API access token</span>
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={accessToken}
            onChange={(event) => setAccessToken(event.target.value)}
            aria-label="Findings API access token"
            placeholder="Paste the local demo token"
          />
          <small>Cleared after loading and never saved in browser storage.</small>
        </label>
        <button className="email-submit" type="submit" disabled={isLoading}>
          {isLoading ? 'Loading…' : 'Load tenant findings'}
        </button>
      </form>

      {error && (
        <p className="email-error" role="alert">
          {error}
        </p>
      )}

      {findings && (
        <div className="findings-results" aria-live="polite">
          <div className="findings-summary">
            <h3>Shared findings</h3>
            <span>{findings.length} shown · newest first · maximum 100</span>
          </div>
          {findings.length === 0 ? (
            <p className="empty-state">No findings are recorded for this tenant yet.</p>
          ) : (
            <ul className="finding-list">
              {findings.map((finding) => (
                <li className="finding-card" key={finding.id}>
                  <div className="finding-card-heading">
                    <div>
                      <span className="finding-source">{formatLabel(finding.source_type)}</span>
                      <h4>{finding.title}</h4>
                    </div>
                    <span className={`finding-severity severity-${finding.severity}`}>
                      {finding.severity}
                    </span>
                  </div>
                  {finding.summary && <p className="finding-summary-text">{finding.summary}</p>}
                  <dl className="finding-metadata">
                    <div><dt>Status</dt><dd>{formatLabel(finding.status)}</dd></div>
                    <div><dt>Confidence</dt><dd>{Math.round(finding.confidence * 100)}%</dd></div>
                    <div><dt>Business impact</dt><dd>{formatLabel(finding.business_impact)}</dd></div>
                    <div><dt>Created</dt><dd>{new Date(finding.created_at).toLocaleString()}</dd></div>
                    {finding.rule_id && <div><dt>Rule</dt><dd>{finding.rule_id}</dd></div>}
                    {finding.detector_version && (
                      <div><dt>Detector</dt><dd>{finding.detector_version}</dd></div>
                    )}
                  </dl>
                  {finding.evidence && (
                    <details className="finding-evidence">
                      <summary>Evidence</summary>
                      <pre>{JSON.stringify(finding.evidence, null, 2)}</pre>
                    </details>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
