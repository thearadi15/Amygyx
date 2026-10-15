import { useState, type ChangeEvent, type FormEvent } from 'react';

type BitcoinIndicator = {
  rule_id: string;
  description: string;
  severity: string;
  evidence: Record<string, string | number>;
  finding_id: string;
};

type BitcoinAnalysis = {
  result: 'no_indicators' | 'suspicious_indicators';
  ruleset_version: string;
  rows_processed: number;
  indicators: BitcoinIndicator[];
  analytics_summary?: Record<string, unknown>;
};

const MAX_CSV_BYTES = 1_048_576;
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isBitcoinAnalysis(value: unknown): value is BitcoinAnalysis {
  if (!isRecord(value)) return false;
  return (
    (value.result === 'no_indicators' || value.result === 'suspicious_indicators') &&
    typeof value.ruleset_version === 'string' &&
    typeof value.rows_processed === 'number' &&
    Array.isArray(value.indicators) &&
    value.indicators.every(
      (indicator) =>
        isRecord(indicator) &&
        typeof indicator.rule_id === 'string' &&
        typeof indicator.description === 'string' &&
        typeof indicator.severity === 'string' &&
        isRecord(indicator.evidence) &&
        Object.values(indicator.evidence).every(
          (entry) => typeof entry === 'string' || typeof entry === 'number',
        ) &&
        typeof indicator.finding_id === 'string',
    )
  );
}

export default function BitcoinAnalysisPanel() {
  const [file, setFile] = useState<File | null>(null);
  const [accessToken, setAccessToken] = useState('');
  const [analysis, setAnalysis] = useState<BitcoinAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [fileInputKey, setFileInputKey] = useState(0);

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    setFile(event.target.files?.[0] ?? null);
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
      setError('Choose a Bitcoin transfer CSV file to analyze.');
      return;
    }
    if (!file.name.toLowerCase().endsWith('.csv')) {
      setError('Choose a file with the .csv extension.');
      return;
    }
    if (file.size > MAX_CSV_BYTES) {
      setError('The selected CSV exceeds the 1 MiB upload limit.');
      return;
    }
    if (file.size === 0) {
      setError('The selected CSV is empty.');
      return;
    }

    setIsSubmitting(true);
    try {
      const response = await fetch(`${API_BASE_URL}/bitcoin/analyze`, {
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
            : `Bitcoin transaction analysis failed (HTTP ${response.status}).`;
        throw new Error(detail);
      }
      if (!isBitcoinAnalysis(responseBody)) {
        throw new Error('The API returned an unexpected Bitcoin analysis response.');
      }
      setAnalysis(responseBody);
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'Bitcoin analysis failed. Check the API connection and try again.',
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
    <section
      className="email-workbench"
      id="bitcoin-analysis"
      aria-labelledby="bitcoin-workbench-title"
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">CIP-005 · WORKING CAPABILITY</p>
          <h2 id="bitcoin-workbench-title">Bitcoin transaction analysis</h2>
          <p className="section-subtitle">
            Review authorized transfer-edge records using an offline, explainable ruleset.
          </p>
        </div>
        <span className="email-version">OFFLINE RULESET · v1</span>
      </div>

      <div className="email-safety-note" role="note">
        Uploads are user-supplied CSV data, not live blockchain monitoring. Fan-in, fan-out, and
        transfer-value outliers are contextual leads only; they do not identify people or establish
        wrongdoing. Raw transaction IDs and addresses are not retained. Use only data you are
        authorized to analyze.
      </div>

      <form className="email-form" onSubmit={onSubmit} noValidate>
        <label className="email-field">
          <span>API access token</span>
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={accessToken}
            onChange={(event) => setAccessToken(event.target.value)}
            aria-label="Bitcoin API access token"
            placeholder="Paste the local demo token"
          />
          <small>
            For the local demo, run <code>python -m app.dev_demo</code> from
            <code> services/api</code>. The token is development-only; it is cleared after the
            request and not saved in browser storage.
          </small>
        </label>
        <label className="email-field">
          <span>Bitcoin transfer-edge CSV</span>
          <input
            key={fileInputKey}
            type="file"
            accept=".csv,text/csv"
            onChange={onFileChange}
            aria-label="Bitcoin transfer CSV file"
          />
          <small>
            {file
              ? `${file.name} · ${file.size.toLocaleString()} bytes`
              : 'Required columns: transaction_id, sender_address, recipient_address, amount_btc.'}
          </small>
        </label>
        <div className="email-actions">
          <button className="email-submit" type="submit" disabled={isSubmitting}>
            {isSubmitting ? 'Analyzing…' : 'Analyze transfers'}
          </button>
          {(analysis || file) && (
            <button className="email-reset" type="button" onClick={resetForm} disabled={isSubmitting}>
              Clear file and results
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
        <section className="analysis-result" aria-labelledby="bitcoin-result-title" aria-live="polite">
          <div className="analysis-result-heading">
            <div>
              <p className="eyebrow">ANALYSIS RESULT · {analysis.ruleset_version}</p>
              <h3 id="bitcoin-result-title">
                {analysis.result === 'suspicious_indicators'
                  ? 'Transaction patterns need review'
                  : 'No configured indicators found'}
              </h3>
              <p>
                {analysis.rows_processed.toLocaleString()} transfer-edge records analyzed ·{' '}
                {analysis.indicators.length} indicator(s)
              </p>
            </div>
            <span
              className={`analysis-badge${analysis.indicators.length ? ' suspicious' : ''}`}
            >
              {analysis.indicators.length ? 'REVIEW' : 'NO INDICATORS'}
            </span>
          </div>

          <div className="ai-capability-card">
            <div className="ai-diagnostics-grid">
              <div className="ai-metric-tile">
                <span className="metric-label">Entity Clustering</span>
                <span className="metric-value text-success">Active</span>
                <small>Common-Input Ownership Heuristic</small>
              </div>
              <div className="ai-metric-tile">
                <span className="metric-label">Peeling Chain & Mixers</span>
                <span className="metric-value">Monitored</span>
                <small>Equal-Output & Velocity Analysis</small>
              </div>
              <div className="ai-metric-tile">
                <span className="metric-label">Privacy Shield</span>
                <span className="metric-value text-success">Enforced</span>
                <small>Zero Raw Address Retention Policy</small>
              </div>
            </div>
          </div>

          {analysis.indicators.length > 0 && (
            <ul className="indicator-list">
              {analysis.indicators.map((indicator) => (
                <li key={indicator.finding_id}>
                  <div>
                    <strong>{indicator.rule_id}</strong>
                    <p>{indicator.description}</p>
                    <p>
                      Evidence: {Object.entries(indicator.evidence)
                        .map(([key, value]) => `${key}=${value}`)
                        .join(' · ')}
                    </p>
                    <p>Shared finding created: {indicator.finding_id}</p>
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
