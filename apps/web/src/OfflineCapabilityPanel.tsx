import { useState, type ChangeEvent, type FormEvent } from 'react';

export type OfflineCapabilityId =
  | 'voice'
  | 'risk'
  | 'forecasting'
  | 'compliance'
  | 'identity'
  | 'video'
  | 'ipsec';

type CapabilityIndicator = {
  rule_id: string;
  description: string;
  severity: string;
  evidence: Record<string, string | number | boolean>;
  finding_id: string;
};

type CapabilityAnalysis = {
  capability_id: OfflineCapabilityId;
  result: 'no_indicators' | 'review_required';
  ruleset_version: string;
  records_processed: number;
  summary: Record<string, string | number | boolean>;
  indicators: CapabilityIndicator[];
};

type Profile = {
  id: OfflineCapabilityId;
  anchor: string;
  eyebrow: string;
  title: string;
  subtitle: string;
  note: string;
  accept: string;
  formats: string;
  placeholder: string;
  budgetLabel?: string;
};

const PROFILES: Profile[] = [
  {
    id: 'voice',
    anchor: 'voice-analysis',
    eyebrow: 'LIMITED LOCAL AUDIO PROFILE',
    title: 'Voice sample signal checks',
    subtitle: 'Check authorized PCM WAV audio quality before an analyst reviews it.',
    note:
      'This profile measures audio format, level, silence, and clipping only. It does not detect cloned voices or verify speaker identity; no voice-cloning model is installed. Never use the result to make decisions about a person.',
    accept: '.wav,audio/wav',
    formats: 'PCM WAV only · mono/stereo · 8/16-bit · 8–96 kHz · up to 120 seconds.',
    placeholder: 'voice-sample.wav',
  },
  {
    id: 'risk',
    anchor: 'risk-analysis',
    eyebrow: 'LOCAL QUANTIFICATION PROFILE',
    title: 'Cyber risk & investment optimization',
    subtitle: 'Rank control investments using an explicit annual expected-loss model.',
    note:
      'This is a scenario model, not an actuarial forecast. Inputs are your assumptions; results are sensitive to probability, impact, control efficacy, and costs. Optional budget optimization uses a bounded knapsack model, rounds costs up to $10 increments, and assumes modeled reductions are additive and independent. Review all assumptions before budgeting.',
    accept: '.csv,text/csv',
    formats:
      'CSV: asset, asset_value_usd, annual_event_probability, impact_fraction, control, annual_control_cost_usd, risk_reduction_fraction.',
    placeholder: 'risk-scenarios.csv',
    budgetLabel: 'Optimization budget (USD, optional)',
  },
  {
    id: 'forecasting',
    anchor: 'forecast-analysis',
    eyebrow: 'LIMITED LOCAL TREND PROFILE',
    title: 'Network event trend analysis',
    subtitle: 'Fit a transparent one-step linear trend to supplied event-count history.',
    note:
      'This is a small-sample statistical projection, not AI and not a forecast of attacks. It does not ingest live network telemetry. Use evenly spaced, timezone-stamped event buckets and review false alarms.',
    accept: '.csv,text/csv',
    formats: 'CSV: timestamp (ISO 8601), event_count · at least 8 strictly increasing observations.',
    placeholder: 'network-events.csv',
  },
  {
    id: 'compliance',
    anchor: 'compliance-analysis',
    eyebrow: 'SUPPORTED BASELINE PROFILE',
    title: 'Cisco IOS configuration baseline',
    subtitle: 'Compare a supplied Cisco IOS text configuration against versioned checks.',
    note:
      'Only the listed Cisco IOS baseline checks run; this is not a complete audit or certification. Configuration files may contain secrets. The upload is processed in memory and raw configuration is not stored.',
    accept: '.txt,.conf,.cfg,text/plain',
    formats: 'Cisco IOS text configuration · checks AAA, enable secret, SSH-only VTY, timeout, logging, and default SNMP communities.',
    placeholder: 'router-config.txt',
  },
  {
    id: 'identity',
    anchor: 'document-analysis',
    eyebrow: 'LIMITED DOCUMENT STRUCTURE PROFILE',
    title: 'Document integrity triage',
    subtitle: 'Inspect basic PDF/PNG/JPEG structure for a short list of review signals.',
    note:
      'This does not extract or verify identity, detect forged documents reliably, read personal data, or establish authenticity. A structural signal is not proof of tampering. Use only documents you are authorized to process.',
    accept: '.pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg',
    formats: 'PDF, PNG, or JPEG · structural markers only · no OCR or face recognition.',
    placeholder: 'document.pdf',
  },
  {
    id: 'video',
    anchor: 'video-analysis',
    eyebrow: 'METADATA-ONLY CCTV PROFILE',
    title: 'CCTV event export review',
    subtitle: 'Summarize authorized event metadata exported by an existing CCTV system.',
    note:
      'This does not ingest camera streams or inspect video frames. It performs no face/biometric identification or autonomous enforcement. After-hours flags require site timezone and schedule context; reported model confidence is unverified.',
    accept: '.csv,text/csv',
    formats: 'CSV: timestamp with offset, camera_id, event_type, confidence (0–1).',
    placeholder: 'cctv-events.csv',
  },
  {
    id: 'ipsec',
    anchor: 'ipsec-analysis',
    eyebrow: 'SUPPORTED BASELINE PROFILE',
    title: 'strongSwan IPsec configuration assessment',
    subtitle: 'Check supplied strongSwan ipsec.conf text against a versioned baseline.',
    note:
      'This checks a limited set of IKE version, proposals, weak algorithms, and inline-secret patterns. It does not parse every version/plugin syntax, validate live negotiation, or probe a VPN. Configuration may contain secrets; raw text is not stored.',
    accept: '.conf,.txt,cfg,text/plain',
    formats: 'strongSwan ipsec.conf text · local checks only · no active network probing.',
    placeholder: 'ipsec.conf',
  },
];

const MAX_UPLOAD_BYTES = 1_048_576;
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isIndicator(value: unknown): value is CapabilityIndicator {
  return (
    isRecord(value) &&
    typeof value.rule_id === 'string' &&
    typeof value.description === 'string' &&
    typeof value.severity === 'string' &&
    isRecord(value.evidence) &&
    Object.values(value.evidence).every(
      (entry) =>
        typeof entry === 'string' || typeof entry === 'number' || typeof entry === 'boolean',
    ) &&
    typeof value.finding_id === 'string'
  );
}

function isCapabilityAnalysis(value: unknown, expectedId: OfflineCapabilityId): value is CapabilityAnalysis {
  return (
    isRecord(value) &&
    value.capability_id === expectedId &&
    (value.result === 'no_indicators' || value.result === 'review_required') &&
    typeof value.ruleset_version === 'string' &&
    typeof value.records_processed === 'number' &&
    isRecord(value.summary) &&
    Object.values(value.summary).every(
      (entry) =>
        typeof entry === 'string' || typeof entry === 'number' || typeof entry === 'boolean',
    ) &&
    Array.isArray(value.indicators) &&
    value.indicators.every(isIndicator)
  );
}

function prettyLabel(value: string): string {
  return value.replaceAll('_', ' ');
}

export default function OfflineCapabilityPanel({ profileId }: { profileId: OfflineCapabilityId }) {
  const profile = PROFILES.find((item) => item.id === profileId);
  if (!profile) throw new Error(`Missing offline analyzer profile: ${profileId}`);

  return <CapabilityUploadPanel key={profile.id} profile={profile} />;
}

function CapabilityUploadPanel({ profile }: { profile: Profile }) {
  const [file, setFile] = useState<File | null>(null);
  const [accessToken, setAccessToken] = useState('');
  const [budget, setBudget] = useState('');
  const [analysis, setAnalysis] = useState<CapabilityAnalysis | null>(null);
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
      setError('Choose an input file to analyze.');
      return;
    }
    if (file.size === 0) {
      setError('The selected file is empty.');
      return;
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      setError('The selected file exceeds the 1 MiB upload limit.');
      return;
    }
    if (profile.budgetLabel && budget.trim()) {
      const amount = Number(budget);
      if (!Number.isFinite(amount) || amount < 0 || amount > 1_000_000) {
        setError('Budget must be between $0 and $1,000,000.');
        return;
      }
    }

    setIsSubmitting(true);
    try {
      const query = new URLSearchParams({ filename: file.name });
      if (profile.budgetLabel && budget.trim()) query.set('budget_usd', budget);
      const response = await fetch(
        `${API_BASE_URL}/capabilities/${profile.id}/analyze?${query.toString()}`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken.trim()}`,
            'Content-Type': 'application/octet-stream',
          },
          body: file,
        },
      );
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        const detail =
          isRecord(body) && typeof body.detail === 'string'
            ? body.detail
            : `Analysis failed (HTTP ${response.status}).`;
        throw new Error(detail);
      }
      if (!isCapabilityAnalysis(body, profile.id)) {
        throw new Error('The API returned an unexpected capability analysis response.');
      }
      setAnalysis(body);
    } catch (caughtError) {
      setError(caughtError instanceof Error ? caughtError.message : 'Analysis failed.');
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
      id={profile.anchor}
      aria-labelledby={`${profile.anchor}-title`}
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">{profile.eyebrow}</p>
          <h2 id={`${profile.anchor}-title`}>{profile.title}</h2>
          <p className="section-subtitle">{profile.subtitle}</p>
        </div>
        <span className="email-version">OFFLINE · V1</span>
      </div>
      <div className="email-safety-note" role="note">{profile.note}</div>

      <form className="email-form" onSubmit={onSubmit} noValidate>
        <label className="email-field">
          <span>API access token</span>
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={accessToken}
            onChange={(event) => setAccessToken(event.target.value)}
            aria-label={`${profile.title} API access token`}
            placeholder="Paste the local demo token"
          />
          <small>Development-only local token · cleared after the request · not saved in browser storage.</small>
        </label>
        {profile.budgetLabel && (
          <label className="email-field">
            <span>{profile.budgetLabel}</span>
            <input
              type="number"
              min="0"
              max="1000000"
              step="10"
              value={budget}
              onChange={(event) => setBudget(event.target.value)}
              aria-label={profile.budgetLabel}
              placeholder="e.g. 100000"
            />
            <small>
              Selects a portfolio maximizing modeled annual loss reduction. Requires at most 100
              candidate options; costs are rounded up to $10 increments and do not replace business
              review.
            </small>
          </label>
        )}
        <label className="email-field">
          <span>Input file</span>
          <input
            key={fileInputKey}
            type="file"
            accept={profile.accept}
            onChange={onFileChange}
            aria-label={`${profile.title} input file`}
          />
          <small>{file ? `${file.name} · ${file.size.toLocaleString()} bytes` : profile.formats}</small>
        </label>
        <div className="email-actions">
          <button className="email-submit" type="submit" disabled={isSubmitting}>
            {isSubmitting ? 'Analyzing…' : 'Analyze file'}
          </button>
          {(analysis || file) && (
            <button className="email-reset" type="button" onClick={resetForm} disabled={isSubmitting}>
              Clear file and results
            </button>
          )}
        </div>
      </form>

      {error && <p className="email-error" role="alert">{error}</p>}

      {analysis && (
        <section className="analysis-result" aria-labelledby={`${profile.anchor}-result`} aria-live="polite">
          <div className="analysis-result-heading">
            <div>
              <p className="eyebrow">ANALYSIS RESULT · {analysis.ruleset_version}</p>
              <h3 id={`${profile.anchor}-result`}>
                {analysis.result === 'review_required' ? 'Review signals reported' : 'No configured signals found'}
              </h3>
              <p>{analysis.records_processed.toLocaleString()} record(s) processed · {analysis.indicators.length} indicator(s)</p>
            </div>
            <span className={`analysis-badge${analysis.indicators.length ? ' suspicious' : ''}`}>
              {analysis.indicators.length ? 'REVIEW' : 'NO SIGNALS'}
            </span>
          </div>
          <dl className="email-metadata">
            {Object.entries(analysis.summary).map(([key, value]) => (
              <div key={key}>
                <dt>{prettyLabel(key)}</dt>
                <dd>{String(value)}</dd>
              </div>
            ))}
          </dl>
          {analysis.indicators.length > 0 && (
            <ul className="indicator-list">
              {analysis.indicators.map((indicator) => (
                <li key={indicator.finding_id}>
                  <div>
                    <strong>{indicator.rule_id}</strong>
                    <p>{indicator.description}</p>
                    <p>
                      Evidence: {Object.entries(indicator.evidence)
                        .map(([key, value]) => `${key}=${String(value)}`)
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
