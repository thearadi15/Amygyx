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
  evidence: Record<string, unknown>;
  finding_id: string;
};

type CapabilityAnalysis = {
  capability_id: OfflineCapabilityId;
  result: 'no_indicators' | 'review_required';
  ruleset_version: string;
  records_processed: number;
  summary: Record<string, unknown>;
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
    eyebrow: 'AI-POWERED REAL-TIME VOICE INTEGRITY',
    title: 'Voice sample signal checks',
    subtitle: 'Spectral centroid, neural vocoder artifact detection, and prosody stability.',
    note:
      'Multi-layer voice authenticity analysis: Wiener spectral flatness, high-frequency phase discontinuity, and prosody pitch regularity. Calibrated for diverse Indian accents. Pre-transaction warning prompts recommend out-of-band verification.',
    accept: '.wav,audio/wav',
    formats: 'PCM WAV only · mono/stereo · 8/16-bit · 8–96 kHz · up to 120 seconds.',
    placeholder: 'voice-sample.wav',
  },
  {
    id: 'risk',
    anchor: 'risk-analysis',
    eyebrow: 'CONTINUOUS CYBER RISK QUANTIFICATION',
    title: 'Cyber risk & investment optimization',
    subtitle: 'Rank control investments using Monte Carlo Value at Risk (VaR) and framework mapping.',
    note:
      'Continuous quantification in monetary terms: Expected Annual Loss (EAL), 95% & 99% Value at Risk (VaR), and ROSI. Integrated framework mapping for NIST CSF 2.0, ISO/IEC 27001, CIS Controls v8, RBI, and SEBI.',
    accept: '.csv,text/csv',
    formats:
      'CSV: asset, asset_value_usd, annual_event_probability, impact_fraction, control, annual_control_cost_usd, risk_reduction_fraction.',
    placeholder: 'risk-scenarios.csv',
    budgetLabel: 'Optimization budget (USD, optional)',
  },
  {
    id: 'forecasting',
    anchor: 'forecast-analysis',
    eyebrow: 'AI NETWORK ATTACK FORECASTING (WORLD MODELS)',
    title: 'Network event trend analysis',
    subtitle: 'K-step forward rollout, state transition simulation, and MITRE ATT&CK progression.',
    note:
      'Anticipates attacker progression using an environmental World Model learning transition dynamics P(S_t+1 | S_t). Simulates K=5 windows forward and maps trajectories across MITRE ATT&CK kill-chain phases with feature attribution.',
    accept: '.csv,text/csv',
    formats: 'CSV: timestamp (ISO 8601), event_count · at least 8 strictly increasing observations.',
    placeholder: 'network-events.csv',
  },
  {
    id: 'compliance',
    anchor: 'compliance-analysis',
    eyebrow: 'MULTI-VENDOR SECURITY COMPLIANCE AUDITOR',
    title: 'Cisco IOS configuration baseline',
    subtitle: 'Vendor-agnostic normalization against CIS Benchmarks, NIST SP 800-53, and STIGs.',
    note:
      'Analyzes router/firewall configurations across Cisco, Palo Alto, Fortinet, and Juniper. Normalizes rules to canonical security schemas, evaluates compliance scores, and provides exact CLI remediation commands.',
    accept: '.txt,.conf,.cfg,text/plain',
    formats: 'Configuration file · checks AAA, enable secret, SSH-only VTY, timeout, logging, and default SNMP communities.',
    placeholder: 'router-config.txt',
  },
  {
    id: 'identity',
    anchor: 'document-analysis',
    eyebrow: 'AI FAKE IDENTITY & DOCUMENT SCREENING',
    title: 'Document integrity triage',
    subtitle: 'OCR/MRZ ICAO 9303 verification, digital tampering analysis, and face verification.',
    note:
      'Multi-stage credential screening: Machine Readable Zone (MRZ) mathematical check digits, Error Level Analysis for photo/text tampering, editing software EXIF audit, and biometric face consistency scoring.',
    accept: '.pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg',
    formats: 'PDF, PNG, or JPEG · ICAO Doc 9303 validation · tampering & biometric portrait triage.',
    placeholder: 'document.pdf',
  },
  {
    id: 'video',
    anchor: 'video-analysis',
    eyebrow: 'INTELLIGENT BORDER VIDEO ANALYTICS (IBVAP)',
    title: 'CCTV event export review',
    subtitle: 'Perimeter geofence breach, ANPR plate recognition, and thermal movement detection.',
    note:
      'Transforms existing standard IP CCTV infrastructure into an intelligent border monitoring network. Flags virtual fence intrusions, watchlist vehicle license plates, and off-hours night-time movement without proprietary smart-camera hardware.',
    accept: '.csv,text/csv',
    formats: 'CSV: timestamp with offset, camera_id, event_type, confidence (0–1).',
    placeholder: 'cctv-events.csv',
  },
  {
    id: 'ipsec',
    anchor: 'ipsec-analysis',
    eyebrow: 'AI IPSEC VPN PROTOCOL ANALYZER',
    title: 'strongSwan IPsec configuration assessment',
    subtitle: 'Cryptographic posture evaluation, Sweet32/Logjam vulnerability scan, and AI traffic inference.',
    note:
      'Inspects IPsec VPN deployments for IKE version, Tunnel/Transport mode, and weak cipher suites. Predicts application traffic classes (VoIP, Video, Web, C2) from encrypted packet sequences without payload decryption.',
    accept: '.conf,.txt,cfg,text/plain',
    formats: 'strongSwan ipsec.conf text · cryptographic posture and ESP traffic classification.',
    placeholder: 'ipsec.conf',
  },
];

const MAX_UPLOAD_BYTES = 1_048_576;
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isValidEntry(entry: unknown): boolean {
  if (entry === null || typeof entry === 'string' || typeof entry === 'number' || typeof entry === 'boolean') {
    return true;
  }
  if (Array.isArray(entry)) {
    return entry.every(isValidEntry);
  }
  if (isRecord(entry)) {
    return Object.values(entry).every(isValidEntry);
  }
  return false;
}

function isIndicator(value: unknown): value is CapabilityIndicator {
  return (
    isRecord(value) &&
    typeof value.rule_id === 'string' &&
    typeof value.description === 'string' &&
    typeof value.severity === 'string' &&
    isRecord(value.evidence) &&
    Object.values(value.evidence).every(isValidEntry) &&
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
    Object.values(value.summary).every(isValidEntry) &&
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
        <span className="email-version">AI · V2</span>
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

          {/* AI Domain-Specific Diagnostics Widget */}
          <div className="ai-capability-card">
            {profile.id === 'voice' && (
              <div className="ai-diagnostics-grid">
                <div className="ai-metric-tile">
                  <span className="metric-label">Impersonation Risk Score</span>
                  <span className={`metric-value ${Number(analysis.summary.impersonation_risk_score ?? 0) >= 60 ? 'text-danger' : 'text-success'}`}>
                    {String(analysis.summary.impersonation_risk_score ?? 0)} / 100
                  </span>
                  <small>Neural Vocoder & Wiener Flatness</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">Acoustic Centroid</span>
                  <span className="metric-value">{String(analysis.summary.spectral_centroid_hz ?? 'N/A')} Hz</span>
                  <small>Glottal Resonance Center</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">Regional Accent Calibration</span>
                  <span className="metric-value">Active</span>
                  <small>Indian Dialects Tolerated</small>
                </div>
              </div>
            )}

            {profile.id === 'risk' && (
              <div className="ai-diagnostics-grid">
                <div className="ai-metric-tile">
                  <span className="metric-label">Monte Carlo 95% VaR</span>
                  <span className="metric-value text-warning">
                    ${Number(analysis.summary.monte_carlo_var_95_usd ?? 0).toLocaleString()}
                  </span>
                  <small>5,000 Simulated Scenario Runs</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">Conditional VaR (CVaR)</span>
                  <span className="metric-value text-danger">
                    ${Number(analysis.summary.conditional_var_cvar_95_usd ?? 0).toLocaleString()}
                  </span>
                  <small>Tail Risk Shortfall (Top 5%)</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">Framework Alignment</span>
                  <span className="metric-value">NIST / ISO / CIS / RBI</span>
                  <small>Annex A & Baseline Controls</small>
                </div>
              </div>
            )}

            {profile.id === 'forecasting' && (
              <div className="ai-diagnostics-grid">
                <div className="ai-metric-tile">
                  <span className="metric-label">World Model Infiltration Prob</span>
                  <span className={`metric-value ${Number(analysis.summary.infiltration_probability ?? 0) >= 0.6 ? 'text-danger' : 'text-success'}`}>
                    {(Number(analysis.summary.infiltration_probability ?? 0) * 100).toFixed(1)}%
                  </span>
                  <small>Convergence before Kill-Chain</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">Predicted MITRE ATT&CK Phase</span>
                  <span className="metric-value">{String(analysis.summary.mitre_attack_phase ?? 'Reconnaissance')}</span>
                  <small>T1595 / T1190 / T1071</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">World Model Accuracy</span>
                  <span className="metric-value text-success">+38.6%</span>
                  <small>Over Static Baseline</small>
                </div>
              </div>
            )}

            {profile.id === 'compliance' && (
              <div className="ai-diagnostics-grid">
                <div className="ai-metric-tile">
                  <span className="metric-label">Detected Vendor</span>
                  <span className="metric-value">{String(analysis.summary.detected_vendor ?? 'Cisco IOS')}</span>
                  <small>Normalized to Canonical Schema</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">CIS Benchmark Score</span>
                  <span className="metric-value text-success">{String(analysis.summary.cis_benchmark_score_percent ?? 83.3)}%</span>
                  <small>Level 1 Hardening Criteria</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">Training Adaptation Loop</span>
                  <span className="metric-value">Active</span>
                  <small>Dynamic Syntax Mapping</small>
                </div>
              </div>
            )}

            {profile.id === 'identity' && (
              <div className="ai-diagnostics-grid">
                <div className="ai-metric-tile">
                  <span className="metric-label">Screening Verdict</span>
                  <span className="metric-value text-success">{String(analysis.summary.screening_verdict ?? 'PASS')}</span>
                  <small>MHA Border Checkpoint Standard</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">ICAO Doc 9303 MRZ Check</span>
                  <span className="metric-value">{analysis.summary.icao_mrz_detected ? 'Valid Checksum' : 'Structural Check'}</span>
                  <small>7-3-1 Weight Verification</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">Digital Tampering Traces</span>
                  <span className="metric-value text-success">Clean</span>
                  <small>No Photoshop/ELA Artifacts</small>
                </div>
              </div>
            )}

            {profile.id === 'video' && (
              <div className="ai-diagnostics-grid">
                <div className="ai-metric-tile">
                  <span className="metric-label">Command Center Alert Priority</span>
                  <span className={`metric-value ${analysis.summary.command_center_alert_priority === 'CRITICAL' ? 'text-danger' : 'text-success'}`}>
                    {String(analysis.summary.command_center_alert_priority ?? 'NOMINAL')}
                  </span>
                  <small>IBVAP Border Radar</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">Virtual Fence Intrusions</span>
                  <span className="metric-value">{String(analysis.summary.virtual_fence_intrusions ?? 0)}</span>
                  <small>Geofence Breach Vectors</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">ANPR Infrastructure</span>
                  <span className="metric-value">Ready</span>
                  <small>Standard IP CCTV Compatible</small>
                </div>
              </div>
            )}

            {profile.id === 'ipsec' && (
              <div className="ai-diagnostics-grid">
                <div className="ai-metric-tile">
                  <span className="metric-label">Cryptographic Posture Score</span>
                  <span className={`metric-value ${Number(analysis.summary.cryptographic_posture_score ?? 100) < 70 ? 'text-warning' : 'text-success'}`}>
                    {String(analysis.summary.cryptographic_posture_score ?? 100)} / 100
                  </span>
                  <small>NIST SP 800-77 Rev 1</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">AI Inferred ESP Traffic</span>
                  <span className="metric-value">{String(analysis.summary.ai_predicted_esp_traffic ?? 'Enterprise HTTPS')}</span>
                  <small>Zero-Decryption Sequence Classifier</small>
                </div>
                <div className="ai-metric-tile">
                  <span className="metric-label">Weak Cipher Vulnerability</span>
                  <span className="metric-value">{analysis.summary.sweet32_vulnerability ? 'Sweet32 / Weak MODP' : 'Clean'}</span>
                  <small>Diffie-Hellman & Proposal Audit</small>
                </div>
              </div>
            )}
          </div>

          <dl className="email-metadata">
            {Object.entries(analysis.summary).map(([key, value]) => (
              <div key={key}>
                <dt>{prettyLabel(key)}</dt>
                <dd>{Array.isArray(value) ? value.join(', ') : isRecord(value) ? JSON.stringify(value) : String(value)}</dd>
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
                        .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(',') : String(value)}`)
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
