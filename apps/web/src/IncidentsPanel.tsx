import { useState, type FormEvent } from 'react';

type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
type IncidentStatus = 'new' | 'investigating' | 'contained' | 'resolved' | 'closed';
const severities: Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];

type FindingOption = {
  id: string;
  title: string;
  severity: Severity;
  source_type: string;
};

type Incident = {
  id: string;
  title: string;
  summary: string | null;
  severity: Severity;
  status: IncidentStatus;
  owner_id: string | null;
  finding_ids: string[];
  created_at: string;
  updated_at: string;
};

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';
const transitions: Record<IncidentStatus, IncidentStatus[]> = {
  new: ['investigating'],
  investigating: ['contained', 'resolved'],
  contained: ['investigating', 'resolved'],
  resolved: ['investigating', 'closed'],
  closed: [],
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && severities.some((severity) => severity === value);
}

function isFinding(value: unknown): value is FindingOption {
  return (
    isRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.title === 'string' &&
    isSeverity(value.severity) &&
    typeof value.source_type === 'string'
  );
}

function isIncident(value: unknown): value is Incident {
  return (
    isRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.title === 'string' &&
    (value.summary === null || typeof value.summary === 'string') &&
    isSeverity(value.severity) &&
    ['new', 'investigating', 'contained', 'resolved', 'closed'].includes(String(value.status)) &&
    (value.owner_id === null || typeof value.owner_id === 'string') &&
    Array.isArray(value.finding_ids) &&
    value.finding_ids.every((id) => typeof id === 'string') &&
    typeof value.created_at === 'string' &&
    typeof value.updated_at === 'string'
  );
}

function formatLabel(value: string): string {
  return value.replaceAll('_', ' ');
}

async function apiRequest<T>(
  path: string,
  token: string,
  validate: (value: unknown) => value is T,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const detail =
      isRecord(body) && typeof body.detail === 'string'
        ? body.detail
        : `Incident request failed (HTTP ${response.status}).`;
    throw new Error(detail);
  }
  if (!validate(body)) {
    throw new Error('The API returned an unexpected incident workflow response.');
  }
  return body;
}

function isIncidentList(value: unknown): value is Incident[] {
  return Array.isArray(value) && value.every(isIncident);
}

function isFindingList(value: unknown): value is FindingOption[] {
  return Array.isArray(value) && value.every(isFinding);
}

export default function IncidentsPanel() {
  const [accessToken, setAccessToken] = useState('');
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [findings, setFindings] = useState<FindingOption[]>([]);
  const [selectedFindingIds, setSelectedFindingIds] = useState<string[]>([]);
  const [createTitle, setCreateTitle] = useState('');
  const [createSummary, setCreateSummary] = useState('');
  const [createSeverity, setCreateSeverity] = useState<Severity>('medium');
  const [linkSelection, setLinkSelection] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isMutating, setIsMutating] = useState(false);

  async function loadWorkspace(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    const token = accessToken.trim();
    if (!token) {
      setError('Provide an API access token to load tenant incidents.');
      return;
    }
    setIsLoading(true);
    try {
      const [loadedIncidents, loadedFindings] = await Promise.all([
        apiRequest('/incidents?limit=100', token, isIncidentList),
        apiRequest('/findings?limit=100', token, isFindingList),
      ]);
      setIncidents(loadedIncidents);
      setFindings(loadedFindings);
      setNotice('Loaded tenant incidents and findings.');
    } catch (caughtError) {
      setError(
        caughtError instanceof Error
          ? caughtError.message
          : 'Could not load the incident workspace.',
      );
    } finally {
      setIsLoading(false);
    }
  }

  async function createIncident(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    if (!accessToken.trim()) {
      setError('Provide an API access token before creating an incident.');
      return;
    }
    const title = createTitle.trim();
    if (!title) {
      setError('Incident title is required.');
      return;
    }
    setIsMutating(true);
    try {
      const created = await apiRequest(
        '/incidents',
        accessToken.trim(),
        isIncident,
        {
          method: 'POST',
          body: JSON.stringify({
            title,
            summary: createSummary.trim() || null,
            severity: createSeverity,
            finding_ids: selectedFindingIds,
          }),
        },
      );
      setIncidents((current) =>
        [created, ...(current ?? []).filter((incident) => incident.id !== created.id)].slice(0, 100),
      );
      setCreateTitle('');
      setCreateSummary('');
      setSelectedFindingIds([]);
      setNotice(`Incident created: ${created.id}`);
    } catch (caughtError) {
      setError(caughtError instanceof Error ? caughtError.message : 'Could not create incident.');
    } finally {
      setIsMutating(false);
    }
  }

  async function updateIncident(
    incidentId: string,
    path: string,
    body: Record<string, string>,
    successMessage: string,
    method: 'PATCH' | 'POST' = 'PATCH',
  ) {
    setError(null);
    setNotice(null);
    if (!accessToken.trim()) {
      setError('Provide an API access token before updating an incident.');
      return;
    }
    setIsMutating(true);
    try {
      const updated = await apiRequest(
        path,
        accessToken.trim(),
        isIncident,
        { method, body: JSON.stringify(body) },
      );
      setIncidents((current) =>
        (current ?? []).map((incident) => (incident.id === incidentId ? updated : incident)),
      );
      setNotice(successMessage);
    } catch (caughtError) {
      setError(caughtError instanceof Error ? caughtError.message : 'Incident update failed.');
    } finally {
      setIsMutating(false);
    }
  }

  async function linkFinding(incident: Incident) {
    const findingId = linkSelection[incident.id];
    if (!findingId) {
      setError('Choose a finding to link to this incident.');
      return;
    }
    await updateIncident(
      incident.id,
      `/incidents/${encodeURIComponent(incident.id)}/findings`,
      { finding_id: findingId },
      'Finding linked to incident.',
      'POST',
    );
  }

  async function changeStatus(incident: Incident, nextStatus: IncidentStatus) {
    await updateIncident(
      incident.id,
      `/incidents/${encodeURIComponent(incident.id)}/status`,
      { status: nextStatus },
      `Incident status changed to ${formatLabel(nextStatus)}.`,
    );
  }

  function toggleFinding(findingId: string, checked: boolean) {
    setSelectedFindingIds((current) =>
      checked ? [...current, findingId] : current.filter((id) => id !== findingId),
    );
  }

  return (
    <section className="findings-workbench" id="incidents" aria-labelledby="incidents-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">INVESTIGATION WORKFLOW</p>
          <h2 id="incidents-title">Incidents</h2>
          <p className="section-subtitle">
            Group tenant findings into investigations and use controlled status transitions.
          </p>
        </div>
        <span className="email-version">TENANT-SCOPED API</span>
      </div>

      <div className="email-safety-note" role="note">
        Incidents and findings are restricted to the authenticated tenant. Allowed transitions:
        new → investigating; investigating → contained or resolved; contained → investigating or
        resolved; resolved → investigating or closed. Closed incidents are terminal.
      </div>

      <form className="incident-auth-form" onSubmit={loadWorkspace} noValidate>
        <label className="email-field">
          <span>API access token</span>
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={accessToken}
            onChange={(event) => setAccessToken(event.target.value)}
            aria-label="Incidents API access token"
            placeholder="Paste the local demo token"
          />
          <small>
            Held in memory while this panel is open so you can perform incident actions; select
            “Clear token” when finished. Never saved in browser storage.
          </small>
        </label>
        <div className="email-actions">
          <button className="email-submit" type="submit" disabled={isLoading || isMutating}>
            {isLoading ? 'Loading…' : 'Load incidents and findings'}
          </button>
          {accessToken && (
            <button
              className="email-reset"
              type="button"
              onClick={() => setAccessToken('')}
              disabled={isLoading || isMutating}
            >
              Clear token
            </button>
          )}
        </div>
      </form>

      {error && <p className="email-error" role="alert">{error}</p>}
      {notice && <p className="incident-notice" role="status">{notice}</p>}

      {incidents !== null && (
        <>
          <form className="incident-create-form" onSubmit={createIncident} noValidate>
            <h3>Create incident</h3>
            <label className="email-field">
              <span>Title</span>
              <input
                value={createTitle}
                onChange={(event) => setCreateTitle(event.target.value)}
                maxLength={255}
                aria-label="Incident title"
                placeholder="Describe the investigation"
              />
            </label>
            <label className="email-field">
              <span>Summary (optional)</span>
              <textarea
                value={createSummary}
                onChange={(event) => setCreateSummary(event.target.value)}
                maxLength={10_000}
                aria-label="Incident summary"
                rows={3}
              />
            </label>
            <label className="email-field">
              <span>Severity</span>
              <select
                value={createSeverity}
                onChange={(event) => {
                  const nextSeverity = event.target.value;
                  if (isSeverity(nextSeverity)) {
                    setCreateSeverity(nextSeverity);
                  }
                }}
                aria-label="Incident severity"
              >
                {severities.map((severity) => (
                  <option key={severity} value={severity}>{formatLabel(severity)}</option>
                ))}
              </select>
            </label>
            {findings.length > 0 && (
              <fieldset className="incident-finding-picker">
                <legend>Link findings at creation (optional)</legend>
                {findings.map((finding) => (
                  <label key={finding.id}>
                    <input
                      type="checkbox"
                      checked={selectedFindingIds.includes(finding.id)}
                      onChange={(event) => toggleFinding(finding.id, event.target.checked)}
                      disabled={
                        !selectedFindingIds.includes(finding.id) && selectedFindingIds.length >= 100
                      }
                    />
                    <span>{finding.title}</span>
                    <small>{formatLabel(finding.source_type)} · {finding.severity}</small>
                  </label>
                ))}
              </fieldset>
            )}
            <button className="email-submit" type="submit" disabled={isMutating}>
              Create incident
            </button>
          </form>

          <div className="incident-results" aria-live="polite">
            <div className="findings-summary">
              <h3>Tenant incidents</h3>
              <span>{incidents.length} shown · newest first · maximum 100</span>
            </div>
            {incidents.length === 0 ? (
              <p className="empty-state">No incidents are recorded for this tenant yet.</p>
            ) : (
              <ul className="incident-list">
                {incidents.map((incident) => {
                  const availableFindings = findings.filter(
                    (finding) => !incident.finding_ids.includes(finding.id),
                  );
                  const availableStatuses = transitions[incident.status];
                  return (
                    <li className="incident-card" key={incident.id}>
                      <div className="finding-card-heading">
                        <div>
                          <span className="finding-source">INCIDENT · {incident.severity}</span>
                          <h4>{incident.title}</h4>
                        </div>
                        <span className="finding-severity">{formatLabel(incident.status)}</span>
                      </div>
                      {incident.summary && <p className="finding-summary-text">{incident.summary}</p>}
                      <p className="incident-linked-count">
                        {incident.finding_ids.length} linked finding(s)
                      </p>
                      {incident.finding_ids.length > 0 && (
                        <ul className="incident-linked-findings">
                          {incident.finding_ids.map((findingId) => {
                            const linkedFinding = findings.find((item) => item.id === findingId);
                            return (
                              <li key={findingId}>
                                {linkedFinding?.title ?? 'Finding'}{' '}
                                <code>{findingId}</code>
                              </li>
                            );
                          })}
                        </ul>
                      )}
                      {availableFindings.length > 0 && incident.status !== 'closed' && (
                        <div className="incident-action-row">
                          <label className="email-field">
                            <span>Link a finding</span>
                            <select
                              value={linkSelection[incident.id] ?? ''}
                              onChange={(event) =>
                                setLinkSelection((current) => ({
                                  ...current,
                                  [incident.id]: event.target.value,
                                }))
                              }
                              aria-label={`Finding to link to ${incident.title}`}
                            >
                              <option value="">Choose finding</option>
                              {availableFindings.map((finding) => (
                                <option key={finding.id} value={finding.id}>
                                  {finding.title} ({formatLabel(finding.source_type)})
                                </option>
                              ))}
                            </select>
                          </label>
                          <button
                            className="email-reset"
                            type="button"
                            onClick={() => void linkFinding(incident)}
                            disabled={isMutating}
                          >
                            Link finding
                          </button>
                        </div>
                      )}
                      {availableStatuses.length > 0 && (
                        <div className="incident-action-row">
                          {availableStatuses.map((nextStatus) => (
                            <button
                              className="email-reset"
                              key={nextStatus}
                              type="button"
                              onClick={() => void changeStatus(incident, nextStatus)}
                              disabled={isMutating}
                            >
                              {formatLabel(nextStatus)}
                            </button>
                          ))}
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        </>
      )}
    </section>
  );
}
