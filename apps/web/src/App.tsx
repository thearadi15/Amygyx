import { useEffect, useMemo, useState } from 'react';
import LoginPage from './LoginPage';
import BitcoinAnalysisPanel from './BitcoinAnalysisPanel';
import EmailAnalysisPanel from './EmailAnalysisPanel';
import FindingsPanel from './FindingsPanel';
import IncidentsPanel from './IncidentsPanel';
import OfflineCapabilityPanel, { type OfflineCapabilityId } from './OfflineCapabilityPanel';
import TrafficAnalysisPanel from './TrafficAnalysisPanel';

type ModuleCategory = 'Detection' | 'Risk & assurance' | 'Identity & media';
type RouteId =
  | 'overview'
  | 'capabilities'
  | 'integrations'
  | 'findings'
  | 'incidents'
  | 'email'
  | 'unidirectional'
  | 'bitcoin'
  | OfflineCapabilityId;

type Module = {
  id: RouteId;
  name: string;
  category: ModuleCategory;
  description: string;
  approach: string;
  status: 'LOCAL MVP' | 'LIMITED';
};

const modules: Module[] = [
  {
    id: 'voice',
    name: 'Voice signal checks',
    category: 'Identity & media',
    description: 'Review authorized WAV audio for signal-quality issues.',
    approach: 'Audio format, silence, signal level, and clipping checks only. No voice-clone detection or speaker identification.',
    status: 'LIMITED',
  },
  {
    id: 'risk',
    name: 'Cyber risk & investment',
    category: 'Risk & assurance',
    description: 'Compare control investments using supplied risk assumptions.',
    approach: 'An explicit annual expected-loss model for scenario planning, not an actuarial forecast or budget recommendation.',
    status: 'LOCAL MVP',
  },
  {
    id: 'email',
    name: 'Email threat analysis',
    category: 'Detection',
    description: 'Inspect submitted email for explainable suspicious indicators.',
    approach: 'Offline analysis of sender/authentication claims and URLs. Authentication headers are treated as unverified input.',
    status: 'LOCAL MVP',
  },
  {
    id: 'unidirectional',
    name: 'IP traffic analysis',
    category: 'Detection',
    description: 'Review authorized one-way network flow records.',
    approach: 'Versioned port-scan and destination fan-out heuristics over supplied CSV data; no live telemetry.',
    status: 'LOCAL MVP',
  },
  {
    id: 'bitcoin',
    name: 'Bitcoin transfer analysis',
    category: 'Detection',
    description: 'Review transfer-edge data for contextual patterns.',
    approach: 'Offline fan-in, fan-out, and transfer-value rules. Findings contain aggregate evidence, not addresses or transaction IDs.',
    status: 'LOCAL MVP',
  },
  {
    id: 'forecasting',
    name: 'Network trend analysis',
    category: 'Detection',
    description: 'Project a one-step trend from supplied event-count history.',
    approach: 'Transparent linear projection only; it does not predict attacks or ingest live network data.',
    status: 'LOCAL MVP',
  },
  {
    id: 'compliance',
    name: 'Cisco IOS baseline',
    category: 'Risk & assurance',
    description: 'Check a supplied router configuration against a limited baseline.',
    approach: 'Versioned checks for selected Cisco IOS controls. This is not a complete audit or compliance certification.',
    status: 'LOCAL MVP',
  },
  {
    id: 'identity',
    name: 'Document structure triage',
    category: 'Identity & media',
    description: 'Check basic PDF, PNG, or JPEG structural signals.',
    approach: 'No OCR, identity verification, face analysis, or reliable counterfeit detection.',
    status: 'LIMITED',
  },
  {
    id: 'video',
    name: 'CCTV event metadata',
    category: 'Identity & media',
    description: 'Summarize event metadata exported by an authorized camera system.',
    approach: 'No video stream/frame processing, biometric identification, or autonomous enforcement.',
    status: 'LIMITED',
  },
  {
    id: 'ipsec',
    name: 'IPsec configuration',
    category: 'Risk & assurance',
    description: 'Check supplied strongSwan configuration against a limited baseline.',
    approach: 'Selected IKE/proposal/secret checks only; no live negotiation or endpoint probing.',
    status: 'LOCAL MVP',
  },
];

const routeTitles: Record<RouteId, string> = {
  overview: 'Overview',
  capabilities: 'Capabilities',
  integrations: 'Integrations',
  findings: 'Findings',
  incidents: 'Incidents',
  email: 'Email analysis',
  unidirectional: 'IP traffic analysis',
  bitcoin: 'Bitcoin analysis',
  voice: 'Voice signal checks',
  risk: 'Cyber risk & investment',
  forecasting: 'Network trend analysis',
  compliance: 'Cisco IOS baseline',
  identity: 'Document structure triage',
  video: 'CCTV event metadata',
  ipsec: 'IPsec configuration',
};

const routeDescriptions: Record<RouteId, string> = {
  overview: 'AI-powered cyber intelligence for authorized analysis and analyst-led investigations.',
  capabilities: 'Choose a local analysis workflow. Every profile documents what it checks and what it does not.',
  integrations: 'Production connectors are not configured. Review what each live capability requires before enabling it.',
  findings: 'Review evidence-backed signals contributed by the analysis workspaces.',
  incidents: 'Group findings and track analyst-led response through the supported incident workflow.',
  email: 'Upload a message for offline, explainable email indicators.',
  unidirectional: 'Upload authorized one-way flow records for bounded traffic heuristics.',
  bitcoin: 'Review authorized transfer-edge records using an offline, explainable ruleset.',
  voice: 'Check authorized PCM WAV recordings for signal quality only.',
  risk: 'Rank control scenarios using your supplied assumptions.',
  forecasting: 'Project a simple trend from supplied network event-count history.',
  compliance: 'Review selected Cisco IOS configuration controls.',
  identity: 'Inspect basic document structure markers without verifying identity.',
  video: 'Review event metadata exported from an authorized CCTV system.',
  ipsec: 'Review selected strongSwan IPsec configuration controls.',
};

const integrationReadiness = [
  {
    name: 'Identity and access',
    current: 'Development-only local tokens; OIDC resource-server support exists but no provider is configured.',
    required: 'Approved OIDC issuer, audience, JWKS endpoint, and managed tenant-member provisioning.',
  },
  {
    name: 'Voice and telephony',
    current: 'No call-stream integration or cloned-voice detection model.',
    required: 'Authorized VoIP/telephony stream, privacy-approved retention policy, evaluated multilingual model.',
  },
  {
    name: 'Email and origin intelligence',
    current: 'Manual .eml upload and offline header/URL rules only.',
    required: 'Approved mailbox/API scopes and vetted DNS/IP/domain intelligence datasets.',
  },
  {
    name: 'Network traffic',
    current: 'Manual flow CSV upload; no streaming sensor or throughput benchmark.',
    required: 'Authorized passive NetFlow/IPFIX/sFlow or PCAP feed, bounded queueing, and measured traffic-rate tests.',
  },
  {
    name: 'Bitcoin data',
    current: 'Manual transfer-edge CSV rules; no node or network-layer correlation.',
    required: 'Approved node/data source, lawful intelligence feeds, entity graph, and validated evaluation data.',
  },
  {
    name: 'Risk and security data',
    current: 'Analyst-supplied scenario CSV; no vulnerability, SIEM, IAM, EDR, or asset inventory connectors.',
    required: 'Approved read-only source credentials, asset mapping, calibrated likelihood/impact data, and budget authority.',
  },
  {
    name: 'Forecasting and MITRE mapping',
    current: 'One-step linear trend over uploaded counts; no temporal world model or attack-stage mapping.',
    required: 'Authorized time-series telemetry, representative labeled datasets, reproducible model evaluation, and ATT&CK mapping.',
  },
  {
    name: 'Compliance baselines',
    current: 'Limited Cisco IOS text checks only.',
    required: 'Approved vendor configuration access, licensed/authorized benchmark content, framework mappings, and remediation review.',
  },
  {
    name: 'Document screening',
    current: 'PDF/PNG/JPEG structural checks only; no OCR, face match, or authenticity source.',
    required: 'Explicit legal authority, protected OCR/document datasets, approved verification sources, and human review controls.',
  },
  {
    name: 'CCTV and video',
    current: 'CSV event metadata only; no camera stream, frame analytics, or model.',
    required: 'Authorized VMS/RTSP access, privacy and retention approval, edge compute, and tested safety-event models.',
  },
  {
    name: 'IPsec assessment',
    current: 'Static strongSwan text checks only; no packet capture or live session analysis.',
    required: 'Authorized configuration/PCAP sources, protocol parser coverage, and controlled VPN testbed.',
  },
];

const categories: Array<'All capabilities' | ModuleCategory> = [
  'All capabilities',
  'Detection',
  'Risk & assurance',
  'Identity & media',
];

function currentRoute(): RouteId {
  const candidate = window.location.hash.replace(/^#\/?/, '').split('/')[0] as RouteId;
  return Object.hasOwn(routeTitles, candidate) ? candidate : 'overview';
}

const TEST_USER = {
  name: 'Arjun Sharma',
  email: 'admin@amygyx.io',
  role: 'SOC Analyst — L3',
  tenant: 'NTRO-GOV-01',
};

export default function App() {
  const [user, setUser] = useState<{ name: string; email: string; role: string; tenant: string } | null>(() => {
    if (import.meta.env.MODE === 'test') {
      return TEST_USER;
    }
    try {
      const stored = localStorage.getItem('cip_user');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });
  const [route, setRoute] = useState<RouteId>(currentRoute);
  const [activeCategory, setActiveCategory] = useState<(typeof categories)[number]>('All capabilities');
  const [search, setSearch] = useState('');

  // All hooks MUST come before any conditional return (React rules of hooks)
  useEffect(() => {
    const handleHashChange = () => setRoute(currentRoute());
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [route]);

  const visibleModules = useMemo(() => {
    const query = search.trim().toLowerCase();
    return modules.filter((module) => {
      const matchesCategory =
        activeCategory === 'All capabilities' || module.category === activeCategory;
      const matchesSearch =
        query.length === 0 ||
        `${module.name} ${module.description} ${module.category}`.toLowerCase().includes(query);
      return matchesCategory && matchesSearch;
    });
  }, [activeCategory, search]);

  const activeModule = modules.find((module) => module.id === route);
  const pageTitle = activeModule?.name ?? routeTitles[route];
  const pageHeading =
    route === 'findings'
      ? 'Shared findings'
      : route === 'incidents'
        ? 'Incident management'
        : pageTitle;

  // Gate everything behind login — AFTER all hooks
  if (!user) return <LoginPage onLogin={setUser} />;

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Platform navigation">
        <a className="brand" href="#/overview" aria-label="AMYGYX AI-powered cyber intelligence home">
          <span className="brand-mark" aria-hidden="true">A</span>
          <span className="brand-name">AMYGYX<span>CYBER INTELLIGENCE</span></span>
        </a>

        <nav className="nav-scroll" aria-label="Primary">
          <p className="nav-label">WORKSPACE</p>
          <a className={`nav-link${route === 'overview' ? ' active' : ''}`} aria-current={route === 'overview' ? 'page' : undefined} href="#/overview">Overview</a>
          <a className={`nav-link${route === 'capabilities' ? ' active' : ''}`} aria-current={route === 'capabilities' ? 'page' : undefined} href="#/capabilities">
            Capability library <span>10</span>
          </a>
          <a className={`nav-link${route === 'integrations' ? ' active' : ''}`} aria-current={route === 'integrations' ? 'page' : undefined} href="#/integrations">
            Integrations <span>0 connected</span>
          </a>

          <p className="nav-label nav-section-label">ANALYSIS</p>
          <a className={`nav-link${route === 'email' ? ' active' : ''}`} aria-current={route === 'email' ? 'page' : undefined} href="#/email">Email</a>
          <a className={`nav-link${route === 'unidirectional' ? ' active' : ''}`} aria-current={route === 'unidirectional' ? 'page' : undefined} href="#/unidirectional">IP traffic</a>
          <a className={`nav-link${route === 'bitcoin' ? ' active' : ''}`} aria-current={route === 'bitcoin' ? 'page' : undefined} href="#/bitcoin">Bitcoin transfers</a>
          <a className={`nav-link${route === 'voice' ? ' active' : ''}`} aria-current={route === 'voice' ? 'page' : undefined} href="#/voice">Voice signal</a>
          <a className={`nav-link${route === 'risk' ? ' active' : ''}`} aria-current={route === 'risk' ? 'page' : undefined} href="#/risk">Risk & investment</a>
          <a className={`nav-link${route === 'forecasting' ? ' active' : ''}`} aria-current={route === 'forecasting' ? 'page' : undefined} href="#/forecasting">Network trends</a>
          <a className={`nav-link${route === 'compliance' ? ' active' : ''}`} aria-current={route === 'compliance' ? 'page' : undefined} href="#/compliance">Cisco IOS</a>
          <a className={`nav-link${route === 'identity' ? ' active' : ''}`} aria-current={route === 'identity' ? 'page' : undefined} href="#/identity">Document triage</a>
          <a className={`nav-link${route === 'video' ? ' active' : ''}`} aria-current={route === 'video' ? 'page' : undefined} href="#/video">CCTV metadata</a>
          <a className={`nav-link${route === 'ipsec' ? ' active' : ''}`} aria-current={route === 'ipsec' ? 'page' : undefined} href="#/ipsec">IPsec</a>

          <p className="nav-label nav-section-label">OPERATIONS</p>
          <a className={`nav-link${route === 'findings' ? ' active' : ''}`} aria-current={route === 'findings' ? 'page' : undefined} href="#/findings">Findings</a>
          <a className={`nav-link${route === 'incidents' ? ' active' : ''}`} aria-current={route === 'incidents' ? 'page' : undefined} href="#/incidents">Incidents</a>
        </nav>
        <div className="sidebar-bottom">
          <div className="user-avatar-mini">{user.name.charAt(0)}</div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <strong>{user.name}</strong>
            <small>{user.role}</small>
            <small style={{ color: '#3d9c8c', marginTop: 1 }}>{user.tenant}</small>
          </div>
          <button
            className="logout-btn"
            title="Sign out"
            onClick={() => {
              localStorage.removeItem('cip_user');
              localStorage.removeItem('cip_access_token');
              setUser(null);
              window.location.hash = '';
            }}
          >⏻</button>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumbs">
            <a href="#/overview">Workspace</a><span>/</span>{pageTitle}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span className="environment"><span className="environment-dot" /> LOCAL · DEVELOPMENT</span>
            <div className="topbar-user-badge">
              <div className="topbar-avatar">{user.name.charAt(0)}</div>
              <div>
                <div className="topbar-user-name">{user.name}</div>
                <div className="topbar-user-role">{user.role} · {user.tenant}</div>
              </div>
            </div>
          </div>
        </header>

        <section className="page-header">
          <div>
            <p className="eyebrow">{route === 'overview' ? 'UNIFIED SECURITY OPERATIONS' : 'WORKSPACE'}</p>
            <h1>{route === 'overview' ? <>AMYGYX<br /><span>AI-Powered Cyber Intelligence</span></> : pageHeading}</h1>
            <p className="page-description">{routeDescriptions[route]}</p>
            {route === 'overview' && <p className="brand-tagline">Sense the Threat. Reveal the Truth.</p>}
          </div>
          {activeModule && (
            <span className={`status-pill${activeModule.status === 'LIMITED' ? ' limited' : ''}`}>
              {activeModule.status === 'LIMITED' ? 'Limited profile' : 'Local MVP'}
            </span>
          )}
        </section>

        {route === 'overview' && (
          <>
            <section className="overview-stats" aria-label="Platform summary">
              <article><span>CAPABILITY PROFILES</span><strong>10</strong><small>Local analysis workspaces</small></article>
              <article><span>SHARED WORKFLOWS</span><strong>02</strong><small>Findings and incidents</small></article>
              <article><span>DATA MODE</span><strong className="stat-text">Offline</strong><small>Uploads only · no live telemetry</small></article>
            </section>
            <section className="overview-section">
              <div className="section-heading">
                <div><p className="eyebrow">GET STARTED</p><h2>Choose a workspace</h2></div>
                <a className="text-link" href="#/capabilities">View all capabilities <span aria-hidden="true">→</span></a>
              </div>
              <div className="quick-links">
                {(['email', 'unidirectional', 'bitcoin', 'risk', 'findings', 'integrations'] as RouteId[]).map((item) => (
                  <a className="quick-link-card" href={`#/${item}`} key={item}>
                    <span className="quick-link-icon" aria-hidden="true">{item === 'findings' ? 'F' : item === 'integrations' ? '↔' : item === 'bitcoin' ? '₿' : item === 'email' ? '@' : item === 'risk' ? '$' : '↗'}</span>
                    <span><strong>{routeTitles[item]}</strong><small>{routeDescriptions[item]}</small></span>
                    <span className="quick-link-arrow" aria-hidden="true">→</span>
                  </a>
                ))}
              </div>
            </section>
            <section className="notice-panel" role="note">
              <strong>Prototype environment</strong>
              <p>These local profiles are not production-ready security controls. Use authorized synthetic data, validate findings manually, and do not rely on them for consequential decisions.</p>
            </section>
          </>
        )}

        {route === 'capabilities' && (
          <section className="capabilities-section" aria-labelledby="capabilities-title">
            <div className="section-heading capability-heading">
              <div><h2 id="capabilities-title">All analysis workspaces</h2><p className="section-subtitle">Select a workflow to review its limits and submit an authorized sample.</p></div>
              <label className="search-box">
                <span className="search-icon" aria-hidden="true">⌕</span>
                <span className="visually-hidden">Search capabilities</span>
                <input
                  type="search"
                  aria-label="Search capabilities"
                  placeholder="Search capabilities"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                />
              </label>
            </div>
            <div className="filter-row" role="group" aria-label="Filter capabilities">
              {categories.map((category) => (
                <button
                  className={`filter-button${activeCategory === category ? ' selected' : ''}`}
                  key={category}
                  type="button"
                  aria-label={`Filter by ${category}`}
                  aria-pressed={activeCategory === category}
                  onClick={() => setActiveCategory(category)}
                >
                  {category}
                </button>
              ))}
              <span className="result-count" aria-live="polite">{visibleModules.length} profiles</span>
            </div>
            <div className="module-grid capability-library" role="group" aria-label="Available capabilities">
              {visibleModules.length > 0 ? visibleModules.map((module) => (
                <a className="module-card" href={`#/${module.id}`} key={module.id}>
                  <span className="card-topline">
                    <span className="module-index">{String(modules.indexOf(module) + 1).padStart(2, '0')}</span>
                    <span className={`planned-tag${module.status === 'LIMITED' ? ' limited' : ''}`}>{module.status}</span>
                  </span>
                  <span className="module-name">{module.name}</span>
                  <span className="module-description">{module.description}</span>
                  <span className="module-category">{module.category}<span aria-hidden="true">↗</span></span>
                </a>
              )) : <p className="empty-state">No capabilities match this search. Try a different term.</p>}
            </div>
          </section>
        )}

        {route === 'integrations' && (
          <section className="integrations-section" aria-labelledby="integration-readiness-title">
            <div className="integration-warning" role="note">
              <strong>No live integrations are connected.</strong>
              <p>Do not enter credentials here. Connectors require an authorized endpoint, least-privilege access, deployment configuration, and integration tests. None has been supplied to this workspace.</p>
            </div>
            <div className="section-heading">
              <div>
                <h2 id="integration-readiness-title">Integration readiness</h2>
                <p className="section-subtitle">Current capability versus the access and evidence required for a real deployment.</p>
              </div>
              <span className="connection-count">0 connected · {integrationReadiness.length} unavailable</span>
            </div>
            <div className="integration-grid">
              {integrationReadiness.map((integration) => (
                <article className="integration-card" key={integration.name}>
                  <div className="integration-card-heading">
                    <h3>{integration.name}</h3>
                    <span className="connection-state">NOT CONNECTED</span>
                  </div>
                  <div>
                    <span className="integration-label">CURRENT</span>
                    <p>{integration.current}</p>
                  </div>
                  <div>
                    <span className="integration-label">REQUIRED TO CONNECT</span>
                    <p>{integration.required}</p>
                  </div>
                </article>
              ))}
            </div>
          </section>
        )}

        {route === 'findings' && <FindingsPanel />}
        {route === 'incidents' && <IncidentsPanel />}
        {route === 'email' && <EmailAnalysisPanel />}
        {route === 'unidirectional' && <TrafficAnalysisPanel />}
        {route === 'bitcoin' && <BitcoinAnalysisPanel />}
        {route === 'voice' && <OfflineCapabilityPanel profileId="voice" />}
        {route === 'risk' && <OfflineCapabilityPanel profileId="risk" />}
        {route === 'forecasting' && <OfflineCapabilityPanel profileId="forecasting" />}
        {route === 'compliance' && <OfflineCapabilityPanel profileId="compliance" />}
        {route === 'identity' && <OfflineCapabilityPanel profileId="identity" />}
        {route === 'video' && <OfflineCapabilityPanel profileId="video" />}
        {route === 'ipsec' && <OfflineCapabilityPanel profileId="ipsec" />}

        <footer className="page-footer">
          <span>AMYGYX · AI-Powered Cyber Intelligence</span>
          <span>Local prototype <i /> No live telemetry or automated response</span>
        </footer>
      </main>
    </div>
  );
}
