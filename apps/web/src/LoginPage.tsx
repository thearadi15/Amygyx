import { useState, useEffect, useRef } from 'react';

interface LoginPageProps {
  onLogin: (user: { name: string; email: string; role: string; tenant: string }) => void;
}

const ADMIN_DEV_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDMiLCJ0ZW5hbnRfaWQiOiIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJlbWFpbCI6ImFkbWluQGFteWd5eC5pbyIsInJvbGUiOiJhZG1pbiIsImlzcyI6ImNpcC1sb2NhbCIsImF1ZCI6ImNpcCIsImlhdCI6MTc5MjA0ODE0MCwibmJmIjoxNzkyMDQ4MTQwLCJleHAiOjE3OTIwNTE3NDB9.5TcEZlT32H26_Do23xEfuZ_3IVBdbzvdvZ6aaJI37hU';
const ANALYST_DEV_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDIiLCJ0ZW5hbnRfaWQiOiIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLCJlbWFpbCI6ImFuYWx5c3RAc3ludGhldGljLmV4YW1wbGUudGVzdCIsInJvbGUiOiJhbmFseXN0IiwiaXNzIjoiY2lwLWxvY2FsIiwiYXVkIjoiY2lwIiwiaWF0IjoxNzkyMDQ4MTQwLCJuYmYiOjE3OTIwNDgxNDAsImV4cCI6MTc5MjA1MTc0MH0.FBeQs4Fc0nwMJZ-f0abG9a1e-SsZ_Pm9_4f0CnsHTO8';

/* Demo credentials with genuine signed API access tokens */
const DEMO_USERS: Record<string, { password: string; name: string; role: string; tenant: string; token: string }> = {
  'admin@amygyx.io': { password: 'Admin@2026', name: 'Arjun Sharma', role: 'SOC Analyst — L3', tenant: 'NTRO-GOV-01', token: ADMIN_DEV_TOKEN },
  'analyst@amygyx.io': { password: 'Analyst@2026', name: 'Priya Mehta', role: 'Threat Intelligence', tenant: 'CERT-IN-02', token: ANALYST_DEV_TOKEN },
  'demo@amygyx.io': { password: 'Demo@2026', name: 'Demo User', role: 'Read-Only Viewer', tenant: 'SANDBOX-00', token: ANALYST_DEV_TOKEN },
};

/* Animated threat globe canvas */
function ThreatGlobe() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const W = canvas.width = 520;
    const H = canvas.height = 520;
    const cx = W / 2, cy = H / 2;

    type Node = { x: number; y: number; vx: number; vy: number; r: number; color: string; pulse: number };
    const nodes: Node[] = Array.from({ length: 22 }, () => {
      const angle = Math.random() * Math.PI * 2;
      const radius = 80 + Math.random() * 140;
      return {
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
        vx: (Math.random() - 0.5) * 0.35,
        vy: (Math.random() - 0.5) * 0.35,
        r: 2.5 + Math.random() * 4,
        color: ['#49e2c2', '#178fbb', '#f0a840', '#e05b5b', '#8b7cf8'][Math.floor(Math.random() * 5)],
        pulse: Math.random() * Math.PI * 2,
      };
    });

    let animId: number;
    let tick = 0;

    function draw() {
      ctx!.clearRect(0, 0, W, H);
      tick++;

      /* grid */
      ctx!.strokeStyle = 'rgba(30,60,80,0.18)';
      ctx!.lineWidth = 0.5;
      for (let i = 0; i < W; i += 38) { ctx!.beginPath(); ctx!.moveTo(i, 0); ctx!.lineTo(i, H); ctx!.stroke(); }
      for (let i = 0; i < H; i += 38) { ctx!.beginPath(); ctx!.moveTo(0, i); ctx!.lineTo(W, i); ctx!.stroke(); }

      /* globe rings */
      [160, 115, 70].forEach((r, idx) => {
        ctx!.beginPath();
        ctx!.arc(cx, cy, r, 0, Math.PI * 2);
        ctx!.strokeStyle = `rgba(42,200,170,${0.08 + idx * 0.04})`;
        ctx!.lineWidth = 0.8;
        ctx!.stroke();
      });

      /* pulsing outer ring */
      const pulseR = 170 + Math.sin(tick * 0.03) * 8;
      ctx!.beginPath();
      ctx!.arc(cx, cy, pulseR, 0, Math.PI * 2);
      ctx!.strokeStyle = 'rgba(73,226,194,0.06)';
      ctx!.lineWidth = 1.5;
      ctx!.stroke();

      /* move nodes */
      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy; n.pulse += 0.04;
        const dx = n.x - cx, dy = n.y - cy;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist > 185 || dist < 50) { n.vx *= -1; n.vy *= -1; }
      }

      /* edges */
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 120) {
            ctx!.beginPath();
            ctx!.moveTo(nodes[i].x, nodes[i].y);
            ctx!.lineTo(nodes[j].x, nodes[j].y);
            ctx!.strokeStyle = `rgba(73,226,194,${0.6 * (1 - d / 120) * 0.35})`;
            ctx!.lineWidth = 0.6;
            ctx!.stroke();
          }
        }
      }

      /* nodes */
      for (const n of nodes) {
        const pulseSize = n.r + Math.sin(n.pulse) * 1.5;
        ctx!.beginPath();
        ctx!.arc(n.x, n.y, pulseSize + 5, 0, Math.PI * 2);
        ctx!.fillStyle = n.color + '22';
        ctx!.fill();
        ctx!.beginPath();
        ctx!.arc(n.x, n.y, pulseSize, 0, Math.PI * 2);
        ctx!.fillStyle = n.color;
        ctx!.fill();
      }

      /* centre core */
      const grad = ctx!.createRadialGradient(cx, cy, 0, cx, cy, 48);
      grad.addColorStop(0, 'rgba(22,74,72,0.9)');
      grad.addColorStop(1, 'rgba(13,32,41,0.6)');
      ctx!.beginPath(); ctx!.arc(cx, cy, 48, 0, Math.PI * 2);
      ctx!.fillStyle = grad; ctx!.fill();
      ctx!.strokeStyle = 'rgba(73,226,194,0.55)'; ctx!.lineWidth = 1;
      ctx!.beginPath(); ctx!.arc(cx, cy, 48, 0, Math.PI * 2); ctx!.stroke();
      ctx!.fillStyle = '#90f1df'; ctx!.font = 'bold 13px "DM Mono", monospace';
      ctx!.textAlign = 'center'; ctx!.textBaseline = 'middle';
      ctx!.fillText('CIP', cx, cy - 6);
      ctx!.fillStyle = '#5a8a80'; ctx!.font = '7px "DM Mono", monospace';
      ctx!.fillText('AMYGYX', cx, cy + 10);

      animId = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(animId);
  }, []);

  return <canvas ref={canvasRef} style={{ width: 260, height: 260 }} />;
}

export default function LoginPage({ onLogin }: LoginPageProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [mfaStep, setMfaStep] = useState(false);
  const [mfaCode, setMfaCode] = useState('');
  const [pendingUser, setPendingUser] = useState<{ name: string; email: string; role: string; tenant: string } | null>(null);

  const statCards = [
    { label: 'Threats Blocked', value: '3,847', icon: '🛡️' },
    { label: 'AI Modules Active', value: '10 / 10', icon: '🤖' },
    { label: 'Avg Detection Time', value: '1.2s', icon: '⚡' },
    { label: 'SOC2 Certified', value: 'Active', icon: '✅' },
  ];

  function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      const user = DEMO_USERS[email.toLowerCase()];
      if (!user || user.password !== password) {
        setError('Invalid credentials. Try demo@amygyx.io / Demo@2026');
        return;
      }
      setPendingUser({ name: user.name, email, role: user.role, tenant: user.tenant });
      setMfaStep(true);
    }, 1200);
  }

  function handleMfa(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    if (mfaCode !== '123456' && mfaCode !== '000000') {
      setError('Invalid MFA code. Use 123456 for demo.');
      return;
    }
    if (pendingUser) {
      const match = DEMO_USERS[pendingUser.email.toLowerCase()];
      if (match) {
        localStorage.setItem('cip_access_token', match.token);
      }
      localStorage.setItem('cip_user', JSON.stringify(pendingUser));
      onLogin(pendingUser);
    }
  }

  function handleSSO() {
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      const ssoUser = { name: 'SSO User', email: 'sso@amygyx.io', role: 'SSO Analyst', tenant: 'AZURE-AD-01' };
      localStorage.setItem('cip_access_token', ADMIN_DEV_TOKEN);
      localStorage.setItem('cip_user', JSON.stringify(ssoUser));
      onLogin(ssoUser);
    }, 1400);
  }

  return (
    <div className="login-root">
      {/* Left panel */}
      <div className="login-left">
        <div className="login-card">
          <div className="login-logo">
            <div className="login-brand-mark">A</div>
            <div>
              <div className="login-brand-name">AMYGYX</div>
              <div className="login-brand-sub">Cyber Intelligence Platform</div>
            </div>
          </div>

          {!mfaStep ? (
            <>
              <p className="login-welcome">Welcome back. Sign in to your SOC workspace.</p>
              <form onSubmit={handleLogin} className="login-form">
                <div className="login-field">
                  <label htmlFor="lf-email">Email address</label>
                  <input
                    id="lf-email"
                    type="email"
                    autoComplete="email"
                    placeholder="analyst@amygyx.io"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    required
                  />
                </div>
                <div className="login-field">
                  <label htmlFor="lf-pwd">Password</label>
                  <div className="pwd-wrap">
                    <input
                      id="lf-pwd"
                      type={showPwd ? 'text' : 'password'}
                      autoComplete="current-password"
                      placeholder="••••••••••"
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      required
                    />
                    <button type="button" className="pwd-toggle" onClick={() => setShowPwd(v => !v)} tabIndex={-1}>
                      {showPwd ? '🙈' : '👁️'}
                    </button>
                  </div>
                </div>
                <div className="login-options">
                  <label className="remember-me">
                    <input type="checkbox" /> Remember this device
                  </label>
                  <a href="#forgot" className="forgot-link" onClick={e => e.preventDefault()}>Forgot password?</a>
                </div>
                {error && <div className="login-error">{error}</div>}
                <button type="submit" className="login-btn" disabled={loading}>
                  {loading ? <span className="spin">⟳</span> : '→'}&nbsp;
                  {loading ? 'Authenticating…' : 'Sign In'}
                </button>
              </form>
              <div className="sso-divider"><span>or continue with SSO</span></div>
              <button className="sso-btn" onClick={handleSSO} disabled={loading}>
                <svg width="18" height="18" viewBox="0 0 21 21"><rect width="10" height="10" fill="#F25022"/><rect x="11" width="10" height="10" fill="#7FBA00"/><rect y="11" width="10" height="10" fill="#00A4EF"/><rect x="11" y="11" width="10" height="10" fill="#FFB900"/></svg>
                Sign in with Microsoft
              </button>
              <div className="login-footer-note">
                🔒 Access restricted to authorised personnel. All sessions are audited and encrypted (TLS 1.3).
              </div>
            </>
          ) : (
            <>
              <div className="mfa-badge">🔐 Multi-Factor Authentication</div>
              <p className="login-welcome">We sent a 6-digit code to <strong>{pendingUser?.email}</strong>. Enter it below to continue.</p>
              <p style={{ fontSize: 10, color: '#5a7a6a', margin: '-8px 0 18px' }}>Demo: use code <code style={{ color: '#49e2c2' }}>123456</code></p>
              <form onSubmit={handleMfa} className="login-form">
                <div className="login-field">
                  <label htmlFor="lf-mfa">Authentication Code</label>
                  <input
                    id="lf-mfa"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    placeholder="000000"
                    value={mfaCode}
                    onChange={e => setMfaCode(e.target.value.replace(/\D/g, ''))}
                    autoFocus
                    required
                    style={{ textAlign: 'center', letterSpacing: '0.4em', fontSize: 20 }}
                  />
                </div>
                {error && <div className="login-error">{error}</div>}
                <button type="submit" className="login-btn">Verify & Enter →</button>
                <button type="button" className="sso-btn" style={{ marginTop: 8 }} onClick={() => { setMfaStep(false); setMfaCode(''); setError(''); }}>← Back to login</button>
              </form>
            </>
          )}
        </div>
        <div className="login-compliance">
          <span>SOC 2 Type II</span><span>ISO 27001</span><span>DPDPA Compliant</span><span>CERT-In Ready</span>
        </div>
      </div>

      {/* Right panel */}
      <div className="login-right">
        <div className="login-globe-wrap">
          <ThreatGlobe />
        </div>
        <div className="login-stats-grid">
          {statCards.map(s => (
            <div className="login-stat-card" key={s.label}>
              <div className="login-stat-icon">{s.icon}</div>
              <div className="login-stat-value">{s.value}</div>
              <div className="login-stat-label">{s.label}</div>
            </div>
          ))}
        </div>
        <p className="login-right-tagline">
          AI-Powered Threat Intelligence · 10 SIH 2026 Modules · Real-Time Detection
        </p>
      </div>
    </div>
  );
}
