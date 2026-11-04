import { useState, useEffect, useRef } from 'react';

interface LoginPageProps {
  onLogin: (user: { name: string; email: string; role: string; tenant: string }) => void;
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

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
  const [accessToken, setAccessToken] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const statCards = [
    { label: 'Analysis surfaces', value: '10', icon: '◎' },
    { label: 'API mode', value: 'Local / OIDC', icon: '◈' },
    { label: 'Findings', value: 'Tenant-scoped', icon: '◇' },
    { label: 'Data handling', value: 'Bounded uploads', icon: '⌁' },
  ];

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/auth/me`, {
        headers: { Authorization: `Bearer ${accessToken.trim()}` },
      });
      if (!response.ok) {
        throw new Error(response.status === 401 ? 'The access token was rejected by the API.' : 'Unable to validate the access token.');
      }
      const member = await response.json();
      const user = {
        name: member.email?.split('@')[0] ?? 'Authenticated analyst',
        email: member.email,
        role: member.role,
        tenant: member.tenant_id,
      };
      localStorage.setItem('cip_access_token', accessToken.trim());
      localStorage.setItem('cip_user', JSON.stringify(user));
      onLogin(user);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-root">
      <div className="login-left">
        <div className="login-card">
          <div className="login-logo">
            <div className="login-brand-mark">A</div>
            <div>
              <div className="login-brand-name">AMYGYX</div>
              <div className="login-brand-sub">Cyber Intelligence Platform</div>
            </div>
          </div>
          <p className="login-welcome">Sign in with an API access token issued by your configured identity provider.</p>
          <form onSubmit={handleLogin} className="login-form">
            <div className="login-field">
              <label htmlFor="lf-token">Access token</label>
              <input
                id="lf-token"
                type="password"
                autoComplete="off"
                placeholder="Paste an access token"
                value={accessToken}
                onChange={(event) => setAccessToken(event.target.value)}
                required
              />
            </div>
            {error && <div className="login-error">{error}</div>}
            <button type="submit" className="login-btn" disabled={loading || !accessToken.trim()}>
              {loading ? 'Validating…' : 'Continue →'}
            </button>
          </form>
          <div className="login-footer-note">
            🔒 Tokens are validated by the API. Development tokens are for local use only.
          </div>
        </div>
        <div className="login-compliance">
          <span>Tenant-scoped</span><span>Audit enabled</span><span>Offline-capable</span>
        </div>
      </div>

      <div className="login-right">
        <div className="login-globe-wrap"><ThreatGlobe /></div>
        <div className="login-stats-grid">
          {statCards.map((stat) => (
            <div className="login-stat-card" key={stat.label}>
              <div className="login-stat-icon">{stat.icon}</div>
              <div className="login-stat-value">{stat.value}</div>
              <div className="login-stat-label">{stat.label}</div>
            </div>
          ))}
        </div>
        <p className="login-right-tagline">
          AI-Powered Cyber Intelligence · Rules, statistical models, and integrations
        </p>
      </div>
    </div>
  );
}
