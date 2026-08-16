import { StrictMode, Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const ThreatScene = lazy(() => import('./three/ThreatScene'));

type Impact = {
  name: string;
  value: string | number | boolean;
  impact: number;
  direction: 'positive' | 'negative' | 'neutral';
  explanation: string;
  observation: string;
  model_impact: string;
  human_interpretation: string;
};
type Scan = {
  scan_id: string;
  url: string;
  prediction: string;
  probability: number;
  risk_score: number;
  risk_level: string;
  confidence: number;
  created_at: string;
  explanation: { summary: string; method: string; features: Impact[]; risk_engine?: { uncertainty: number } };
  threat_intelligence: { provider: string; status: string; detail?: string; matched?: boolean }[];
};
type Auth = { token: string; email: string } | null;

function localApiCandidates(): string[] {
  const configured = import.meta.env.VITE_API_URL;
  const browserHost = typeof window === 'undefined' ? 'localhost' : window.location.hostname;
  const pairedHost = browserHost === '127.0.0.1' ? 'localhost' : '127.0.0.1';
  return Array.from(new Set([
    '',
    configured,
    `http://${browserHost}:8000`,
    `http://${browserHost}:8010`,
    `http://${pairedHost}:8000`,
    `http://${pairedHost}:8010`,
    'http://localhost:8000',
    'http://127.0.0.1:8000',
  ].filter(Boolean) as string[]));
}

const apiCandidates = localApiCandidates();
const INTRO_DURATION_MS = 10_000;
const INTRO_AUDIO_DURATION_MS = 14_210;
const INTRO_SILENT_FALLBACK_MS = 15_000;
const INTRO_HARD_CAP_MS = 18_000;
const INTRO_STORAGE_KEY = 'phantomtrace-intro-seen';
const INTRO_AUDIO_SRC = '/intro-voice.mp3';
const INTRO_VIDEO_SRC = '/intro-background.mp4';
const INTRO_TIMELINE = {
  brandReveal: 0.06,
  headlineReveal: 0.22,
  sceneExpansion: 0.46,
  ctaReveal: 0.76,
};

const introMoments = [
  {
    at: 0,
    label: 'PHANTOMTRACE AI',
    title: ['See the threat', 'before it', 'reaches you.'],
    text: 'AI-powered phishing detection, explainable risk analysis, and threat intelligence in one visual command surface.',
  },
  {
    at: INTRO_TIMELINE.sceneExpansion,
    label: 'AI URL DEFENSE',
    title: ['Analyze links', 'before trust', 'is assumed.'],
    text: 'Signals align. Risk surfaces. Evidence resolves.',
  },
  {
    at: INTRO_TIMELINE.ctaReveal,
    label: 'SECURE WORKSTATION',
    title: ['Paste a URL.', 'Watch the signal.', 'Decide faster.'],
    text: 'The scanner is ready.',
  },
];

const scanStages = [
  'URL normalization',
  'Domain signal review',
  'Structural feature extraction',
  'AI classification',
  'Threat-intelligence correlation',
  'Explainable verdict',
];

const threatRegions = [
  { city: 'Singapore', signal: 'Credential lure', volume: 42 },
  { city: 'Frankfurt', signal: 'Payment impersonation', volume: 31 },
  { city: 'São Paulo', signal: 'Shortener abuse', volume: 24 },
  { city: 'Mumbai', signal: 'Account verification', volume: 18 },
];

type IntroScreenProps = {
  reducedMotion: boolean;
  onComplete: (target?: 'scanner' | 'observatory') => void;
};

async function request<T>(path: string, options: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const failures: string[] = [];
  for (const api of apiCandidates) {
    try {
      const response = await fetch(api + path, { ...options, headers });
      const contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        throw new Error('API did not return JSON');
      }
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.detail || `API error ${response.status}`);
      return payload as T;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'connection failed';
      failures.push(`${api}: ${message}`);
      const retryable = message === 'Failed to fetch'
        || message.includes('NetworkError')
        || message.includes('Load failed')
        || message === 'API did not return JSON';
      if (!retryable) throw err;
    }
  }
  throw new Error(`Cannot reach PhantomTrace API. Tried ${failures.join(' | ')}`);
}

function riskColor(risk: number): string {
  if (risk >= 70) return '#d95c4a';
  if (risk >= 40) return '#e9a23b';
  return '#8fa36a';
}

function hostnameFromUrl(value: string): string {
  try {
    return new URL(value).hostname || 'pending';
  } catch {
    return 'pending';
  }
}

function IntroScreen({ reducedMotion, onComplete }: IntroScreenProps) {
  const [armed, setArmed] = useState(false);
  const [progress, setProgress] = useState(0);
  const startedAt = useRef(0);
  const durationRef = useRef(INTRO_AUDIO_DURATION_MS);
  const frame = useRef<number | null>(null);
  const completed = useRef(false);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const audioStarted = useRef(false);
  const audioStartedAt = useRef(0);

  const completeIntro = useCallback((target?: 'scanner' | 'observatory') => {
    if (completed.current) return;
    completed.current = true;
    if (frame.current) cancelAnimationFrame(frame.current);
    if (audioRef.current) {
      audioRef.current.pause();
      audioRef.current.currentTime = 0;
    }
    localStorage.setItem(INTRO_STORAGE_KEY, 'true');
    onComplete(target);
  }, [onComplete]);

  const startVisualTimer = useCallback(() => {
    if (startedAt.current) return;
    startedAt.current = performance.now();

    const tick = (now: number) => {
      const visualElapsed = now - startedAt.current;
      const audioElapsed = audioStartedAt.current ? now - audioStartedAt.current : 0;
      const activeElapsed = audioStartedAt.current ? audioElapsed : visualElapsed;
      const activeDuration = audioStartedAt.current ? durationRef.current + 750 : INTRO_SILENT_FALLBACK_MS;
      const nextProgress = Math.min(1, activeElapsed / activeDuration);
      setProgress(nextProgress);
      if (activeElapsed >= activeDuration || visualElapsed >= INTRO_HARD_CAP_MS) completeIntro();
      else frame.current = requestAnimationFrame(tick);
    };

    frame.current = requestAnimationFrame(tick);
  }, [completeIntro]);

  const playIntroAudio = useCallback(async (fromGesture = false) => {
    const audio = audioRef.current;
    if (!audio || audioStarted.current || completed.current) return;
    try {
      audio.currentTime = 0;
      audio.muted = !fromGesture;
      audio.volume = fromGesture ? 0.16 : 0.001;
      await audio.play();
      audio.muted = false;
      audioStarted.current = true;
      audioStartedAt.current = performance.now();
      const fadeStarted = performance.now();
      const fade = (now: number) => {
        if (!audio || audio.paused) return;
        const ratio = Math.min(1, (now - fadeStarted) / 1200);
        audio.volume = (fromGesture ? 0.16 : 0.001) + ratio * (fromGesture ? 0.5 : 0.58);
        if (ratio < 1) requestAnimationFrame(fade);
      };
      requestAnimationFrame(fade);
    } catch {
      // Audible autoplay may be blocked. The cinematic intro continues and
      // playback is retried once the browser receives a user gesture.
    }
  }, []);

  useEffect(() => {
    if (!armed) return undefined;
    startVisualTimer();
    if (!reducedMotion) playIntroAudio();

    const retryAudio = () => {
      playIntroAudio();
      window.removeEventListener('pointerdown', retryAudio);
      window.removeEventListener('keydown', retryAudio);
      window.removeEventListener('touchstart', retryAudio);
    };
    window.addEventListener('pointerdown', retryAudio, { once: true });
    window.addEventListener('keydown', retryAudio, { once: true });
    window.addEventListener('touchstart', retryAudio, { once: true });

    return () => {
      if (frame.current) cancelAnimationFrame(frame.current);
      audioRef.current?.pause();
      window.removeEventListener('pointerdown', retryAudio);
      window.removeEventListener('keydown', retryAudio);
      window.removeEventListener('touchstart', retryAudio);
    };
  }, [armed, playIntroAudio, reducedMotion, startVisualTimer]);

  const currentMoment = introMoments.reduce((active, moment) => progress >= moment.at ? moment : active, introMoments[0]);

  return (
    <section className="intro-overlay" aria-label="PhantomTrace AI introduction" style={{ '--intro-progress': progress } as React.CSSProperties}>
      <audio
        ref={audioRef}
        src={INTRO_AUDIO_SRC}
        preload="auto"
        playsInline
        onLoadedMetadata={(event) => {
          const mediaDuration = event.currentTarget.duration;
          durationRef.current = Number.isFinite(mediaDuration) && mediaDuration > 1
            ? Math.min(INTRO_HARD_CAP_MS - 1000, Math.max(8000, mediaDuration * 1000))
            : INTRO_AUDIO_DURATION_MS;
        }}
        onTimeUpdate={(event) => {
          const mediaDuration = event.currentTarget.duration;
          if (Number.isFinite(mediaDuration) && mediaDuration > 1 && event.currentTarget.currentTime >= mediaDuration - 0.12) {
            completeIntro();
          }
        }}
        onStalled={() => {
          durationRef.current = Math.min(durationRef.current, INTRO_SILENT_FALLBACK_MS);
        }}
        onEnded={() => completeIntro()}
      />
      <video className="intro-video" src={INTRO_VIDEO_SRC} autoPlay muted loop playsInline preload="auto" aria-hidden="true" />
      <div className="intro-shell" aria-hidden="true" />
      <div className="intro-depth-field" aria-hidden="true">
        <i />
        <i />
        <i />
      </div>
      <div className="intro-panel">
        <div className="intro-mini-nav">
          <span><b>◇</b> PhantomTrace AI</span>
        </div>
        {!armed ? (
          <div className="intro-gate">
            <h2>Enter PhantomTrace</h2>
            <p>Launch the cinematic threat-intelligence intro with full narration.</p>
            <button
              type="button"
              onClick={() => {
                setArmed(true);
                requestAnimationFrame(() => playIntroAudio(true));
              }}
            >
              Enter experience
            </button>
          </div>
        ) : (
          <>
            <div className="intro-copy">
              <span className="eyebrow">{currentMoment.label}</span>
              <h2 key={currentMoment.label}>
                {currentMoment.title.map((line) => <span key={line}>{line}</span>)}
              </h2>
              <p>{currentMoment.text}</p>
            </div>
            <div className="intro-system-caption" aria-hidden="true">
              <span>URL SIGNALS</span>
              <span>MODEL CONFIDENCE</span>
              <span>THREAT MEMORY</span>
            </div>
            <div className="intro-cta">
              <button type="button" onClick={() => completeIntro('scanner')}>Start analysis</button>
              <button type="button" onClick={() => completeIntro('observatory')}>Explore intelligence</button>
            </div>
          </>
        )}
      </div>
    </section>
  );
}

function App() {
  const [url, setUrl] = useState('https://example.com/login');
  const [scan, setScan] = useState<Scan | null>(null);
  const [history, setHistory] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [tab, setTab] = useState<'scanner' | 'observatory'>('scanner');
  const [auth, setAuth] = useState<Auth>(() => {
    const raw = localStorage.getItem('phantomtrace-auth');
    return raw ? JSON.parse(raw) as Auth : null;
  });
  const [email, setEmail] = useState('analyst@local.test');
  const [password, setPassword] = useState('change-me-12345');
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const [showIntro, setShowIntro] = useState(() => localStorage.getItem(INTRO_STORAGE_KEY) !== 'true');

  const loadHistory = async (token = auth?.token) => {
    if (!token) return setHistory([]);
    const payload = await request<{ items: Scan[] }>('/api/v1/scans', {}, token);
    setHistory(payload.items);
  };

  const authenticate = async (mode: 'login' | 'register') => {
    setError('');
    try {
      const payload = await request<{ access_token: string }>(`/api/v1/auth/${mode}`, {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      const next = { token: payload.access_token, email };
      localStorage.setItem('phantomtrace-auth', JSON.stringify(next));
      setAuth(next);
      await loadHistory(next.token);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication unavailable');
    }
  };

  const run = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      const result = await request<Scan>('/api/v1/analyze', {
        method: 'POST',
        body: JSON.stringify({ url, include_threat_intelligence: true }),
      }, auth?.token);
      setScan(result);
      if (auth) await loadHistory(auth.token);
      else setHistory((items) => [result, ...items].slice(0, 8));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis unavailable');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (auth?.token) loadHistory(auth.token).catch(() => setHistory([]));
  }, []);

  useEffect(() => {
    navigator.serviceWorker?.register('/sw.js').catch(() => undefined);
  }, []);

  const risk = scan?.risk_score ?? 20;
  const activeHost = hostnameFromUrl(scan?.url || url);
  const topFeatures = scan?.explanation.features.slice(0, 4) ?? [];
  const signalCards = [
    { label: 'Threat score', value: `${risk.toFixed(0)}/100`, tone: risk >= 70 ? 'critical' : risk >= 40 ? 'warning' : 'safe' },
    { label: 'Domain', value: activeHost, tone: 'info' },
    { label: 'AI confidence', value: scan ? `${(scan.confidence * 100).toFixed(0)}%` : 'Awaiting scan', tone: 'info' },
    { label: 'Intel providers', value: scan ? String(scan.threat_intelligence.length) : 'Standby', tone: 'info' },
  ];
  const aggregates = useMemo(() => {
    const total = history.length || 1;
    const high = history.filter((item) => item.risk_score >= 60).length;
    const avg = history.reduce((sum, item) => sum + item.risk_score, 0) / total;
    return { total: history.length, high, avg };
  }, [history]);

  return (
    <main>
      {showIntro && <IntroScreen reducedMotion={reducedMotion} onComplete={(target) => { if (target) setTab(target); setShowIntro(false); }} />}
      <header>
        <div className="mark">PT</div>
        <div>
          <h1>PHANTOMTRACE <i>AI</i></h1>
          <p>AI-powered phishing detection & explainable threat intelligence</p>
        </div>
        <nav aria-label="Primary">
          <button className={tab === 'scanner' ? 'active' : ''} onClick={() => setTab('scanner')}>Analyze URL</button>
          <button className={tab === 'observatory' ? 'active' : ''} onClick={() => setTab('observatory')}>Threat Intel</button>
          <a href="#evidence">Evidence</a>
        </nav>
      </header>

      <section className="auth-strip" aria-label="Authentication">
        <span>{auth ? `Signed in as ${auth.email}` : 'Anonymous scans run, but saved history requires sign-in.'}</span>
        {!auth ? (
          <div>
            <input value={email} onChange={(event) => setEmail(event.target.value)} aria-label="Email" />
            <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" aria-label="Password" />
            <button onClick={() => authenticate('login')}>Log in</button>
            <button onClick={() => authenticate('register')}>Register</button>
          </div>
        ) : (
          <button onClick={() => { localStorage.removeItem('phantomtrace-auth'); setAuth(null); setHistory([]); }}>Sign out</button>
        )}
      </section>

      {tab === 'scanner' ? (
        <>
          <section className="hero">
            <div className="intro">
              <span className="eyebrow">01 / AI URL DEFENSE WORKSTATION</span>
              <h2>See the <em>threat</em> before it reaches you.</h2>
              <p>Analyze suspicious URLs with local feature extraction, explainable AI scoring, and threat-intelligence correlation. Submitted destinations are parsed as strings; the server does not open pages or execute remote JavaScript.</p>
              <div className="credibility" aria-label="Platform capabilities">
                <span>AI-powered analysis</span>
                <span>Explainable verdicts</span>
                <span>Global threat visibility</span>
                <span>Privacy-conscious scanning</span>
              </div>
              <form onSubmit={run}>
                <label htmlFor="url">Target URL</label>
                <div className="inputrow">
                  <input id="url" value={url} onChange={(event) => setUrl(event.target.value)} inputMode="url" />
                  <button disabled={loading}>{loading ? 'ANALYZING...' : 'Analyze'}</button>
                </div>
                <small>http/https only. Private networks, credentials, control characters, and unsafe schemes are blocked.</small>
              </form>
              {error && <p role="alert" className="error">{error}</p>}
              <div className="quick-actions">
                <button type="button" onClick={() => setUrl('https://example.com/login')}>Use safe demo</button>
                <button type="button" onClick={() => setUrl('https://paypal.security-check.example-login.com/account/verify?redirect=https%3A%2F%2Fpaypal.com')}>Use suspicious demo</button>
              </div>
            </div>
            <div className="command-visual">
              <div className="signal">
                <Suspense fallback={<div className="fallback">3D loading</div>}>
                  <ThreatScene risk={risk} reducedMotion={reducedMotion} points={history.map((item) => item.risk_score)} />
                </Suspense>
                <span>Risk signal<br /><b style={{ color: riskColor(risk) }}>{risk.toFixed(1)}</b>/100</span>
              </div>
              <div className="floating-cards" aria-label="Current scan signals">
                {signalCards.map((card) => (
                  <article key={card.label} className={card.tone}>
                    <span>{card.label}</span>
                    <b>{card.value}</b>
                  </article>
                ))}
              </div>
            </div>
          </section>

          <section className="scan-console" aria-label="Real-time scan workflow">
            <div>
              <span className="eyebrow">LIVE ANALYSIS PIPELINE</span>
              <h2>From raw link to explainable verdict.</h2>
            </div>
            <ol>
              {scanStages.map((stage, index) => (
                <li key={stage} className={loading || scan ? 'active' : ''}>
                  <span>{String(index + 1).padStart(2, '0')}</span>
                  <b>{stage}</b>
                  <small>{loading ? 'Running' : scan ? 'Completed' : 'Ready'}</small>
                </li>
              ))}
            </ol>
          </section>

          {scan ? (
            <section className="result" id="evidence" aria-live="polite">
              <div className="verdict">
                <span className="eyebrow">ASSESSMENT / {scan.risk_level}</span>
                <h2 className={scan.prediction}>{scan.prediction}</h2>
                <p>{scan.explanation.summary}</p>
                <dl>
                  <div><dt>Model probability</dt><dd>{(scan.probability * 100).toFixed(1)}%</dd></div>
                  <div><dt>Confidence</dt><dd>{(scan.confidence * 100).toFixed(0)}%</dd></div>
                  <div><dt>Explainability</dt><dd>{scan.explanation.method}</dd></div>
                  <div><dt>Normalized host</dt><dd>{activeHost}</dd></div>
                </dl>
                <div className="intel-grid">
                  {scan.threat_intelligence.map((item) => (
                    <article key={item.provider}>
                      <span>{item.provider}</span>
                      <b>{item.status}</b>
                      <small>{item.detail || (item.matched ? 'Threat match reported.' : 'No verified match reported.')}</small>
                    </article>
                  ))}
                </div>
              </div>
              <div className="findings">
                <span className="eyebrow">EXPLAINABILITY / FEATURE IMPACT</span>
                {topFeatures.map((feature) => (
                  <article key={feature.name}>
                    <div><strong>{feature.name.replaceAll('_', ' ')}</strong><span>{String(feature.value)}</span></div>
                    <div className="bar"><i style={{ width: `${Math.min(100, Math.abs(feature.impact) * 180)}%`, background: feature.direction === 'negative' ? '#8fa36a' : '#d95c4a' }} /></div>
                    <p>{feature.explanation}</p>
                  </article>
                ))}
                <table className="sr-table">
                  <caption>Screen-reader feature impact table</caption>
                  <thead><tr><th>Feature</th><th>Value</th><th>Impact</th><th>Direction</th></tr></thead>
                  <tbody>{scan.explanation.features.map((feature) => <tr key={feature.name}><td>{feature.name}</td><td>{String(feature.value)}</td><td>{feature.impact}</td><td>{feature.direction}</td></tr>)}</tbody>
                </table>
                <p className="intel">Complete model evidence is preserved in the accessible table. Top visual cards show the strongest feature contributions.</p>
              </div>
            </section>
          ) : (
            <section className="empty" id="evidence">
              <span>Awaiting a target URL.</span>
              <p>Your verdict, model confidence, threat-intelligence notes, and feature contributions will appear here after analysis.</p>
              <div className="empty-grid">
                <article><b>01</b><span>Paste suspicious URL</span></article>
                <article><b>02</b><span>Run local feature extraction</span></article>
                <article><b>03</b><span>Review explainable verdict</span></article>
              </div>
            </section>
          )}
        </>
      ) : (
        <section className="observatory">
          <div>
            <span className="eyebrow">02 / THREAT OBSERVATORY</span>
            <h2>Global threat intelligence view</h2>
            <p>Operational view for recent scan pressure, regional phishing patterns, and historical risk movement. Aggregates are derived from saved scans for the signed-in analyst.</p>
          </div>
          <div className="metrics">
            <article><span>Total scans</span><b>{aggregates.total}</b></article>
            <article><span>High risk</span><b>{aggregates.high}</b></article>
            <article><span>Average risk</span><b>{aggregates.avg.toFixed(1)}</b></article>
          </div>
          <div className="threat-map" aria-label="Accessible threat map summary">
            {threatRegions.map((region) => (
              <article key={region.city}>
                <span>{region.city}</span>
                <b>{region.signal}</b>
                <i style={{ width: `${region.volume}%` }} />
              </article>
            ))}
          </div>
          <Suspense fallback={<div className="fallback">Observatory loading</div>}>
            <div className="wide-scene"><ThreatScene risk={aggregates.avg || 20} reducedMotion={reducedMotion} points={history.map((item) => item.risk_score)} /></div>
          </Suspense>
        </section>
      )}

      <section className="history">
        <span className="eyebrow">RECENT EVIDENCE</span>
        <h2>Scan history</h2>
        {history.length ? (
          <ol>{history.map((item) => <li key={item.scan_id}><span className={`dot ${item.prediction}`} /><code>{item.url}</code><b>{item.risk_score.toFixed(0)}</b><time>{new Date(item.created_at).toLocaleString()}</time></li>)}</ol>
        ) : (
          <p>{auth ? 'Your threat history will appear here after your first URL analysis.' : 'Sign in to persist history across sessions.'}</p>
        )}
      </section>
      <footer>
        PHANTOMTRACE AI · Local URL analysis · Accessible 2D evidence mirrors the WebGL view
        <button className="replay" type="button" onClick={() => { localStorage.removeItem(INTRO_STORAGE_KEY); setShowIntro(true); }}>Replay intro</button>
      </footer>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
