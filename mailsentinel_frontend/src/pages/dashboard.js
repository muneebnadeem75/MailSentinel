import React, { useEffect, useState, useRef, useCallback } from "react";
import "../styles/Dashboard.css";
import "../styles/ScanLog.css";

function Dashboard() {
  const [emails, setEmails]           = useState([]);
  const [selected, setSelected]       = useState(null);
  const [loading, setLoading]         = useState(true);
  const [scanning, setScanning]       = useState(false);
  const [activeTab, setActiveTab]     = useState("inbox");
  const [spamming, setSpamming]       = useState(false);
  const [bodyCache, setBodyCache]     = useState({});
  const [loadingBody, setLoadingBody] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [scanLogs, setScanLogs]       = useState([]);
  const [pdfLoading, setPdfLoading]   = useState(false);
  const intervalRef  = useRef(null);
  const intervalMs   = useRef(10000);

  async function handleLogout() {
    await fetch('/auth/logout/', { credentials: 'include' }).catch(() => {});
    window.location.href = '/';
  }

  const errorCount = useRef(0);
  
  const fetchEmails = useCallback(async () => {
    // Request scanned email data from the Django backend.
    try {
      const res = await fetch("/auth/emails/", { credentials: "include" });
  // Slow down refresh if Gmail/API quota is hit.
      if (res.status === 429) {
        intervalMs.current = 20000;
        clearInterval(intervalRef.current);
        intervalRef.current = setInterval(fetchEmails, intervalMs.current);
        console.warn('[MailSentinel] Gmail quota hit -- backing off to 20s refresh');
        return;
      }

      if (!res.ok) {
        throw new Error('HTTP ' + res.status);
      }

      // Store email data in React state.
      const data = await res.json();
      if (Array.isArray(data)) {
        setEmails(data);
        setLastRefresh(new Date().toLocaleTimeString());
        errorCount.current = 0;
        intervalMs.current = 10000;
      }
    } catch (e) {
      // Back off if repeated errors occur.
      errorCount.current += 1;
      console.error('[MailSentinel] Fetch error #' + errorCount.current + ':', e.message);

      if (errorCount.current >= 3 && intervalMs.current < 30000) {
        intervalMs.current = 30000;
        clearInterval(intervalRef.current);
        intervalRef.current = setInterval(fetchEmails, intervalMs.current);
        console.warn('[MailSentinel] Backend unreachable -- backing off to 30s refresh');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const init = setTimeout(() => {
      fetchEmails();
      intervalRef.current = setInterval(fetchEmails, intervalMs.current);
    }, 1000);
    return () => { clearTimeout(init); clearInterval(intervalRef.current); };
  }, [fetchEmails]);

  async function handleScanAll() {
    setScanning(true);
    setScanLogs([{ text: '[INFO] Scan All triggered — clearing cache and re-analyzing...', type: 'info' }]);
    try {
      await fetch('/auth/clear-cache/', { method: 'POST', credentials: 'include' });
      setBodyCache({});
      await fetchEmails();

      if (selected !== null) {
        setScanLogs([{ text: '[INFO] Re-scan complete — refreshing analysis...', type: 'info' }]);
      } else {
        setScanLogs([]);
      }
    } finally {
      setScanning(false);
    }
  }

  async function selectEmail(sortedIndex) {
    setSelected(sortedIndex);
    setScanLogs([]);
    const email = sortedEmails[sortedIndex];
    if (!email) return;

    const checks = email.security_checks || [];

    if (checks.length > 0) {
      const ICON = { pass: '[PASS]', warn: '[WARN]', fail: '[FAIL]' };
      setScanLogs([{ text: '[ENGINE] MailSentinel Security Engine — analyzing email...', type: 'info' }]);
      for (let i = 0; i < checks.length; i++) {
        await new Promise(r => setTimeout(r, 250));
        const c = checks[i];
        const icon = ICON[c.status] || '[INFO]';
        setScanLogs(prev => [...prev, {
          text: icon + '  [' + c.name + ']  ' + c.detail,
          type: c.status,
        }]);
      }
      await new Promise(r => setTimeout(r, 350));
      const riskLabel = { safe: '[SAFE]', suspicious: '[SUSPICIOUS]', danger: '[DANGER]' };
      const em = riskLabel[email.risk] || '[UNKNOWN]';

      setScanLogs(prev => [...prev, {
        text: em + '  VERDICT: ' + (email.risk || 'unknown').toUpperCase() + '  |  Score: ' + (email.risk_score ?? 0) + '/100',
        type: 'verdict',
      }]);
    } else {
      setScanLogs([{ text: '[INFO] Not scanned yet — click Scan All to run analysis', type: 'info' }]);
    }

    if (bodyCache[email.id]) return;
    setLoadingBody(true);
    try {
      const res  = await fetch('/auth/email/' + email.id + '/', { credentials: 'include' });
      const data = await res.json();
      setBodyCache(prev => ({ ...prev, [email.id]: data }));
    } catch (e) {
      console.error('Body fetch failed:', e);
    } finally {
      setLoadingBody(false);
    }
  }

  async function handleMarkSpam(emailId) {
    setSpamming(true);
    try {
      const res = await fetch(`/auth/mark-spam/${emailId}/`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(`Failed to mark as spam: ${err.error || res.status}\n\nTip: Log out and log back in to refresh your permissions.`);
        return;
      }
      setEmails(prev => prev.map(e =>
        e.id === emailId ? { ...e, is_spam: true } : e
      ));
      setSelected(null);
      setActiveTab('spam');
    } catch (e) {
      alert('Network error — could not reach server.');
      console.error('Mark spam failed:', e);
    } finally {
      setSpamming(false);
    }
  }

  async function handleUnmarkSpam(emailId) {
    setSpamming(true);
    try {
      const res = await fetch(`/auth/unmark-spam/${emailId}/`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(`Failed to restore email: ${err.error || res.status}\n\nTip: Log out and log back in to refresh your permissions.`);
        return;
      }
      setEmails(prev => prev.map(e =>
        e.id === emailId ? { ...e, is_spam: false } : e
      ));
      setSelected(null);
      setActiveTab('inbox');
    } catch (e) {
      alert('Network error — could not reach server.');
      console.error('Unmark spam failed:', e);
    } finally {
      setSpamming(false);
    }
  }

  function getName(from = "") {
    const match = from.match(/^(.*?)</);
    return match ? match[1].trim() : from;
  }

  function getEmail(from = "") {
    const match = from.match(/<(.*)>/);
    return match ? match[1] : from;
  }

  function getInitial(from = "") {
    return getName(from).charAt(0).toUpperCase() || "?";
  }

  function avatarColor(from = "") {
    const colors = ["#6366f1","#8b5cf6","#ec4899","#06b6d4","#10b981","#f59e0b","#ef4444"];
    let h = 0;
    for (let c of from) h = (h * 31 + c.charCodeAt(0)) % colors.length;
    return colors[h];
  }

  function getRisk(email) {
    return email.risk || "pending";
  }

  function parseEmailDate(dateStr) {
    if (!dateStr) return new Date(0);
    return new Date(dateStr);
  }

  function formatDate(dateStr) {
    const d = parseEmailDate(dateStr);
    if (isNaN(d)) return dateStr || '';
    const now    = new Date();
    const diffMs = now - d;
    const diffM  = Math.floor(diffMs / 60000);
    const diffH  = Math.floor(diffMs / 3600000);
    const diffD  = Math.floor(diffMs / 86400000);

    if (diffM < 1)   return 'Just now';
    if (diffM < 60)  return `${diffM}m ago`;
    if (diffH < 24)  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (diffD === 1) return 'Yesterday';
    if (diffD < 7)   return d.toLocaleDateString([], { weekday: 'short' });
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  }

  const q = searchQuery.trim().toLowerCase();

  const sortedEmails = [...emails].sort(
    (a, b) => parseEmailDate(b.date) - parseEmailDate(a.date)
  );

  const inboxEmails = sortedEmails.filter(e => !e.is_spam);
  const spamEmails  = sortedEmails.filter(e =>  e.is_spam);

  const baseList    = activeTab === 'inbox' ? inboxEmails : spamEmails;
  const displayList = q
    ? baseList.filter(e =>
        (e.subject || '').toLowerCase().includes(q) ||
        (e.from    || '').toLowerCase().includes(q) ||
        (e.snippet || '').toLowerCase().includes(q)
      )
    : baseList;

  const currentEmail = selected !== null ? sortedEmails[selected] : null;

  return (
    <div className="ds-root">

      {/* ── TOP NAVBAR ─────────────────────────────────────────────── */}
      <nav className="ds-nav">
        <div className="ds-nav-brand">
          <span className="ds-nav-title">MailSentinel</span>
          <span className="ds-nav-badge">BETA</span>
        </div>

        <div className="ds-nav-stats">
          <div className="ds-stat-chip ds-chip-total">
            <span className="ds-chip-num">{emails.length}</span>
            <span className="ds-chip-lbl">Scanned</span>
          </div>
          <div className="ds-stat-chip ds-chip-safe">
            <span className="ds-chip-num">{emails.filter(e => e.risk === "safe").length}</span>
            <span className="ds-chip-lbl">Safe</span>
          </div>
          <div className="ds-stat-chip ds-chip-warn">
            <span className="ds-chip-num">{emails.filter(e => e.risk === "suspicious").length}</span>
            <span className="ds-chip-lbl">Suspicious</span>
          </div>
          <div className="ds-stat-chip ds-chip-danger">
            <span className="ds-chip-num">{emails.filter(e => e.risk === "danger").length}</span>
            <span className="ds-chip-lbl">Threats</span>
          </div>
        </div>

        <div className="ds-nav-actions">
          {lastRefresh && (
            <span className="ds-refresh-label" style={{ color: '#fff' }}>
              Updated {lastRefresh}
            </span>
          )}
          <button
            className="ds-btn-scan"
            onClick={handleScanAll}
            disabled={scanning}
          >
            {scanning ? 'Scanning...' : 'Scan All'}
          </button>
          <button
            className="ds-btn-pdf"
            disabled={pdfLoading || !currentEmail}
            onClick={async () => {
              if (!currentEmail) {
                alert('Select an email first to export its security report.');
                return;
              }
              setPdfLoading(true);
              try {
                const res = await fetch('/auth/report/' + currentEmail.id + '/', {
                  credentials: 'include',
                });
                if (!res.ok) {
                  const err = await res.json().catch(() => ({}));
                  alert('PDF Error: ' + (err.error || 'Could not generate report.'));
                  return;
                }
                const blob = await res.blob();
                const url  = URL.createObjectURL(blob);
                const a    = document.createElement('a');
                a.href     = url;
                a.download = 'MailSentinel_Report.pdf';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
              } catch (e) {
                alert('Failed to download PDF. Is Django running?');
              } finally {
                setPdfLoading(false);
              }
            }}
            title={currentEmail ? 'Download PDF threat report for selected email' : 'Select an email first'}
            style={{ opacity: currentEmail ? 1 : 0.5 }}
          >
            {pdfLoading ? 'Generating...' : 'Export PDF'}
          </button>
          <button className="ds-btn-logout" onClick={handleLogout}>Logout</button>
        </div>
      </nav>

      <div className="ds-body">

        <aside className="ds-sidebar">

          <div className="ds-tabs">
            <button
              className={`ds-tab ${activeTab === "inbox" ? "ds-tab-active" : ""}`}
              onClick={() => { setActiveTab("inbox"); setSelected(null); }}
            >
              Inbox
              {!loading && <span className="ds-tab-count">{inboxEmails.length}</span>}
            </button>
            <button
              className={`ds-tab ${activeTab === "spam" ? "ds-tab-active ds-tab-spam" : ""}`}
              onClick={() => { setActiveTab("spam"); setSelected(null); }}
            >
              Flagged
              {!loading && <span className="ds-tab-count ds-tab-count-spam">{spamEmails.length}</span>}
            </button>
          </div>

          <div className="ds-search-wrap">
            <span className="ds-search-icon">&#9906;</span>
            <input
              className="ds-search"
              type="text"
              placeholder="Search by sender, subject, or content..."
              value={searchQuery}
              onChange={e => { setSearchQuery(e.target.value); setSelected(null); }}
            />
            {searchQuery && (
              <button
                className="ds-search-clear"
                onClick={() => { setSearchQuery(''); setSelected(null); }}
              >X</button>
            )}
          </div>

          <div className="ds-email-list">
            {loading && (
              <div className="ds-loader-wrap">
                <div className="ds-spinner"></div>
                <p className="ds-loading-text">Fetching emails...</p>
              </div>
            )}

            {!loading && displayList.length === 0 && (
              <div className="ds-empty-list">
                <p>
                  {q
                    ? `No results for "${searchQuery}"`
                    : activeTab === 'spam' ? 'No flagged emails' : 'No emails found'
                  }
                </p>
              </div>
            )}

            {!loading && displayList.map((email, index) => {
              const risk      = getRisk(email);
              const realIndex = sortedEmails.indexOf(email);
              return (
                <div
                  key={email.id || index}
                  className={`ds-email-item ${selected === realIndex ? "ds-email-active" : ""} ${email.unread ? "ds-email-unread" : ""}`}
                  onClick={() => selectEmail(realIndex)}
                >
                  {email.unread && <span className="ds-unread-dot"></span>}

                  <div
                    className="ds-avatar"
                    style={{ background: avatarColor(email.from) }}
                  >
                    {getInitial(email.from)}
                  </div>

                  <div className="ds-email-text">
                    <div className="ds-email-top-row">
                      <span className="ds-sender">{getName(email.from) || 'Unknown'}</span>
                      <span className="ds-email-date">{formatDate(email.date)}</span>
                    </div>
                    <div className="ds-email-sub-row">
                      <span className="ds-subject">{email.subject || '(No Subject)'}</span>
                      <span className={`ds-risk-badge ds-risk-${risk}`}>
                        {risk === 'safe'       && 'SAFE'}
                        {risk === 'suspicious' && 'SUSPICIOUS'}
                        {risk === 'danger'     && 'THREAT'}
                        {risk === 'pending'    && 'PENDING'}
                      </span>
                    </div>
                    <p className="ds-snippet">{email.snippet}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </aside>

        <main className="ds-main">

          {!currentEmail && !loading && (
            <div className="ds-empty-state">
              <div className="ds-empty-glow"></div>
              <h2>MailSentinel</h2>
              <p>Select an email to view its security analysis</p>
              <div className="ds-feature-chips">
                <span>Phishing Detection</span>
                <span>Link Analysis</span>
                <span>Header Inspection</span>
                <span>PDF Reports</span>
              </div>
            </div>
          )}

          {loading && (
            <div className="ds-empty-state">
              <div className="ds-spinner ds-spinner-lg"></div>
              <p style={{marginTop: "20px", color: "var(--text-secondary)"}}>Loading your emails...</p>
            </div>
          )}

          {currentEmail && (
            <div className="ds-detail">

              <button className="ds-back-btn" onClick={() => setSelected(null)}>
                &larr; Back
              </button>

              <div className="ds-detail-header">
                <div className="ds-detail-left">
                  <h1 className="ds-detail-subject">{currentEmail.subject || "(No Subject)"}</h1>
                  <div className="ds-detail-from">
                    <div
                      className="ds-avatar ds-avatar-lg"
                      style={{ background: avatarColor(currentEmail.from) }}
                    >
                      {getInitial(currentEmail.from)}
                    </div>
                    <div>
                      <p className="ds-from-name">{getName(currentEmail.from)}</p>
                      <p className="ds-from-addr">{getEmail(currentEmail.from)}</p>
                    </div>
                  </div>
                </div>

                <div className="ds-detail-right">
                  <span className={`ds-risk-badge-lg ds-risk-${getRisk(currentEmail)}`}>
                    {getRisk(currentEmail) === "safe"       && "SAFE"}
                    {getRisk(currentEmail) === "suspicious" && "SUSPICIOUS"}
                    {getRisk(currentEmail) === "danger"     && "THREAT DETECTED"}
                    {getRisk(currentEmail) === "pending"    && "ANALYSIS PENDING"}
                  </span>
                  {currentEmail.unread && (
                    <span className="ds-unread-label">● Unread</span>
                  )}
                </div>
              </div>

              <div className="ds-security-panel">
                <div className="ds-panel-header">
                  <h3 className="ds-panel-title">Security Analysis</h3>
                  <div className="ds-score-pill ds-risk-" style={{
                    background: currentEmail.risk === 'safe' ? 'var(--safe-bg)' :
                                currentEmail.risk === 'suspicious' ? 'var(--warn-bg)' :
                                currentEmail.risk === 'danger' ? 'var(--danger-bg)' : 'var(--pending-bg)',
                    color: currentEmail.risk === 'safe' ? 'var(--safe)' :
                           currentEmail.risk === 'suspicious' ? 'var(--warn)' :
                           currentEmail.risk === 'danger' ? 'var(--danger)' : 'var(--pending)',
                  }}>
                    Score: {currentEmail.risk_score ?? '—'} / 100
                  </div>
                </div>

                <div className="ds-checks-grid">
                  {(currentEmail.security_checks || []).map((check, i) => (
                    <div key={i} className={`ds-check ds-check-${check.status}`}>
                      <span className="ds-check-icon">
                        {check.status === 'pass' ? '[PASS]' :
                         check.status === 'warn' ? '[WARN]' : '[FAIL]'}
                      </span>
                      <div>
                        <p className="ds-check-name">{check.name}</p>
                        <p className="ds-check-desc">{check.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>

                {scanLogs.length > 0 && (
                  <div className="ds-scan-log">
                    <div className="ds-scan-log-header">
                      <span className="ds-scan-log-dot" />
                      <span className="ds-scan-log-dot ds-dot-yellow" />
                      <span className="ds-scan-log-dot ds-dot-green" />
                      <span className="ds-scan-log-title">MailSentinel Security Engine — Scan Log</span>
                    </div>
                    <div className="ds-scan-log-body">
                      {scanLogs.map((log, i) => (
                        <div key={i} className={'ds-log-line ds-log-' + log.type}
                          style={{ animationDelay: (i * 0.05) + 's' }}>
                          <span className="ds-log-ts">
                            {new Date().toLocaleTimeString([], { hour:'2-digit', minute:'2-digit', second:'2-digit' })}
                          </span>
                          <span className="ds-log-text">{log.text}</span>
                        </div>
                      ))}
                      {scanLogs.length > 0 && scanLogs[scanLogs.length - 1].type !== 'verdict' && (
                        <div className="ds-log-cursor">█</div>
                      )}
                    </div>
                  </div>
                )}

                <div className="ds-spam-actions">
                  {!currentEmail.is_spam ? (
                    <button
                      className="ds-btn-mark-spam"
                      onClick={() => handleMarkSpam(currentEmail.id)}
                      disabled={spamming}
                    >
                      {spamming ? 'Moving...' : 'Move to Spam'}
                    </button>
                  ) : (
                    <button
                      className="ds-btn-restore"
                      onClick={() => handleUnmarkSpam(currentEmail.id)}
                      disabled={spamming}
                    >
                      {spamming ? 'Restoring...' : 'Restore to Inbox'}
                    </button>
                  )}
                </div>
              </div>

              <div className="ds-email-body">
                <h4 className="ds-body-label">Email Content</h4>
                {loadingBody ? (
                  <div style={{display:'flex', justifyContent:'center', padding:'40px'}}>
                    <div className="ds-spinner"></div>
                  </div>
                ) : (() => {
                  const cached = bodyCache[currentEmail.id];
                  if (cached?.html_body) {
                    return (
                      <iframe
                        title="email-content"
                        srcDoc={cached.html_body}
                        className="ds-iframe"
                        sandbox="allow-same-origin"
                      />
                    );
                  }
                  return (
                    <p className="ds-plain-text">
                      {cached?.body || currentEmail.snippet || 'No content available.'}
                    </p>
                  );
                })()}
              </div>

            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default Dashboard;