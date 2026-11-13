(() => {
  'use strict';
  const SAMPLE = `# synthetic sample — safe to scan\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nGITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuv\nPRIVATE_KEY="-----BEGIN PRIVATE KEY-----"\nAPI_KEY="sk_live_1234567890abcdefghijkl"\nNORMAL_SETTING=true`;
  const patterns = [
    { type: 'Private key block', severity: 'critical', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/g },
    { type: 'AWS access key', severity: 'high', regex: /\bAKIA[0-9A-Z]{16}\b/g },
    { type: 'GitHub token', severity: 'high', regex: /\bgh[pousr]_[A-Za-z0-9]{20,100}\b/g },
    { type: 'Slack token', severity: 'high', regex: /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/g },
    { type: 'JWT token', severity: 'high', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
    { type: 'Generic secret assignment', severity: 'review', regex: /\b(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["']?([A-Za-z0-9_\-/.]{16,})["']?/gi }
  ];
  const e = { files: document.querySelector('#files'), drop: document.querySelector('#drop'), fileList: document.querySelector('#fileList'), source: document.querySelector('#source'), sample: document.querySelector('#sample'), scan: document.querySelector('#scan'), status: document.querySelector('#status'), download: document.querySelector('#download'), found: document.querySelector('#found'), filesRead: document.querySelector('#filesRead'), critical: document.querySelector('#critical'), other: document.querySelector('#other'), foundHint: document.querySelector('#foundHint'), findingCount: document.querySelector('#findingCount'), findings: document.querySelector('#findings') };
  let loadedFiles = []; let latestReport = null;
  const escapeHtml = (value) => String(value).replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
  const redact = (value) => value.length <= 8 ? '[REDACTED]' : `${value.slice(0, 4)}${'•'.repeat(Math.min(12, Math.max(4, value.length - 8)))}${value.slice(-4)}`;
  function scanText(text, fileName) {
    const findings = []; const lines = text.split(/\r?\n/);
    patterns.forEach((pattern) => {
      pattern.regex.lastIndex = 0; let match;
      while ((match = pattern.regex.exec(text)) !== null) {
        const before = text.slice(0, match.index); const line = before.split('\n').length; const column = match.index - before.lastIndexOf('\n');
        const raw = match[0]; const shown = raw.includes('=') || raw.includes(':') ? raw.replace(/([=:]\s*["']?)([^"'\s]+)(["']?\s*)$/, (_, lead, value, tail) => `${lead}${redact(value)}${tail}`) : redact(raw);
        findings.push({ type: pattern.type, severity: pattern.severity, file: fileName, line, column, preview: shown });
        if (!pattern.regex.global) break;
      }
    });
    return findings.sort((a, b) => a.line - b.line || a.file.localeCompare(b.file));
  }
  function runScan() {
    const text = e.source.value; if (!text.trim() && !loadedFiles.length) { e.status.textContent = 'Add material first'; e.status.classList.remove('ready'); e.source.focus(); return; }
    const findings = loadedFiles.length ? loadedFiles.flatMap((file) => scanText(file.text, file.name)) : scanText(text, 'pasted-input.txt');
    latestReport = { generated_at: new Date().toISOString(), files_read: loadedFiles.length || 1, summary: { secrets_found: findings.length, critical: findings.filter((f) => f.severity === 'critical').length, high: findings.filter((f) => f.severity === 'high').length, review: findings.filter((f) => f.severity === 'review').length }, findings };
    render(latestReport);
  }
  function render(report) {
    e.found.textContent = report.summary.secrets_found; e.filesRead.textContent = report.files_read; e.critical.textContent = report.summary.critical; e.other.textContent = report.summary.high + report.summary.review; e.foundHint.textContent = report.summary.secrets_found ? 'Values are redacted below' : 'No known patterns matched'; e.findingCount.textContent = `${report.findings.length} finding${report.findings.length === 1 ? '' : 's'}`; e.status.textContent = `Scanned ${report.files_read} file${report.files_read === 1 ? '' : 's'}`; e.status.classList.add('ready'); e.download.disabled = false;
    if (!report.findings.length) { e.findings.innerHTML = '<div class="empty"><span>✓</span><strong>No known secrets found</strong><p>Keep reviewing before committing. Pattern scanners cannot prove a file is clean.</p></div>'; return; }
    e.findings.innerHTML = report.findings.map((f) => `<article class="finding severity-${f.severity}"><div><div class="finding-type">${escapeHtml(f.type)}</div><div class="finding-location">${escapeHtml(f.file)} : line ${f.line}, col ${f.column}</div></div><div class="finding-severity">${f.severity.toUpperCase()}</div><div class="finding-preview">${escapeHtml(f.preview)}</div></article>`).join('');
  }
  function loadFiles(fileList) { const files = [...fileList].filter((file) => file.size <= 2 * 1024 * 1024); if (!files.length) return; Promise.all(files.map((file) => new Promise((resolve) => { const reader = new FileReader(); reader.onload = () => resolve({ name: file.name, text: String(reader.result) }); reader.onerror = () => resolve(null); reader.readAsText(file); }))).then((items) => { loadedFiles = items.filter(Boolean); e.source.value = ''; e.fileList.textContent = `${loadedFiles.length} file${loadedFiles.length === 1 ? '' : 's'} loaded`; runScan(); }); }
  e.files.addEventListener('change', () => loadFiles(e.files.files)); e.sample.addEventListener('click', () => { loadedFiles = []; e.fileList.textContent = 'Synthetic sample loaded'; e.source.value = SAMPLE; runScan(); }); e.scan.addEventListener('click', runScan);
  e.drop.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); e.files.click(); } }); ['dragenter', 'dragover'].forEach((name) => e.drop.addEventListener(name, (event) => { event.preventDefault(); e.drop.classList.add('dragging'); })); ['dragleave', 'drop'].forEach((name) => e.drop.addEventListener(name, (event) => { event.preventDefault(); e.drop.classList.remove('dragging'); })); e.drop.addEventListener('drop', (event) => loadFiles(event.dataTransfer.files));
  e.source.addEventListener('input', () => { if (e.source.value) loadedFiles = []; }); e.download.addEventListener('click', () => { if (!latestReport) return; const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([JSON.stringify(latestReport, null, 2)], { type: 'application/json' })); link.download = 'secretlens-report.json'; link.click(); URL.revokeObjectURL(link.href); });
})();
