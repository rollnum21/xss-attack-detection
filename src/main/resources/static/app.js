const form = document.querySelector('#analysis-form');
const inputField = document.querySelector('#input');
const analyzeButton = document.querySelector('#analyze-button');
const clearButton = document.querySelector('#clear-button');
const resultPanel = document.querySelector('#result');
const characterCount = document.querySelector('#character-count');
const historyStorageKey = 'xss-shield-analysis-history-v1';
const themeStorageKey = 'xss-shield-theme-v1';
const historyList = document.querySelector('#analysis-history');
const historyEmpty = document.querySelector('#history-empty');
const exportButton = document.querySelector('#export-json-button');
let analysisHistory = readHistory();
let latestReport = null;

const examples = {
  script: '<script>alert(1)</script>',
  url: 'javascript:alert(1)',
  benign: 'Hello, this is normal text.'
};

initializeTheme();
renderHistory();

document.querySelector('#theme-toggle').addEventListener('click', () => {
  const nextTheme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  applyTheme(nextTheme, true);
});

document.querySelector('#clear-history-button').addEventListener('click', () => {
  analysisHistory = [];
  try { localStorage.removeItem(historyStorageKey); } catch (error) { /* Clear the visible session even if storage is unavailable. */ }
  renderHistory();
});

exportButton.addEventListener('click', downloadReport);

inputField.addEventListener('input', () => {
  const length = inputField.value.length;
  characterCount.textContent = `${length} ${length === 1 ? 'character' : 'characters'}`;
});

document.querySelectorAll('[data-example]').forEach((button) => {
  button.addEventListener('click', () => {
    const example = examples[button.dataset.example];
    if (!example) return;
    inputField.value = example;
    inputField.dispatchEvent(new Event('input'));
    inputField.focus();
  });
});

clearButton.addEventListener('click', () => {
  form.reset();
  inputField.dispatchEvent(new Event('input'));
  resultPanel.hidden = true;
  inputField.focus();
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const submittedInput = inputField.value;
  const startedAt = performance.now();
  setLoading(true);

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ input: submittedInput, context: 'AUTO' })
    });
    const result = await response.json();
    const durationMs = Math.max(0, performance.now() - startedAt);
    renderResult(result, submittedInput, durationMs);
    saveAnalysis(submittedInput, result, durationMs);
  } catch (error) {
    renderClientError('The analysis service could not be reached. Check that the application is running and try again.', submittedInput);
  } finally {
    setLoading(false);
  }
});

function setLoading(isLoading) {
  analyzeButton.disabled = isLoading;
  form.setAttribute('aria-busy', String(isLoading));
  analyzeButton.querySelector('.loading-spinner').hidden = !isLoading;
  analyzeButton.querySelector('.button-arrow').hidden = isLoading;
  analyzeButton.querySelector('.button-label').textContent = isLoading ? 'Analyzing…' : 'Analyze input';
}

function renderResult(result, submittedInput, durationMs) {
  const classification = result?.classification;
  const resultConfig = {
    KNOWN_XSS_PATTERN: { state: 'match', title: 'Known XSS pattern' },
    NO_KNOWN_XSS_PATTERN: { state: 'clear', title: 'No known pattern detected' },
    INVALID_INPUT: { state: 'invalid', title: 'Input needs attention' }
  }[classification] ?? { state: 'invalid', title: 'Unable to analyze input' };

  resultPanel.dataset.state = resultConfig.state;
  document.querySelector('#result-title').textContent = classification ?? resultConfig.title;
  document.querySelector('#result-message').textContent = result?.message ?? 'The server returned an incomplete result.';
  document.querySelector('.result-status-card').dataset.status = resultConfig.state;
  document.querySelector('#result-context').textContent = result?.context ?? 'AUTO SCAN';
  document.querySelector('#summary-classification').textContent = classification ?? 'UNKNOWN';
  const contexts = Array.isArray(result?.analyzedContexts) ? result.analyzedContexts : [];
  document.querySelector('#summary-context').textContent = contexts.length === 4
    ? 'All supported contexts'
    : contexts.length > 0 ? contexts.join(', ') : 'Unavailable';
  document.querySelector('#summary-rule-count').textContent = String(Array.isArray(result?.matchedRules) ? result.matchedRules.length : 0);
  document.querySelector('#submitted-input').textContent = submittedInput;
  const matchedRules = Array.isArray(result?.matchedRules) ? result.matchedRules : [];
  renderMatchedRules(matchedRules);
  latestReport = {
    generatedAt: new Date().toISOString(),
    elapsedMs: Number(durationMs.toFixed(2)),
    request: { input: submittedInput, context: 'AUTO' },
    response: result
  };
  exportButton.disabled = false;
  revealResult();
}

function renderMatchedRules(rules) {
  const section = document.querySelector('#matched-rules-section');
  const list = document.querySelector('#matched-rules');
  list.replaceChildren();
  section.hidden = rules.length === 0;

  rules.forEach((rule) => {
    const item = document.createElement('li');
    item.className = 'matched-rule';

    const title = document.createElement('div');
    title.className = 'matched-rule-title';
    const name = document.createElement('span');
    name.textContent = rule.name ?? 'Matched rule';
    const id = document.createElement('span');
    id.className = 'rule-id';
    id.textContent = rule.id ?? 'Rule ID unavailable';
    title.append(name, id);

    const description = document.createElement('p');
    description.textContent = rule.description ?? '';

    const recommendation = document.createElement('p');
    recommendation.className = 'rule-recommendation';
    const recommendationLabel = document.createElement('strong');
    recommendationLabel.textContent = 'Recommended action';
    const recommendationText = document.createElement('span');
    recommendationText.textContent = rule.recommendation ?? 'Keep untrusted input as data and apply output encoding appropriate to where it will be used.';
    recommendation.append(recommendationLabel, recommendationText);

    const metadata = document.createElement('div');
    metadata.className = 'matched-rule-meta';
    if (rule.cwe) {
      const cwe = document.createElement('span');
      cwe.textContent = rule.cwe;
      metadata.append(cwe);
    }
    if (rule.context) {
      const context = document.createElement('span');
      context.textContent = rule.context;
      metadata.append(context);
    }
    const referenceUrl = safeReferenceUrl(rule.securityReference);
    if (referenceUrl) {
      const reference = document.createElement('a');
      reference.href = referenceUrl.href;
      reference.target = '_blank';
      reference.rel = 'noopener noreferrer';
      reference.textContent = 'Security reference ↗';
      metadata.append(reference);
    }

    item.append(title, description, recommendation);
    if (metadata.childElementCount > 0) item.append(metadata);
    list.append(item);
  });
}

function safeReferenceUrl(value) {
  try {
    const url = new URL(value);
    const allowedHosts = new Set(['cheatsheetseries.owasp.org', 'cwe.mitre.org']);
    return url.protocol === 'https:' && allowedHosts.has(url.hostname) ? url : null;
  } catch (error) {
    return null;
  }
}

function renderClientError(message, submittedInput) {
  resultPanel.dataset.state = 'invalid';
  document.querySelector('#result-title').textContent = 'Service unavailable';
  document.querySelector('#result-message').textContent = message;
  document.querySelector('.result-status-card').dataset.status = 'invalid';
  document.querySelector('#result-context').textContent = 'SERVICE UNAVAILABLE';
  document.querySelector('#summary-classification').textContent = 'SERVICE_UNAVAILABLE';
  document.querySelector('#summary-context').textContent = 'Not analyzed';
  document.querySelector('#summary-rule-count').textContent = '0';
  document.querySelector('#submitted-input').textContent = submittedInput;
  document.querySelector('#matched-rules').replaceChildren();
  document.querySelector('#matched-rules-section').hidden = true;
  latestReport = null;
  exportButton.disabled = true;
  revealResult();
}

function revealResult() {
  resultPanel.hidden = false;
  resultPanel.classList.remove('is-entering');
  // Restart the short reveal for each real response, without delaying the API result.
  void resultPanel.offsetWidth;
  resultPanel.classList.add('is-entering');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  resultPanel.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'nearest' });
}

function initializeTheme() {
  let savedTheme = 'light';
  try {
    const storedTheme = localStorage.getItem(themeStorageKey);
    if (storedTheme === 'light' || storedTheme === 'dark') savedTheme = storedTheme;
  } catch (error) {
    // The page still works when browser storage is unavailable.
  }
  applyTheme(savedTheme, false);
}

function applyTheme(theme, persist) {
  document.documentElement.dataset.theme = theme;
  const dark = theme === 'dark';
  const toggle = document.querySelector('#theme-toggle');
  toggle.setAttribute('aria-pressed', String(dark));
  toggle.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
  document.querySelector('#theme-label').textContent = dark ? 'Light mode' : 'Dark mode';
  if (persist) {
    try { localStorage.setItem(themeStorageKey, theme); } catch (error) { /* Ignore unavailable storage. */ }
  }
}

function readHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem(historyStorageKey) ?? '[]');
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item) => item && typeof item.input === 'string' && item.result && typeof item.result === 'object').slice(0, 10);
  } catch (error) {
    return [];
  }
}

function saveAnalysis(input, result, durationMs) {
  const entry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
    input,
    context: result?.context ?? 'AUTO SCAN',
    result,
    durationMs: Number(durationMs.toFixed(2))
  };
  analysisHistory = [entry, ...analysisHistory].slice(0, 10);
  try { localStorage.setItem(historyStorageKey, JSON.stringify(analysisHistory)); } catch (error) { /* Analysis results remain available in the current page. */ }
  renderHistory(true);
}

function renderHistory(animateNewest = false) {
  historyList.replaceChildren();
  historyEmpty.hidden = analysisHistory.length > 0;
  document.querySelector('#clear-history-button').disabled = analysisHistory.length === 0;

  analysisHistory.forEach((entry) => {
    const item = document.createElement('li');
    item.className = 'history-entry';
    if (animateNewest && analysisHistory[0] === entry) item.classList.add('history-enter');
    const info = document.createElement('div');
    info.className = 'history-info';
    const heading = document.createElement('div');
    heading.className = 'history-heading';
    const classification = document.createElement('strong');
    classification.className = `history-classification ${historyState(entry.result?.classification)}`;
    classification.textContent = entry.result?.classification ?? 'UNKNOWN';
    const context = document.createElement('span');
    context.className = 'history-context';
    context.textContent = entry.context ?? 'Context unavailable';
    heading.append(classification, context);
    const preview = document.createElement('p');
    preview.className = 'history-preview';
    preview.textContent = entry.input.length > 130 ? `${entry.input.slice(0, 130)}…` : entry.input;
    const date = document.createElement('time');
    date.className = 'history-time';
    date.dateTime = entry.timestamp ?? '';
    const parsedDate = new Date(entry.timestamp);
    date.textContent = Number.isNaN(parsedDate.getTime()) ? 'Time unavailable' : parsedDate.toLocaleString();
    info.append(heading, preview, date);
    const reuse = document.createElement('button');
    reuse.className = 'btn btn-clear history-reuse';
    reuse.type = 'button';
    reuse.textContent = 'Use again';
    reuse.addEventListener('click', () => {
      inputField.value = entry.input;
      inputField.dispatchEvent(new Event('input'));
      inputField.focus();
      form.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    item.append(info, reuse);
    historyList.append(item);
  });
}

function historyState(classification) {
  if (classification === 'KNOWN_XSS_PATTERN') return 'history-match';
  if (classification === 'NO_KNOWN_XSS_PATTERN') return 'history-clear';
  return 'history-invalid';
}

function downloadReport() {
  if (!latestReport) return;
  const file = new Blob([JSON.stringify(latestReport, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(file);
  const link = document.createElement('a');
  link.href = url;
  link.download = `xss-analysis-${new Date(latestReport.generatedAt).toISOString().replace(/[:.]/g, '-')}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
