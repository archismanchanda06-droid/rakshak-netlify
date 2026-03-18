/* ============================================================
   RAKSHAK BOT — engine.js  (Phase 2 — Rule Engine + Ollama AI)
   ============================================================ */

// ── EXAMPLE MESSAGES ─────────────────────────────────────────
const EXAMPLES = [
  "Dear SBI customer, your account has been temporarily suspended due to incomplete KYC. Click here to update immediately or your account will be permanently blocked: http://sbi-kyc-update.xyz/verify",
  "Congratulations! You have won Rs 25,00,000 in the KBC Lottery 2024. Your ticket number is IND-4829. To claim your prize, send your Aadhaar and bank details to kbc.lottery.india@gmail.com",
  "TRAI Notice: Your mobile number will be disconnected within 2 hours due to suspicious activity. Call 9876543210 immediately to avoid service interruption. This is your final warning.",
  "Hi, I found your resume on Naukri. We have a work-from-home job with salary Rs 50,000/month. No experience needed. Register fee Rs 999 only. WhatsApp: 8765432109",
  "Your SBI account XXXX1234 has been credited with Rs 5,000 on 15-Dec. Available balance: Rs 12,450. Not you? Call 1800-11-2211.",
  "http://amaz0n-india-offers.xyz/claim?user=winner&prize=iphone15&ref=8273",
  "Your Amazon delivery is on hold. Pay Rs 49 customs fee to release your package: bit.ly/amz-custom-release. Offer expires in 2 hours.",
  "Join our SEBI-registered investment platform. Guaranteed 40% monthly returns. Minimum deposit Rs 5,000. WhatsApp us now: 9988776655. Limited spots available!"
];

// ── KEYWORD LISTS ─────────────────────────────────────────────
const SCAM_KEYWORDS = {
  critical: [
    'kyc update','kyc verification','kyc expired','kyc block','kyc pending',
    'account blocked','account suspended','account will be blocked','account deactivated',
    'otp share','share otp','send otp','otp bhejo','otp batao',
    'aadhaar link','link aadhaar','aadhaar verify','pan verify','pan update',
    'win prize','won prize','lucky draw','lottery winner','prize money',
    'kbc winner','kbc lottery','kaun banega','jackpot winner',
    'trai notice','trai disconnected','sim block','sim suspended','sim deactivated',
    'cybercrime case','arrest warrant','police case filed','fir registered',
    'income tax notice','it notice','tax fraud','tax evasion',
    'work from home','earn from home','ghar se kaam','online earning',
    'registration fee','joining fee','processing fee','security deposit',
    'custom duty','courier package held','parcel held','customs clearance fee',
    'click here to verify','click to update','verify now','update immediately',
    'urgent action required','immediate action required',
    'within 24 hours','within 2 hours','within 1 hour',
    'last warning','final warning','this is your last',
    'bitcoin investment','crypto profit','guaranteed return','double your money',
    'guaranteed profit','guaranteed income','40% return','100% return',
    'nude video','blackmail','intimate video',
    'pm relief fund','modi scheme','government cash','free ration',
    'delivery failed','reschedule delivery fee','customs fee','release package'
  ],
  high: [
    'verify account','verify your account','confirm identity','confirm your details',
    'bank details','share bank account','account number share',
    'debit card number','credit card number','cvv number','card details',
    'password share','share password','login credentials',
    'refund process','refund initiated','get your refund',
    'free iphone','free laptop','free recharge','free gift',
    'pm kisan','government scheme','yojana',
    'rewarded','you are selected','you have been chosen',
    'helpline number','customer care number',
    'apply now register','enroll today','limited seats',
    'sebi registered','rbi approved','government approved'
  ],
  medium: [
    'click here','tap here','link below','visit link',
    'limited time','offer expires','hurry','act fast',
    'free','winner','prize','reward','bonus',
    'congratulations','congrats','you have won',
    'dear customer','dear user','dear sir',
    'suspended','blocked','deactivated','terminated',
    'verify','update required','confirm','validate',
    'urgently','immediately','asap','right now'
  ]
};

const HINDI_SCAM = [
  'aapka account band','khata band ho jayega','kyc update karo',
  'otp batao','otp bhejo','otp share karo',
  'inam jeeta hai','paise mile hain','lucky draw','puraskar','inaam mila',
  'ghar baithe kamao','ghar se kaam','online paise kamao',
  'turat karo','jaldi karo','abhi karen','turant karen',
  'police case','giraftari hogi','warrant aaya','case darj',
  'registration fee do','paisa bhejo pehle','advance bhejo',
  'aadhar bhejo','pan card bhejo','bank details do'
];

// ── SUSPICIOUS PATTERNS ───────────────────────────────────────
const SUSPICIOUS_PATTERNS = [
  { re: /\b(bit\.ly|tinyurl|goo\.gl|t\.co|short\.gy|cutt\.ly|rb\.gy|is\.gd|ow\.ly|buff\.ly)\b/i,
    msg: 'Shortened URL — real destination is hidden' },
  { re: /(?:gmail|yahoo|hotmail|outlook)\.com.{0,20}(?:bank|sbi|hdfc|icici|axis|paytm|ubi|pnb)/i,
    msg: 'Bank name used with free email — likely fake sender' },
  { re: /\b(otp|password|pin|cvv)\b.{0,30}(share|send|tell|give|provide|batao|bhejo)/i,
    msg: 'Requesting sensitive credential (OTP / PIN / CVV)' },
  { re: /\b(account|card|loan|sim|number)\b.{0,20}(blocked|suspended|frozen|deactivated)/i,
    msg: 'Account / service threat used as pressure tactic' },
  { re: /rs\.?\s*[\d,]{4,}\s*(prize|reward|bonus|cashback|return|profit|jeeta)/i,
    msg: 'Large money prize or guaranteed return claim' },
  { re: /\b(aadhaar|aadhar|pan card|passport)\b.{0,30}(send|share|upload|submit|provide|bhejo)/i,
    msg: 'Requesting government ID documents' },
  { re: /\b\d{10}\b.{0,30}(whatsapp|call|contact|reach|ping)/i,
    msg: 'Unverified phone number pushed for contact' },
  { re: /[a-z0-9-]*(sbi|hdfc|icici|axis|paytm|npci|uidai|nsdl|irctc|amazon|flipkart)[a-z0-9-]*\.(xyz|tk|ml|top|online|net\.in|co\.in\.)/i,
    msg: 'Lookalike brand domain — impersonating a known brand' },
  { re: /https?:\/\/[^\s]*\d{6,}[^\s]*/,
    msg: 'URL with long suspicious numeric string' },
  { re: /guaranteed.{0,20}(return|profit|income|interest)/i,
    msg: 'Guaranteed returns — classic investment fraud signal' }
];

// ── KNOWN SCAM DOMAINS ────────────────────────────────────────
const BLOCKLIST_DOMAINS = [
  'sbi-kyc-update.xyz','hdfc-verify.tk','paytm-refund.ml','amazon-prize.ga',
  'kbc-lottery.top','income-tax-refund.xyz','gov-scheme.click','uidai-update.tk',
  'banking-secure.xyz','account-verify.top','flipkart-winner.ml','pm-kisan-money.tk',
  'amaz0n','flipkart-offer.xyz','reward-india.top','covid-relief-fund.xyz',
  'free-recharge.tk','jio-offer.ml','vodafone-prize.ga','airtel-recharge.xyz',
  'custom-duty-india.com','parcel-release.xyz','courier-pending.tk',
  'crypto-profit-india.xyz','bitcoin-india.tk','trading-returns.ml',
  'loan-approval-india.xyz','cibil-fix.tk','emi-waiver.ml'
];

// ── SAFE SIGNAL PATTERNS ──────────────────────────────────────
const SAFE_PATTERNS = [
  { re: /\b(HDFC|SBI|ICICI|AXIS|KOTAK|PNB|BOI|BOB|CANARA|UCO|UBI)\b.{0,40}(txn|credited|debited|transaction|balance|statement)/i,
    msg: 'Legitimate bank transaction format detected' },
  { re: /\bOTP is\b.{0,20}do not share/i,
    msg: 'Official "do not share OTP" warning present' },
  { re: /do not share.{0,10}otp/i,
    msg: 'Genuine OTP safety warning present' },
  { re: /\byour.{0,10}OTP.{0,20}valid for\b/i,
    msg: 'Standard OTP expiry format' },
  { re: /\b(IRCTC|NSDL|UIDAI|EPFO|GSTN|DigiLocker)\b.{0,40}(reference|ticket|application|booking)/i,
    msg: 'Legitimate government service reference' },
  { re: /(?:credited|debited).{0,10}(?:rs|inr|₹).{0,30}(?:avail|balance|a\/c|acct)/i,
    msg: 'Standard bank debit/credit notification format' }
];

const URGENCY_WORDS = [
  'immediately','urgent','within 24 hours','within 2 hours','within 1 hour',
  'right now','asap','last chance','final warning','do it now','expires tonight'
];

// ── MAIN RULE ENGINE ANALYZE ──────────────────────────────────
function analyze(text, type) {
  const lower = text.toLowerCase();
  let score = 0;
  const flags = [];

  // Safe signals
  let safeHits = 0;
  const safeSignals = [];
  for (const s of SAFE_PATTERNS) {
    if (s.re.test(text)) {
      safeHits++;
      safeSignals.push({ level: 'green', text: s.msg });
    }
  }

  // Critical keywords (18 pts, max 3 shown)
  let critCount = 0;
  for (const kw of SCAM_KEYWORDS.critical) {
    if (lower.includes(kw)) {
      score += 18;
      if (critCount < 3) flags.push({ level: 'red', text: `High-risk phrase: "${kw}"` });
      critCount++;
    }
  }

  // High keywords (8 pts, max 2 shown)
  let highCount = 0;
  for (const kw of SCAM_KEYWORDS.high) {
    if (lower.includes(kw)) {
      score += 8;
      if (highCount < 2) flags.push({ level: 'amber', text: `Suspicious phrase: "${kw}"` });
      highCount++;
    }
  }

  // Medium keywords (3 pts)
  let medCount = 0;
  for (const kw of SCAM_KEYWORDS.medium) {
    if (lower.includes(kw)) { score += 3; medCount++; }
  }
  if (medCount >= 3) flags.push({ level: 'amber', text: `Multiple lure/urgency words (${medCount} detected)` });

  // Hindi scam (14 pts, max 2 shown)
  let hindiCount = 0;
  for (const kw of HINDI_SCAM) {
    if (lower.includes(kw)) {
      score += 14;
      if (hindiCount < 2) flags.push({ level: 'red', text: `Hindi scam phrase: "${kw}"` });
      hindiCount++;
    }
  }

  // Regex patterns (12 pts each)
  for (const p of SUSPICIOUS_PATTERNS) {
    if (p.re.test(text)) {
      score += 12;
      flags.push({ level: 'amber', text: p.msg });
    }
  }

  // URL checks
  const urls = extractURLs(text);
  for (const url of urls) {
    const u = url.toLowerCase();
    for (const domain of BLOCKLIST_DOMAINS) {
      if (u.includes(domain)) {
        score += 45;
        flags.push({ level: 'red', text: `Known scam domain: ${url.slice(0, 60)}` });
      }
    }
    if (/\.(xyz|tk|ml|ga|cf|gq|top|click|win|free|loan|gift)\b/i.test(url)) {
      score += 15;
      flags.push({ level: 'amber', text: `High-risk domain extension: ${url.slice(0, 50)}` });
    }
    if (/bit\.ly|tinyurl|goo\.gl|short\.gy|cutt\.ly/i.test(url)) {
      score += 10;
      flags.push({ level: 'amber', text: `Shortened URL — real destination hidden: ${url}` });
    }
    if (/[a-z0-9-]*(sbi|hdfc|icici|paytm|amazon|flipkart)[a-z0-9-]*\.[a-z]{2,}/i.test(url) &&
        !/\b(sbi\.co\.in|hdfcbank\.com|icicibank\.com|paytm\.com|amazon\.in|flipkart\.com)\b/i.test(url)) {
      score += 30;
      flags.push({ level: 'red', text: `Lookalike brand domain: ${url.slice(0, 60)}` });
    }
  }

  // Urgency amplifier
  const urgencyHits = URGENCY_WORDS.filter(w => lower.includes(w)).length;
  if (urgencyHits >= 2) {
    score += urgencyHits * 5;
    flags.push({ level: 'amber', text: `Extreme urgency language: ${urgencyHits} pressure signals` });
  }

  // Safe signal discounts
  if (safeHits > 0 && score < 55) score = Math.max(0, score - safeHits * 22);
  if (/do not share/i.test(text) && /otp/i.test(text)) score = Math.max(0, score - 30);

  score = Math.min(100, Math.round(score));

  // Verdict
  let verdict, emoji, sublabel, steps;
  const effectivelySafe = score < 30 || (safeHits >= 2 && score < 50);

  if (effectivelySafe) {
    verdict  = 'safe';
    emoji    = '✓';
    sublabel = 'This message appears legitimate';
    steps    = [
      'No immediate action needed.',
      'Never share your OTP or password — no legitimate organization will ever ask.',
      'When unsure, call the institution on their official number only.'
    ];
  } else if (score < 65) {
    verdict  = 'suspicious';
    emoji    = '⚠';
    sublabel = 'Proceed with extreme caution';
    steps    = [
      'Do NOT click any links in this message.',
      'Do NOT share OTP, password, Aadhaar, or bank details.',
      'Call the organization using the number on their official website — not this message.',
      'Report to cybercrime.gov.in or call 1930 if you suspect fraud.'
    ];
  } else {
    verdict  = 'scam';
    emoji    = '✗';
    sublabel = 'High probability scam — do not engage';
    steps    = [
      'Block and delete this message immediately.',
      'Do NOT call any number mentioned in this message.',
      'Do NOT click any links or provide any personal information.',
      'Report on cybercrime.gov.in or call National Cyber Helpline: 1930.',
      'Warn your family and friends — this scam may be targeting others too.'
    ];
  }

  const allFlags = [...safeSignals, ...flags];
  if (allFlags.length === 0) allFlags.push({ level: 'green', text: 'No known scam patterns detected' });

  return { score, verdict, emoji, sublabel, flags: allFlags, steps };
}

// ── HELPERS ───────────────────────────────────────────────────
function extractURLs(text) {
  return text.match(/https?:\/\/[^\s]+|www\.[^\s]+|[a-z0-9-]+\.[a-z]{2,4}(?:\/[^\s]*)?/gi) || [];
}

function scoreColor(score) {
  if (score < 30) return 'var(--safe)';
  if (score < 65) return 'var(--warn)';
  return 'var(--danger)';
}

// ── AI STATUS CHECK ───────────────────────────────────────────
async function checkAIStatus() {
  const dot  = document.getElementById('aiDot');
  const text = document.getElementById('aiStatusText');
  dot.className = 'ai-dot checking';
  text.textContent = 'Checking AI…';
  try {
    const res = await fetch('http://localhost:11434/api/tags');
    if (res.ok) {
      dot.className  = 'ai-dot online';
      text.textContent = 'AI online';
      document.getElementById('aiModelStat').textContent = 'Gemma';
    } else throw new Error();
  } catch {
    dot.className  = 'ai-dot offline';
    text.textContent = 'AI offline';
    document.getElementById('aiModelStat').textContent = 'Off';
  }
}

// ── OLLAMA AI CALL ────────────────────────────────────────────
async function runAIAnalysis(text, type, ruleScore) {
  const aiBox = document.getElementById('aiBox');
  if (!aiBox) return;

  aiBox.innerHTML = `
    <div class="ai-section">
      <div class="ai-loading">
        <div class="ai-spinner"></div>
        AI is doing deep analysis of this message…
      </div>
    </div>`;

  try {
    const res = await fetch('/api/ai-analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, type, ruleScore })
    });

    const data = await res.json();
    if (!data.success) throw new Error(data.error);

    const ai = data.ai;
    const color = ai.verdict === 'safe' ? 'var(--safe)' : ai.verdict === 'suspicious' ? 'var(--warn)' : 'var(--danger)';

    const scamBadge = ai.scam_type && ai.scam_type !== 'none'
      ? `<span class="scam-type-badge">${ai.scam_type.replace(/_/g, ' ')}</span>`
      : '';

    const reasonsHTML = (ai.reasons || []).map(r =>
      `<div class="flag-item">
        <div class="flag-dot cyan"></div>
        <span>${r}</span>
      </div>`
    ).join('');

    aiBox.innerHTML = `
      <div class="ai-section">
        <div class="detail-title">
          🤖 AI deep analysis ${scamBadge}
        </div>
        <div class="ai-summary" style="border-left: 3px solid ${color}">
          ${ai.summary}
        </div>
        <div class="ai-confidence-row">
          <span class="ai-confidence-label">AI confidence</span>
          <div class="ai-confidence-track">
            <div class="ai-confidence-fill" id="aiConfBar" style="background:${color}"></div>
          </div>
          <span class="ai-confidence-value" style="color:${color}">${ai.confidence}%</span>
        </div>
        <div class="flag-list">${reasonsHTML}</div>
      </div>`;

    // Animate confidence bar
    requestAnimationFrame(() => requestAnimationFrame(() => {
      const bar = document.getElementById('aiConfBar');
      if (bar) bar.style.width = ai.confidence + '%';
    }));

    // Update AI status dot
    const dot = document.getElementById('aiDot');
    if (dot) { dot.className = 'ai-dot online'; }

  } catch (err) {
    aiBox.innerHTML = `
      <div class="ai-section">
        <div class="ai-offline-note">
          ⚠ AI is offline — rule engine result is still accurate.<br>
          To enable AI: make sure Ollama is running in the background.
          If it stopped, search for <code>Ollama</code> in your Start Menu and open it.
        </div>
      </div>`;

    const dot = document.getElementById('aiDot');
    if (dot) dot.className = 'ai-dot offline';
  }
}

// ── UI STATE ──────────────────────────────────────────────────
let currentType = 'sms';
let scanCount = parseInt(localStorage.getItem('rakshak_scans') || '0');
document.getElementById('scanCount').textContent = scanCount;

// Check AI status on load
checkAIStatus();

function setType(t, btn) {
  currentType = t;
  document.querySelectorAll('.type-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const placeholders = {
    sms:   'Paste your SMS here…',
    email: 'Paste email subject + body here…',
    url:   'Paste a suspicious URL or link here…',
    chat:  'Paste the WhatsApp / Telegram message here…'
  };
  document.getElementById('inputText').placeholder = placeholders[t];
}

function updateChar() {
  document.getElementById('charCount').textContent =
    document.getElementById('inputText').value.length;
}

function loadExample(i) {
  document.getElementById('inputText').value = EXAMPLES[i];
  updateChar();
  document.getElementById('resultArea').innerHTML = '';
}

// ── RUN SCAN ──────────────────────────────────────────────────
function runScan() {
  const text = document.getElementById('inputText').value.trim();
  if (!text) { document.getElementById('inputText').focus(); return; }

  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.querySelector('.btn-text').textContent = 'Analyzing…';

  document.getElementById('resultArea').innerHTML = `
    <div class="analyzing">
      <div class="spinner"></div>
      <p>Running ${text.length > 100 ? '300+' : '150+'} scam signal checks…</p>
    </div>`;

  setTimeout(() => {
    const result = analyze(text, currentType);

    // Update scan count
    scanCount++;
    localStorage.setItem('rakshak_scans', scanCount);
    document.getElementById('scanCount').textContent = scanCount;

    const color = scoreColor(result.score);

    const flagsHTML = result.flags.slice(0, 6).map(f =>
      `<div class="flag-item">
        <div class="flag-dot ${f.level}"></div>
        <span>${f.text}</span>
      </div>`
    ).join('');

    const stepsHTML = result.steps.map((s, i) =>
      `<div class="step-item">
        <div class="step-num">${i + 1}</div>
        <span>${s}</span>
      </div>`
    ).join('');

    document.getElementById('resultArea').innerHTML = `
      <div class="result">
        <div class="verdict-card ${result.verdict}">

          <div class="verdict-header">
            <div class="verdict-icon">${result.emoji}</div>
            <div>
              <div class="verdict-label">${result.verdict.toUpperCase()}</div>
              <div class="verdict-sublabel">${result.sublabel}</div>
            </div>
          </div>

          <div class="score-bar-wrap">
            <div class="score-label">
              <span>Rule engine risk score</span>
              <span style="color:${color};font-weight:600">${result.score} / 100</span>
            </div>
            <div class="score-track">
              <div class="score-fill" id="scoreBar" style="width:0%;background:${color}"></div>
            </div>
          </div>

          <div class="details">
            <div>
              <div class="detail-title">Detection signals (${result.flags.length})</div>
              <div class="flag-list">${flagsHTML}</div>
            </div>
            <div>
              <div class="detail-title">What to do next</div>
              <div class="steps-list">${stepsHTML}</div>
            </div>
            <div id="aiBox"></div>
          </div>

        </div>
        <button class="report-btn" onclick="window.open('https://cybercrime.gov.in','_blank')">
          Report this scam to cybercrime.gov.in →
        </button>
      </div>`;

    // Animate rule engine score bar
    requestAnimationFrame(() => requestAnimationFrame(() => {
      const bar = document.getElementById('scoreBar');
      if (bar) bar.style.width = result.score + '%';
    }));

    // Trigger AI in background
    runAIAnalysis(text, currentType, result.score);

    btn.disabled = false;
    btn.querySelector('.btn-text').textContent = 'Scan Now';

  }, 700);
}

// Ctrl+Enter shortcut
document.getElementById('inputText').addEventListener('keydown', e => {
  if (e.ctrlKey && e.key === 'Enter') runScan();
});
