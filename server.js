const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── OLLAMA AI ENDPOINT ────────────────────────────────────────
app.post('/api/ai-analyze', async (req, res) => {
  const { text, type, ruleScore } = req.body;

  if (!text) return res.status(400).json({ error: 'No text provided' });

  const prompt = `You are Rakshak Bot, an expert scam detector for India.

Analyze this ${type} message and detect if it is a scam.

MESSAGE:
"${text}"

The rule engine already gave it a risk score of ${ruleScore}/100.

Common Indian scam types:
- KYC fraud (fake bank KYC update requests)
- OTP theft (tricking users to share OTP)
- Lottery/prize fraud (fake KBC, lucky draw)
- Job fraud (fake work from home jobs with registration fee)
- Impersonation (fake TRAI, police, income tax)
- Phishing (fake bank/brand websites)
- Investment fraud (guaranteed returns, crypto)
- Delivery fraud (fake customs fee for parcel)

Respond ONLY in this exact JSON format, nothing else:
{
  "verdict": "safe",
  "confidence": 85,
  "reasons": ["reason 1", "reason 2", "reason 3"],
  "scam_type": "none",
  "summary": "one sentence explanation for the user in simple language"
}

verdict must be exactly one of: safe, suspicious, scam
scam_type must be exactly one of: phishing, lottery, impersonation, job_fraud, kyc_fraud, otp_theft, investment, delivery_fraud, none`;

  try {
    const response = await fetch('http://localhost:11434/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'gemma2:2b',
        prompt: prompt,
        stream: false,
        options: {
          temperature: 0.1,
          num_predict: 300
        }
      })
    });

    if (!response.ok) throw new Error(`Ollama returned ${response.status}`);

    const data = await response.json();
    const rawText = data.response || '';

    // Extract JSON safely
    const jsonMatch = rawText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('Could not parse AI response');

    const aiResult = JSON.parse(jsonMatch[0]);

    // Validate fields
    if (!['safe','suspicious','scam'].includes(aiResult.verdict)) {
      aiResult.verdict = ruleScore > 65 ? 'scam' : ruleScore > 30 ? 'suspicious' : 'safe';
    }
    if (typeof aiResult.confidence !== 'number') aiResult.confidence = 70;
    if (!Array.isArray(aiResult.reasons)) aiResult.reasons = ['Analysis complete'];
    if (!aiResult.summary) aiResult.summary = 'AI analysis complete.';
    if (!aiResult.scam_type) aiResult.scam_type = 'none';

    res.json({ success: true, ai: aiResult });

  } catch (err) {
    console.error('Ollama error:', err.message);
    res.json({ success: false, error: err.message });
  }
});

// ── START SERVER ──────────────────────────────────────────────
app.listen(3000, () => {
  console.log('');
  console.log('  ✅  Rakshak Bot running at http://localhost:3000');
  console.log('  🤖  AI endpoint ready at /api/ai-analyze');
  console.log('  🛡️   Ollama should be running at http://localhost:11434');
  console.log('');
});
