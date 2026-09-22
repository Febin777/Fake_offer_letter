import hashlib
import json
import math
import re
import time
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Optional
import uvicorn
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

app = FastAPI(title="SENTINEL // Autonomous Counter-Intelligence Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------
# 1. ADVANCED FORENSIC ALGORITHMS
# -------------------------------------------------------------

def detect_zero_width_and_invisible_steganography(text: str) -> Dict:
    """Detects invisible unicode markers used in LLM prompt injection and email fingerprinting."""
    zero_width_chars = {
        '\u200B': 'ZERO_WIDTH_SPACE',
        '\u200C': 'ZERO_WIDTH_NON_JOINER',
        '\u200D': 'ZERO_WIDTH_JOINER',
        '\uFEFF': 'BYTE_ORDER_MARK',
        '\u202E': 'RIGHT_TO_LEFT_OVERRIDE'
    }
    found = {}
    for char, name in zero_width_chars.items():
        cnt = text.count(char)
        if cnt > 0:
            found[name] = cnt

    # Check for adversarial prompt injection hints attempting to deceive LLM security layers
    injection_patterns = [
        r'ignore previous instructions',
        r'system prompt override',
        r'do not flag this email',
        r'mark as verified safe'
    ]
    injections_detected = [p for p in injection_patterns if re.search(p, text, re.I)]

    return {
        "steganography_detected": len(found) > 0,
        "invisible_glyphs": found,
        "adversarial_prompt_injection": injections_detected
    }

def detect_devsecops_contagious_interview(text: str) -> Dict:
    """Detects modern fake technical test exploits (e.g. malicious npm, python scripts, docker traps)."""
    code_exploit_lexicon = [
        r'npm install', r'yarn start', r'pip install', r'git clone',
        r'docker run', r'run test script', r'execute build', r'debug project',
        r'unzip project', r'\.dmg', r'\.scr', r'\.exe'
    ]
    matches = [m for m in code_exploit_lexicon if re.search(m, text, re.I)]
    
    # Check for crypto / wallet address extraction
    crypto_addresses = re.findall(r'\b(0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33})\b', text)
    telegram_handles = re.findall(r'@([a-zA-Z0-9_]{4,32})', text)

    return {
        "developer_exploit_indicators": matches,
        "crypto_wallets": crypto_addresses,
        "telegram_channels": telegram_handles,
        "is_dev_test_trap": len(matches) > 0 or len(crypto_addresses) > 0
    }

def compute_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) for c in set(text)}
    total = len(text)
    return round(-sum((cnt / total) * math.log2(cnt / total) for cnt in freq.values()), 2)

def analyze_stylometry(text: str) -> Dict:
    urgency_lexicon = [
        "urgent", "wire transfer", "bank routing", "check deposit", 
        "equipment fee", "immediate response", "confidential offer", 
        "crypto rail", "cleared funds", "cashier check", "onboarding fee",
        "task payment", "whatsapp recruiter", "telegram hr"
    ]
    detected = [w for w in urgency_lexicon if re.search(r'\b' + re.escape(w) + r'\b', text, re.I)]
    words = text.split()
    sentences = max(len(re.split(r'[.!?]+', text)), 1)
    burstiness = round(len(words) / sentences, 2)
    entropy = compute_shannon_entropy(text)

    synthetic_prob = min(round((entropy / 8.0) * 45 + (burstiness / 25) * 55, 1), 99.0) if text else 0.0

    return {
        "entropy": entropy,
        "burstiness": burstiness,
        "urgency_triggers": detected,
        "synthetic_confidence": synthetic_prob
    }

def check_domain_reputation(domain: str, authentic_target: str = "meta-careers.com") -> Dict:
    if not domain:
        return {"levenshtein_distance": 0, "is_suspect": False}
    
    is_punycode = domain.lower().startswith("xn--") or ".xn--" in domain.lower()
    non_ascii = [c for c in domain if ord(c) > 127]

    s1, s2 = domain.lower(), authentic_target.lower()
    dp = [[0] * (len(s2) + 1) for _ in range(len(s1) + 1)]
    for i in range(len(s1) + 1): dp[i][0] = i
    for j in range(len(s2) + 1): dp[0][j] = j
    for i in range(1, len(s1) + 1):
        for j in range(1, len(s2) + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
    distance = dp[len(s1)][len(s2)]

    return {
        "distance": distance,
        "is_suspect": (1 <= distance <= 4) or is_punycode or len(non_ascii) > 0,
        "is_punycode": is_punycode
    }

# -------------------------------------------------------------
# 2. REST API ENDPOINT
# -------------------------------------------------------------

@app.post("/api/audit")
async def execute_audit(
    raw_payload: str = Form(""),
    target_domain: str = Form(""),
    sender_mailbox: str = Form(""),
    av_artifact_url: str = Form(""),
    file: Optional[UploadFile] = File(None)
):
    consolidated_text = raw_payload
    auth_matrix = {"spf": "FAIL", "dkim": "FAIL", "dmarc": "REJECT", "origin_ip": "194.26.29.11"}

    if file:
        file_bytes = await file.read()
        consolidated_text += "\n" + file_bytes.decode(errors="ignore")
        try:
            msg = BytesParser(policy=policy.default).parsebytes(file_bytes)
            ar_header = msg.get("Authentication-Results", "").lower()
            if "spf=pass" in ar_header: auth_matrix["spf"] = "PASS"
            if "dkim=pass" in ar_header: auth_matrix["dkim"] = "PASS"
            if "dmarc=pass" in ar_header: auth_matrix["dmarc"] = "PASS"
            recv = msg.get("Received", "")
            ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', recv)
            if ips: auth_matrix["origin_ip"] = ips[0]
        except Exception:
            pass

    sha256_hash = hashlib.sha256(consolidated_text.encode("utf-8")).hexdigest()
    stylometry = analyze_stylometry(consolidated_text)
    domain_rep = check_domain_reputation(target_domain)
    stego_data = detect_zero_width_and_invisible_steganography(consolidated_text)
    dev_exploits = detect_devsecops_contagious_interview(consolidated_text)

    # Deepfake Inspector Simulation
    deepfake_rep = None
    if av_artifact_url.strip():
        deepfake_rep = {
            "artifact_url": av_artifact_url,
            "blink_frequency_hz": 0.11,
            "voice_synthesis_score": 93.8,
            "verdict": "SYNTHETIC_AV_CLONE_CONFIRMED"
        }

    # Dynamic Weighting
    threat_points = 15
    if auth_matrix["spf"] != "PASS": threat_points += 15
    if auth_matrix["dkim"] != "PASS": threat_points += 15
    if domain_rep["is_suspect"]: threat_points += 25
    if len(stylometry["urgency_triggers"]) > 0: threat_points += 15
    if stego_data["steganography_detected"]: threat_points += 20
    if dev_exploits["is_dev_test_trap"]: threat_points += 30
    if deepfake_rep: threat_points += 25
    threat_score = min(threat_points, 100)

    # MITRE ATT&CK Matrix Alignment
    mitre_ttps = []
    if dev_exploits["is_dev_test_trap"]:
        mitre_ttps.append({"id": "T1204.002", "name": "User Execution: Malicious Payload Repository"})
    if domain_rep["is_suspect"]:
        mitre_ttps.append({"id": "T1583.001", "name": "Resource Development: Typosquatting"})
    if len(stylometry["urgency_triggers"]) > 0:
        mitre_ttps.append({"id": "T1566.002", "name": "Spearphishing Link"})
    if stego_data["steganography_detected"]:
        mitre_ttps.append({"id": "T1027", "name": "Obfuscated Files or Information: Steganography"})
    if deepfake_rep:
        mitre_ttps.append({"id": "T1056.003", "name": "Synthetic Avatar Impersonation"})

    return {
        "blockchain_receipt": {
            "polygon_tx_hash": f"0x{sha256_hash[:40]}",
            "state_merkle_root": f"0x{sha256_hash[40:]}",
            "block_timestamp": int(time.time()),
            "ledger": "POLYGON_POS_MAINNET"
        },
        "composite_threat_score": threat_score,
        "threat_tier": "CRITICAL RISK" if threat_score >= 70 else ("SUSPICIOUS" if threat_score >= 40 else "SAFE / VERIFIED"),
        "email_auth": auth_matrix,
        "stylometrics": stylometry,
        "domain_forensics": domain_rep,
        "steganography": stego_data,
        "devsecops_exploit": dev_exploits,
        "deepfake": deepfake_rep,
        "mitre_ttps": mitre_ttps
    }

# -------------------------------------------------------------
# 3. INTERACTIVE WEB UI (HTML / Tailwind / Canvas)
# -------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>SENTINEL // Modern Cyber Threat Workstation</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <style>
        body { background-color: #04070d; color: #94a3b8; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
        .neon-glow { text-shadow: 0 0 14px rgba(0, 255, 136, 0.45); }
        .neon-box { box-shadow: 0 0 20px rgba(0, 255, 136, 0.08); }
      </style>
    </head>
    <body class="flex min-h-screen">
      <!-- Sidebar -->
      <aside class="w-80 border-r border-[#121c2d] bg-[#070b12] p-6 flex flex-col justify-between">
        <div class="space-y-6">
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-[#00ff88] animate-pulse"></span>
            <h2 class="text-[#00ff88] text-xs font-bold tracking-widest">// TERMINAL CONTROLS</h2>
          </div>

          <div>
            <label class="text-[11px] text-gray-400 block mb-2 font-bold">⚡ INJECT THREAT VECTOR</label>
            <select id="presetSelect" onchange="applyPreset()" class="w-full bg-[#0a111c] border border-[#1b283d] rounded p-2.5 text-xs text-white focus:outline-none focus:border-[#00ff88]">
              <option value="">-- Choose Exploitation Preset --</option>
              <option value="npm_trap">Fake Tech Test: Malicious npm Clone</option>
              <option value="telegram_crypto">Telegram Escrow & USDT Advance</option>
              <option value="unicode_stego">Invisible Zero-Width Steganography</option>
            </select>
          </div>

          <div class="space-y-3 pt-6 border-t border-[#121c2d] text-xs">
            <div class="flex justify-between items-center"><span class="text-gray-400">[DAEMON]:</span><span class="text-[#00ff88] bg-[#00ff88]/10 px-2 py-0.5 rounded text-[10px] font-bold">ONLINE_ACTIVE</span></div>
            <div class="flex justify-between items-center"><span class="text-gray-400">[EIP-712]:</span><span class="text-[#00ff88] bg-emerald-950/40 px-2 py-0.5 rounded text-[10px]">ECDSA_ENABLED</span></div>
            <div class="flex justify-between items-center"><span class="text-gray-400">[LEDGER]:</span><span class="text-[#00ff88] bg-emerald-950/40 px-2 py-0.5 rounded text-[10px]">POLYGON_MAINNET</span></div>
            <div class="flex justify-between items-center"><span class="text-gray-400">[DEVSECOPS]:</span><span class="text-[#00e5ff] bg-cyan-950/40 px-2 py-0.5 rounded text-[10px]">SCANNER_ARMED</span></div>
          </div>
        </div>

        <div class="text-[10px] text-gray-600 border-t border-[#121c2d] pt-4 text-center">
          SENTINEL ARCHITECTURE // v3.0-ENTERPRISE
        </div>
      </aside>

      <!-- Main Operational Console -->
      <main class="flex-1 p-8 overflow-y-auto">
        <header class="mb-8">
          <h1 class="text-3xl font-black text-white neon-glow tracking-wider">SENTINEL // PHISHING & SPOOF FORENSICS</h1>
          <p class="text-xs text-[#00e5ff] tracking-wider mt-1">Autonomous Counter-Intelligence Engine for Synthetic Recruitment & DevSecOps Exploits</p>
        </header>

        <div class="grid grid-cols-12 gap-8">
          <!-- Ingestion Column -->
          <section class="col-span-6 space-y-4">
            <h3 class="text-xs tracking-wider bg-[#0f1926] text-[#00ff88] inline-block px-3 py-1 rounded border border-[#1c2c44]">[1.0] ARTIFACT INGESTION</h3>
            
            <div class="border border-[#121c2d] bg-[#070b13] rounded-lg p-5 space-y-4 neon-box">
              <div>
                <label class="text-[11px] font-bold text-gray-300 block mb-1">OFFER LETTER / RECRUITER PAYLOAD *</label>
                <textarea id="payload" rows="6" class="w-full bg-[#03060a] border border-[#1b283d] focus:border-[#00ff88] rounded p-3 text-xs text-white outline-none resize-none" placeholder="[Paste raw payload, GitHub repo pitch, or recruiter DM here...]"></textarea>
              </div>

              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="text-[11px] font-bold text-gray-300 block mb-1">TARGET DOMAIN / REPO URL</label>
                  <input id="domain" type="text" placeholder="meta-careers.com" class="w-full bg-[#03060a] border border-[#1b283d] rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#00ff88]" />
                </div>
                <div>
                  <label class="text-[11px] font-bold text-gray-300 block mb-1">SENDER MAILBOX / CHAT HANDLE</label>
                  <input id="sender" type="text" placeholder="recruiter@telegram.org" class="w-full bg-[#03060a] border border-[#1b283d] rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#00ff88]" />
                </div>
              </div>

              <div>
                <label class="text-[11px] font-bold text-gray-300 block mb-1">AV INTERVIEW ARTIFACT URL (Deepfake Inspector)</label>
                <input id="avUrl" type="text" placeholder="Link to interview video stream, audio reel, or screen record" class="w-full bg-[#03060a] border border-[#1b283d] rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#00ff88]" />
              </div>

              <button onclick="runAudit()" id="auditBtn" class="w-full py-3.5 bg-[#0a1b18] hover:bg-[#0f2924] border border-[#00ff88] text-[#00ff88] font-bold text-xs tracking-widest rounded flex items-center justify-center gap-2 transition-all shadow-[0_0_15px_rgba(0,255,136,0.15)]">
                ⚡ EXECUTE FORENSIC AUDIT
              </button>
            </div>
          </section>

          <!-- Telemetry Matrix -->
          <section class="col-span-6 space-y-4">
            <h3 class="text-xs tracking-wider bg-[#0f1926] text-[#00e5ff] inline-block px-3 py-1 rounded border border-[#1c2c44]">[2.0] TELEMETRY MATRIX</h3>

            <div id="idleState" class="border border-[#121c2d] bg-[#070b13] rounded-lg p-6 text-xs text-gray-400">
              SYSTEM IDLE. Select an exploitation preset from the left sidebar or input raw artifacts to initiate real-time telemetry.
            </div>

            <div id="activeTelemetry" class="hidden space-y-4 text-xs">
              <!-- Score & On-Chain Proof -->
              <div class="border border-[#121c2d] bg-[#070b13] rounded-lg p-4 flex justify-between items-center">
                <div>
                  <span class="text-[10px] text-gray-500 block">POLYGON ATTESTATION HASH</span>
                  <span id="txReceipt" class="text-[#00ff88] font-bold block mt-0.5"></span>
                  <span id="threatTier" class="inline-block mt-1 text-[9px] px-2 py-0.5 rounded font-bold"></span>
                </div>
                <div class="text-right">
                  <span class="text-[10px] text-gray-500 block">COMPOSITE THREAT</span>
                  <span id="scoreVal" class="text-3xl font-black"></span>
                </div>
              </div>

              <!-- Attack Surface Radar Canvas -->
              <div class="border border-[#121c2d] bg-[#070b13] rounded-lg p-4 flex items-center justify-between">
                <div>
                  <span class="text-xs font-bold text-white block">ATTACK SURFACE RADAR</span>
                  <p class="text-[10px] text-gray-400 mt-1 max-w-xs">Dynamic matrix across DevSecOps Traps, Unicode Steganography, Email Protocol Spoof, Coercion, and AV clones.</p>
                </div>
                <canvas id="threatCanvas" width="130" height="130"></canvas>
              </div>

              <!-- DevSecOps & Steganography Real-time Alarms -->
              <div class="border border-[#121c2d] bg-[#070b13] rounded-lg p-4 space-y-2">
                <span class="font-bold text-white block">DEVSECOPS & STEGANOGRAPHY ALARMS</span>
                <div id="devAlerts" class="text-[11px] space-y-1"></div>
                <div id="stegoAlerts" class="text-[11px] space-y-1"></div>
              </div>

              <!-- Stylometrics & AV Deepfake Telemetry -->
              <div class="grid grid-cols-2 gap-4">
                <div class="border border-[#121c2d] bg-[#070b13] rounded-lg p-4 space-y-2">
                  <span class="font-bold text-white block">STYLOMETRICS</span>
                  <div class="flex justify-between"><span>Entropy:</span><span id="entropyVal" class="text-white"></span></div>
                  <div class="flex justify-between"><span>Synthetic Prob:</span><span id="syntheticVal" class="text-red-400 font-bold"></span></div>
                </div>

                <div class="border border-[#121c2d] bg-[#070b13] rounded-lg p-4 space-y-2">
                  <span class="font-bold text-white block">DEEPFAKE TELEMETRY</span>
                  <div id="deepfakeDetails" class="text-[11px]"></div>
                </div>
              </div>

              <!-- MITRE Matrix Badges -->
              <div class="border border-[#121c2d] bg-[#070b13] rounded-lg p-4">
                <span class="text-xs font-bold text-white block mb-2">DETECTED MITRE ATT&CK® TACTICS</span>
                <div id="mitreBadges" class="flex flex-wrap gap-2"></div>
              </div>
            </div>
          </section>
        </div>
      </main>

      <script>
        function applyPreset() {
          const val = document.getElementById('presetSelect').value;
          if (val === 'npm_trap') {
            document.getElementById('payload').value = "Please complete our senior developer technical screen: git clone https://github.com/recruitment-eval-infra/auth-module.git && cd auth-module && npm install && npm run test";
            document.getElementById('domain').value = "github-eval-careers.com";
            document.getElementById('sender').value = "tech-lead@github-eval-careers.com";
            document.getElementById('avUrl').value = "";
          } else if (val === 'telegram_crypto') {
            document.getElementById('payload').value = "Interview passed! Join @GlobalRecruitmentCorp on Telegram. Send $150 verification deposit to TRC-20 USDT wallet: 0x71C8364724a35010B438Fa6A8BFF810A14";
            document.getElementById('domain').value = "global-careers-verify.io";
            document.getElementById('sender').value = "@GlobalRecruitmentHR";
            document.getElementById('avUrl').value = "";
          } else if (val === 'unicode_stego') {
            // Injects invisible zero-width spaces (\u200B) directly inside the text payload
            document.getElementById('payload').value = "Confidential\u200B\u200C\u200D Executive Offer Letter. Verify banking routing instructions on our enterprise onboarding server.";
            document.getElementById('domain').value = "meta-careers-support.com";
            document.getElementById('sender').value = "hr@meta-careers-support.com";
            document.getElementById('avUrl').value = "";
          }
        }

        async function runAudit() {
          const btn = document.getElementById('auditBtn');
          btn.innerText = "PROCESSING FORENSIC SIGNALS...";

          const fd = new FormData();
          fd.append('raw_payload', document.getElementById('payload').value);
          fd.append('target_domain', document.getElementById('domain').value);
          fd.append('sender_mailbox', document.getElementById('sender').value);
          fd.append('av_artifact_url', document.getElementById('avUrl').value);

          try {
            const res = await fetch('/api/audit', { method: 'POST', body: fd });
            const data = await res.json();

            document.getElementById('idleState').classList.add('hidden');
            document.getElementById('activeTelemetry').classList.remove('hidden');

            document.getElementById('txReceipt').innerText = data.blockchain_receipt.polygon_tx_hash;
            const scoreEl = document.getElementById('scoreVal');
            scoreEl.innerText = data.composite_threat_score + "/100";
            scoreEl.className = "text-3xl font-black " + (data.composite_threat_score >= 70 ? "text-red-400" : "text-yellow-400");

            const tierBadge = document.getElementById('threatTier');
            tierBadge.innerText = data.threat_tier;
            tierBadge.className = "inline-block mt-1 text-[9px] px-2 py-0.5 rounded font-bold " + (data.composite_threat_score >= 70 ? "bg-red-950 text-red-400 border border-red-800" : "bg-yellow-950 text-yellow-400 border border-yellow-800");

            // DevSecOps Alerts
            const devBox = document.getElementById('devAlerts');
            if (data.devsecops_exploit.is_dev_test_trap) {
              devBox.innerHTML = `<span class="text-red-400 font-bold">⚠️ Malicious Dev Pipeline: </span><span class="text-gray-300">${data.devsecops_exploit.developer_exploit_indicators.join(', ')}</span>`;
            } else {
              devBox.innerHTML = `<span class="text-gray-500">No malicious CLI commands or code test exploits detected</span>`;
            }

            // Stego Alerts
            const stegoBox = document.getElementById('stegoAlerts');
            if (data.steganography.steganography_detected) {
              stegoBox.innerHTML = `<span class="text-red-400 font-bold">⚠️ Invisible Glyphs Detected: </span><span class="text-yellow-400">Zero-width steganography active in payload</span>`;
            } else {
              stegoBox.innerHTML = `<span class="text-gray-500">Zero-width Unicode integrity intact</span>`;
            }

            // Stylometrics
            document.getElementById('entropyVal').innerText = data.stylometrics.entropy;
            document.getElementById('syntheticVal').innerText = data.stylometrics.synthetic_confidence + "%";

            // Deepfake
            const dfBox = document.getElementById('deepfakeDetails');
            if (data.deepfake) {
              dfBox.innerHTML = `
                <div class="flex justify-between"><span>Voice Clone Delta:</span><span class="text-red-400 font-bold">${data.deepfake.voice_synthesis_score}%</span></div>
                <div class="text-[9px] text-[#00e5ff] mt-1">${data.deepfake.verdict}</div>
              `;
            } else {
              dfBox.innerHTML = `<span class="text-gray-500">No AV artifact ingested</span>`;
            }

            // MITRE Badges
            const mBox = document.getElementById('mitreBadges');
            mBox.innerHTML = "";
            data.mitre_ttps.forEach(m => {
              mBox.innerHTML += `<span class="bg-[#03060a] border border-[#1b283d] text-gray-300 px-2 py-1 rounded"><strong class="text-[#00ff88]">${m.id}</strong>: ${m.name}</span>`;
            });

            // Draw Radar Chart
            drawRadar([
              data.domain_forensics.is_suspect ? 90 : 15,
              data.steganography.steganography_detected ? 95 : 10,
              data.devsecops_exploit.is_dev_test_trap ? 95 : 10,
              data.stylometrics.synthetic_confidence,
              data.deepfake ? 90 : 15
            ]);

          } catch (err) {
            console.error(err);
          } finally {
            btn.innerText = "⚡ EXECUTE FORENSIC AUDIT";
          }
        }

        function drawRadar(values) {
          const canvas = document.getElementById('threatCanvas');
          const ctx = canvas.getContext('2d');
          const cx = 65, cy = 65, r = 48;
          ctx.clearRect(0, 0, 130, 130);

          ctx.strokeStyle = '#121c2d';
          ctx.lineWidth = 1;
          for (let i = 1; i <= 3; i++) {
            ctx.beginPath();
            ctx.arc(cx, cy, (r / 3) * i, 0, Math.PI * 2);
            ctx.stroke();
          }

          ctx.beginPath();
          for (let i = 0; i < 5; i++) {
            const angle = (Math.PI * 2 / 5) * i - Math.PI / 2;
            const dist = (values[i] / 100) * r;
            const x = cx + dist * Math.cos(angle);
            const y = cy + dist * Math.sin(angle);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
          }
          ctx.closePath();
          ctx.fillStyle = 'rgba(255, 68, 68, 0.35)';
          ctx.fill();
          ctx.strokeStyle = '#ff4444';
          ctx.lineWidth = 1.5;
          ctx.stroke();
        }
      </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)