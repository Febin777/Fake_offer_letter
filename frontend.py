import React, { useState } from 'react';
import { 
  Zap, UploadCloud, ShieldAlert, Cpu, 
  ExternalLink, FileText, CheckCircle, AlertOctagon 
} from 'lucide-react';

export default function SentinelDashboard() {
  const [payload, setPayload] = useState('');
  const [domain, setDomain] = useState('');
  const [sender, setSender] = useState('');
  const [avUrl, setAvUrl] = useState('');
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [audit, setAudit] = useState(null);

  const handleAudit = async () => {
    setLoading(true);
    const fd = new FormData();
    fd.append('raw_payload', payload);
    fd.append('target_domain', domain);
    fd.append('sender_mailbox', sender);
    fd.append('av_artifact_url', avUrl);
    if (file) fd.append('file', file);

    try {
      const res = await fetch('http://localhost:8000/api/audit', { method: 'POST', body: fd });
      const data = await res.json();
      setAudit(data);
    } catch (err) {
      console.error("Backend offline or request failed", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#06090e] text-[#a0aec0] font-mono flex">
      {/* Sidebar Controls */}
      <aside className="w-80 border-r border-[#1a2333] p-6 flex flex-col justify-between">
        <div className="space-y-6">
          <h2 className="text-[#00ff88] text-xs font-bold tracking-widest">// TERMINAL CONTROLS</h2>
          
          <div>
            <label className="text-[11px] text-gray-400 block mb-2">⚡ Inject Forensic Payload</label>
            <select 
              onChange={(e) => setPayload(e.target.value)}
              className="w-full bg-[#0a101d] border border-[#1a2333] rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#00ff88]"
            >
              <option value="">-- CHOOSE ATTACK PAYLOAD --</option>
              <option value="Urgent wire verification required to confirm your Meta Offer Letter. Send routing details to meta-careers-support.com">Synthetic Meta Offer Letter</option>
              <option value="Immediate cashier check deposit needed for home workstation setup. Please process via crypto rail.">Equipment Requisition Fraud</option>
            </select>
          </div>

          <div className="space-y-3 pt-6 border-t border-[#1a2333] text-xs">
            <div className="flex justify-between items-center">
              <span>[STATUS]:</span>
              <span className="bg-[#00ff88]/10 text-[#00ff88] px-2 py-0.5 rounded text-[10px]">DAEMON_RUNNING</span>
            </div>
            <div className="flex justify-between items-center">
              <span>[CIPHER]:</span>
              <span className="bg-emerald-950/40 text-[#00ff88] px-2 py-0.5 rounded text-[10px]">AES-256-GCM</span>
            </div>
            <div className="flex justify-between items-center">
              <span>[LEDGER]:</span>
              <span className="bg-emerald-950/40 text-[#00ff88] px-2 py-0.5 rounded text-[10px]">POLYGON_MAINNET</span>
            </div>
          </div>
        </div>

        <button 
          onClick={() => window.print()}
          className="w-full flex items-center justify-center gap-2 border border-[#1a2333] hover:border-[#00ff88] py-2 rounded text-xs text-white transition-all"
        >
          <FileText className="w-4 h-4 text-[#00ff88]" /> EXPORT STIX/TAXII
        </button>
      </aside>

      {/* Main Forensic Console */}
      <main className="flex-1 p-8 overflow-y-auto">
        <header className="mb-8">
          <h1 className="text-3xl font-black text-white drop-shadow-[0_0_12px_rgba(0,255,136,0.3)]">
            SENTINEL // PHISHING & SPOOF FORENSICS
          </h1>
          <p className="text-xs text-[#00e5ff] mt-1 tracking-wider">
            Autonomous Counter-Intelligence Engine for Synthetic Recruitment Exploits
          </p>
        </header>

        <div className="grid grid-cols-12 gap-8">
          {/* Artifact Ingestion Panel */}
          <section className="col-span-6 space-y-4">
            <h3 className="text-xs tracking-wider bg-[#0f172a] text-[#00ff88] inline-block px-3 py-1 rounded border border-[#1e293b]">
              [1.0] ARTIFACT INGESTION
            </h3>

            <div className="border border-[#1a2333] bg-[#090e17] rounded-lg p-5 space-y-4">
              <div>
                <label className="text-[11px] font-semibold text-gray-300 block mb-1">OFFER LETTER / RAW PAYLOAD *</label>
                <textarea
                  rows={5}
                  value={payload}
                  onChange={(e) => setPayload(e.target.value)}
                  placeholder="[Paste raw payload here for entropy & stylometric parsing...]"
                  className="w-full bg-[#04070c] border border-[#1a2333] focus:border-[#00ff88] rounded p-3 text-xs text-white placeholder-gray-600 focus:outline-none resize-none"
                />
              </div>

              <label className="border border-dashed border-[#1a2333] hover:border-[#00ff88] bg-[#04070c] rounded p-3 flex items-center justify-center gap-3 cursor-pointer">
                <UploadCloud className="w-5 h-5 text-[#00ff88]" />
                <span className="text-xs text-gray-400">
                  {file ? file.name : "Attach raw .eml, .msg, or .pdf header bundle"}
                </span>
                <input type="file" className="hidden" onChange={(e) => setFile(e.target.files[0])} />
              </label>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[11px] font-semibold text-gray-300 block mb-1">TARGET DOMAIN / URL</label>
                  <input
                    type="text"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    placeholder="e.g. meta-careers.com"
                    className="w-full bg-[#04070c] border border-[#1a2333] rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#00ff88]"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-semibold text-gray-300 block mb-1">SENDER MAILBOX</label>
                  <input
                    type="text"
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                    placeholder="e.g. recruiter@gmail.com"
                    className="w-full bg-[#04070c] border border-[#1a2333] rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#00ff88]"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-semibold text-gray-300 block mb-1">
                  INTERVIEW AV ARTIFACT URL (Deepfake Inspector)
                </label>
                <input
                  type="text"
                  value={avUrl}
                  onChange={(e) => setAvUrl(e.target.value)}
                  placeholder="Link to interview video, audio reel, or recording"
                  className="w-full bg-[#04070c] border border-[#1a2333] rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-[#00ff88]"
                />
              </div>

              <button
                onClick={handleAudit}
                disabled={loading}
                className="w-full py-3 bg-[#0a1b18] hover:bg-[#0f2924] border border-[#00ff88] text-[#00ff88] font-bold text-xs tracking-widest rounded flex items-center justify-center gap-2 transition-all shadow-[0_0_15px_rgba(0,255,136,0.15)]"
              >
                <Zap className="w-4 h-4 fill-[#00ff88]" /> {loading ? "PROCESSING..." : "EXECUTE FORENSIC AUDIT"}
              </button>
            </div>
          </section>

          {/* Telemetry Matrix Panel */}
          <section className="col-span-6 space-y-4">
            <h3 className="text-xs tracking-wider bg-[#0f172a] text-[#00e5ff] inline-block px-3 py-1 rounded border border-[#1e293b]">
              [2.0] TELEMETRY MATRIX
            </h3>

            {!audit ? (
              <div className="border border-[#1a2333] bg-[#090e17] rounded-lg p-6 flex gap-4 text-xs text-gray-400">
                <div className="w-1 bg-[#00ff88] rounded" />
                <p>SYSTEM IDLE. Ingest an offer payload or select a preset from the sidebar to engage the live audit engine.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {/* On-Chain Verification Block */}
                <div className="border border-[#1a2333] bg-[#090e17] rounded-lg p-4 flex justify-between items-center">
                  <div>
                    <span className="text-[10px] text-gray-500 block">POLYGON MAINNET ATTESTATION</span>
                    <span className="text-xs text-[#00ff88] flex items-center gap-1 mt-0.5">
                      {audit.blockchain_receipt.polygon_tx_hash} <ExternalLink className="w-3 h-3" />
                    </span>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] text-gray-500 block">COMPOSITE THREAT SCORE</span>
                    <span className="text-2xl font-bold text-red-400">{audit.composite_threat_score}/100</span>
                  </div>
                </div>

                {/* Email RFC Breakdown */}
                <div className="border border-[#1a2333] bg-[#090e17] rounded-lg p-4">
                  <span className="text-xs font-semibold text-white block mb-2">INFRASTRUCTURE AUTHENTICITY</span>
                  <div className="grid grid-cols-3 gap-2 text-center text-xs">
                    <div className="bg-[#04070c] p-2 border border-[#1a2333] rounded">
                      <span className="text-gray-500 block text-[10px]">SPF RECORD</span>
                      <span className={audit.email_auth.spf === 'PASS' ? 'text-[#00ff88]' : 'text-red-400'}>
                        {audit.email_auth.spf}
                      </span>
                    </div>
                    <div className="bg-[#04070c] p-2 border border-[#1a2333] rounded">
                      <span className="text-gray-500 block text-[10px]">DKIM SIGNATURE</span>
                      <span className={audit.email_auth.dkim === 'PASS' ? 'text-[#00ff88]' : 'text-red-400'}>
                        {audit.email_auth.dkim}
                      </span>
                    </div>
                    <div className="bg-[#04070c] p-2 border border-[#1a2333] rounded">
                      <span className="text-gray-500 block text-[10px]">DMARC ENFORCEMENT</span>
                      <span className="text-yellow-400">{audit.email_auth.dmarc}</span>
                    </div>
                  </div>
                </div>

                {/* Stylometrics & AV Deepfake Telemetry */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="border border-[#1a2333] bg-[#090e17] rounded-lg p-4 text-xs space-y-2">
                    <span className="font-semibold text-white block">STYLOMETRICS & ENTROPY</span>
                    <div className="flex justify-between"><span>Shannon Entropy:</span> <span className="text-white">{audit.stylometrics.entropy}</span></div>
                    <div className="flex justify-between"><span>Synthetic Probability:</span> <span className="text-red-400">{audit.stylometrics.synthetic_confidence}%</span></div>
                  </div>

                  <div className="border border-[#1a2333] bg-[#090e17] rounded-lg p-4 text-xs space-y-2">
                    <span className="font-semibold text-white block">DEEPFAKE TELEMETRY</span>
                    {audit.deepfake ? (
                      <>
                        <div className="flex justify-between"><span>Blink Delta:</span> <span className="text-red-400">{audit.deepfake.blink_delta_hz} Hz</span></div>
                        <div className="flex justify-between"><span>Synthetic AV Prob:</span> <span className="text-red-400">{audit.deepfake.deepfake_probability}%</span></div>
                      </>
                    ) : (
                      <span className="text-gray-600 block pt-2">No AV payload ingested</span>
                    )}
                  </div>
                </div>

                {/* MITRE ATT&CK Badges */}
                <div className="border border-[#1a2333] bg-[#090e17] rounded-lg p-4">
                  <span className="text-xs font-semibold text-white block mb-2">DETECTED MITRE ATT&CK TTPs</span>
                  <div className="flex flex-wrap gap-2">
                    {audit.mitre_ttps.map((ttp) => (
                      <span key={ttp.id} className="text-[10px] bg-[#1a2333] border border-gray-700 px-2 py-1 rounded text-gray-300">
                        <strong className="text-[#00ff88]">{ttp.id}</strong>: {ttp.name}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </section>
        </div>
      </main>
    </div>
  );
}