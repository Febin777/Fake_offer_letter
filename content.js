// Floating quick-scan button injected into recruitment pages
const scanBtn = document.createElement("button");
scanBtn.innerText = "🛡️ SENTINEL SCAN";
scanBtn.style.position = "fixed";
scanBtn.style.bottom = "20px";
scanBtn.style.right = "20px";
scanBtn.style.zIndex = "99999";
scanBtn.style.backgroundColor = "#06090e";
scanBtn.style.color = "#00ff88";
scanBtn.style.border = "1px solid #00ff88";
scanBtn.style.padding = "8px 16px";
scanBtn.style.fontFamily = "monospace";
scanBtn.style.fontSize = "12px";
scanBtn.style.cursor = "pointer";
scanBtn.style.borderRadius = "4px";
scanBtn.style.boxShadow = "0 0 10px rgba(0,255,136,0.3)";

scanBtn.onclick = async () => {
  const selectedText = window.getSelection().toString() || document.body.innerText.substring(0, 1000);
  
  const fd = new FormData();
  fd.append("raw_payload", selectedText);
  fd.append("target_domain", window.location.hostname);

  try {
    const res = await fetch("http://localhost:8000/api/audit", { method: "POST", body: fd });
    const data = await res.json();
    alert(`SENTINEL ALERT:\nScore: ${data.composite_threat_score}/100\nSynthetic Prob: ${data.stylometrics.synthetic_confidence}%\nPolygon Hash: ${data.blockchain_receipt.polygon_tx_hash}`);
  } catch (err) {
    alert("Sentinel daemon is offline. Ensure FastAPI is running on port 8000.");
  }
};

document.body.appendChild(scanBtn);