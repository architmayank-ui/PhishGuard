function scan() {
  const urlText = document.getElementById("urlInput").value.trim();
  const resultBox = document.getElementById("result");
  const detailList = document.getElementById("details");
  const scoreText = document.getElementById("score");

  detailList.innerHTML = "";
  let risk = 0;

  let url;
  try {
    url = new URL(urlText);
  } catch {
    alert("Please enter a valid URL (example: https://example.com)");
    return;
  }

  const hostname = url.hostname;

  // -------- Heuristic Checks --------
  const checks = [];

  // 1. HTTPS?
  if (url.protocol !== "https:") {
    checks.push({msg:"Site is not using HTTPS", risk:15, level:"bad"});
    risk += 15;
  } else {
    checks.push({msg:"Uses HTTPS", risk:0, level:"good"});
  }

  // 2. IP address instead of domain?
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    checks.push({msg:"URL uses an IP address instead of a domain name", risk:20, level:"bad"});
    risk += 20;
  }

  // 3. Punycode
  if (hostname.includes("xn--")) {
    checks.push({msg:"Domain uses punycode (can hide look-alike characters)", risk:15, level:"warn"});
    risk += 15;
  }

  // 4. Long domain / many subdomains
  const subdomainCount = hostname.split(".").length - 2;
  if (subdomainCount > 2) {
    checks.push({msg:"Unusually long domain with many subdomains", risk:10, level:"warn"});
    risk += 10;
  }

  // 5. Hyphens
  if (hostname.split("-").length - 1 >= 2) {
    checks.push({msg:"Contains multiple hyphens (common in phishing domains)", risk:10, level:"warn"});
    risk += 10;
  }

  // 6. Risky TLDs
  const riskyTLDs = ["xyz","top","tk","gq","ml","work","zip","cam"];
  const tld = hostname.split(".").pop();
  if (riskyTLDs.includes(tld)) {
    checks.push({msg:`Domain ends with .${tld} (often abused)`, risk:10, level:"warn"});
    risk += 10;
  }

  // 7. Fake brand usage
  const brands = ["google","paypal","facebook","amazon","apple","bank"];
  const isBrand = brands.some(b => hostname.includes(b));
  if (isBrand && !hostname.endsWith(".com") && !hostname.endsWith(".in")) {
    checks.push({msg:"Domain name contains a famous brand but not the official domain", risk:20, level:"bad"});
    risk += 20;
  }

  // -------- Show Results --------
  resultBox.classList.remove("hidden");

  let riskLabel = "";
  if (risk <= 15) riskLabel = "Low Risk";
  else if (risk <= 35) riskLabel = "Medium Risk";
  else riskLabel = "High Risk ⚠️";

  scoreText.innerHTML = `<strong>Total Risk Score:</strong> ${risk} — <span class="${
    risk > 35 ? "bad" : risk > 15 ? "warn" : "good"
  }">${riskLabel}</span>`;

  checks.forEach(c => {
    const li = document.createElement("li");
    li.className = c.level;
    li.textContent = c.msg;
    detailList.appendChild(li);
  });
}
