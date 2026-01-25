async function loadData() {
  let tabs = await browser.tabs.query({ active: true, currentWindow: true });
  let tab = tabs[0];
  let message = await browser.messageDisplay.getDisplayedMessage(tab.id);
  
  if (!message) {
      document.getElementById('loading').innerText = "No email selected.";
      return;
  }

  const key = 'analysis_' + message.id;
  const res = await browser.storage.local.get(key);
  const data = res[key];

  if (!data) {
      document.getElementById('loading').innerText = "No analysis data found (Wait for banner).";
      return;
  }

  document.getElementById('loading').style.display = 'none';
  document.getElementById('content').style.display = 'block';

  // Header
  const badge = document.getElementById('mainStatus');
  badge.innerText = data.statusText;
  badge.style.backgroundColor = data.theme.border;
  document.getElementById('ipDisplay').innerText = data.sourceIp;

  // Threat Intel
  const scoreEl = document.getElementById('scoreVal');
  scoreEl.innerText = data.abuseScore + "%";
  scoreEl.style.color = data.abuseScore > 0 ? data.theme.border : '#2e7d32';
  
  document.getElementById('countryVal').innerText = data.location.country;
  
  const setFlag = (id, isActive) => {
    const el = document.getElementById(id);
    if (id === 'vpnVal' && data.isAllowedCloud && isActive) {
        el.innerText = "CLOUD";
        el.style.color = '#2e7d32';
        el.style.fontWeight = '900';
        return;
    }
    el.innerText = isActive ? "YES" : "No";
    if (isActive) {
        el.style.color = '#c62828';
        el.style.fontWeight = '900';
    } else {
        el.style.removeProperty('color');
        el.style.removeProperty('font-weight');
    }
  };

  const sec = data.security;
  setFlag('vpnVal', sec.vpn);
  setFlag('proxyVal', sec.proxy);
  setFlag('torVal', sec.tor);
  setFlag('relayVal', sec.relay);

  // Network
// Network Context
  document.getElementById('ispVal').innerText = data.network.org || "Unknown ISP";
  document.getElementById('asnVal').innerText = data.network.asn ? `(${data.network.asn})` : "";
  
  document.getElementById('usageVal').innerText = data.network.usageType;
  document.getElementById('tzVal').innerText = data.location.timeZone || "Unknown";
  document.getElementById('domainVal').innerText = data.network.domain || "N/A";
  
  const regionStr = data.location.region ? `, ${data.location.region}` : "";
  document.getElementById('cityVal').innerText = `${data.location.city}${regionStr}, ${data.location.country}`;

  // Route List
  const list = document.getElementById('routeList');
  list.innerHTML = "";
  if (data.routeData && data.routeData.length > 0) {
      data.routeData.forEach((hop, index) => {
          const row = document.createElement('div');
          row.className = 'hop';
          let pieces = [];
          if (hop.city) pieces.push(hop.city);
          if (hop.region) pieces.push(hop.region);
          if (hop.country) pieces.push(hop.country);
          const locString = pieces.length > 0 ? pieces.join(", ") : "Unknown Location";

          row.innerHTML = `
            <span>${index + 1}. ${hop.ip}</span>
            <span style="color: var(--sub-text)">${locString}</span>
          `;
          list.appendChild(row);
      });
  } else {
      list.innerText = "No route hops available.";
  }
}

document.getElementById('settingsBtn').addEventListener('click', () => {
    browser.runtime.openOptionsPage();
});

document.getElementById('rescanBtn').addEventListener('click', async () => {
    const btn = document.getElementById('rescanBtn');
    btn.innerText = "Scanning...";
    btn.disabled = true;
    await browser.runtime.sendMessage({ command: "forceRescan" });
    setTimeout(() => { window.close(); }, 1000);
});

loadData();