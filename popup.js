async function loadData() {
  try {
    let tabs = await browser.tabs.query({ active: true, currentWindow: true });
    let tab = tabs[0];
    let message = await browser.messageDisplay.getDisplayedMessage(tab.id);
    
    if (!message) {
        document.getElementById('loading').textContent = "No email selected.";
        return;
    }

    const key = 'analysis_' + message.id;
    const res = await browser.storage.local.get(key);
    const data = res[key];

    if (!data) {
        document.getElementById('loading').textContent = "No analysis data found (Wait for banner).";
        return;
    }

    document.getElementById('loading').style.display = 'none';
    document.getElementById('content').style.display = 'block';

    const net = data.network || {};
    const loc = data.location || {};
    const sec = data.security || {};

    // --- HEADER ---
    const badge = document.getElementById('mainStatus');
    badge.textContent = data.statusText;
    badge.style.backgroundColor = data.theme.border;

    // --- CLICKABLE IP LOGIC START ---
    const ipEl = document.getElementById('ipDisplay');
    ipEl.textContent = data.sourceIp;
    
    // Make it look and act like a link
    ipEl.style.cursor = "pointer";
    ipEl.style.textDecoration = "underline";
    ipEl.title = "View full report on AbuseIPDB";
    
    ipEl.onclick = function() {
        browser.tabs.create({ 
            url: `https://www.abuseipdb.com/check/${data.sourceIp}` 
        });
    };
    // --- CLICKABLE IP LOGIC END ---

    // Threat Intel
    const scoreEl = document.getElementById('scoreVal');
    scoreEl.textContent = data.abuseScore + "%";
    scoreEl.style.color = data.abuseScore > 0 ? data.theme.border : '#2e7d32';
    
    document.getElementById('countryVal').textContent = loc.country || "Unknown";
    
    const setFlag = (id, isActive) => {
      const el = document.getElementById(id);
      if (id === 'vpnVal' && data.isAllowedCloud && isActive) {
          el.textContent = "CLOUD";
          el.style.color = '#2e7d32';
          el.style.fontWeight = '900';
          return;
      }
      el.textContent = isActive ? "YES" : "No";
      if (isActive) {
          el.style.color = '#c62828';
          el.style.fontWeight = '900';
      } else {
          el.style.removeProperty('color');
          el.style.removeProperty('font-weight');
      }
    };

    setFlag('vpnVal', sec.vpn);
    setFlag('proxyVal', sec.proxy);
    setFlag('torVal', sec.tor);
    setFlag('relayVal', sec.relay);

    // --- AUTHENTICATION UI ---
    // Make sure your popup.html has elements with these IDs (we will add them next)
    const setAuth = (id, val) => {
        const el = document.getElementById(id);
        if (!el) return; // Safety
        
        el.textContent = val.toUpperCase();
        
        if (val === 'pass') {
            el.style.color = '#2e7d32'; // Green
            el.style.fontWeight = 'bold';
        } else if (val === 'fail') {
            el.style.color = '#c62828'; // Red
            el.style.fontWeight = '900';
        } else if (val === 'softfail' || val === 'none') {
            el.style.color = '#ef6c00'; // Orange/Grey
        }
    };

    const auth = data.auth || { spf: 'none', dkim: 'none', arc: 'none', dmarc: 'none' };
    
    setAuth('spfVal', auth.spf);
    setAuth('dkimVal', auth.dkim);
    setAuth('dmarcVal', auth.dmarc); 
    setAuth('arcVal', auth.arc);

    // Network Context
    document.getElementById('ispVal').textContent = net.org || "Unknown ISP";
    document.getElementById('asnVal').textContent = net.asn ? `(${net.asn})` : "";
    document.getElementById('usageVal').textContent = net.usageType || "Unknown";
    document.getElementById('tzVal').textContent = loc.timeZone || "Unknown";
    document.getElementById('domainVal').textContent = net.domain || "N/A";
    
    const regionStr = loc.region ? `, ${loc.region}` : "";
    document.getElementById('cityVal').textContent = `${loc.city || 'Unknown'}${regionStr}, ${loc.country || 'Unknown'}`;

    // Route List (Secure DOM Creation)
    const list = document.getElementById('routeList');
    list.textContent = ""; // Clear list
    
    if (data.routeData && data.routeData.length > 0) {
        data.routeData.forEach((hop, index) => {
            const row = document.createElement('div');
            row.className = 'hop';

            const ipSpan = document.createElement('span');
            ipSpan.textContent = `${index + 1}. ${hop.ip}`;

            const locSpan = document.createElement('span');
            locSpan.style.color = "var(--sub-text)";
            
            let pieces = [];
            if (hop.city) pieces.push(hop.city);
            if (hop.region) pieces.push(hop.region);
            if (hop.country) pieces.push(hop.country);
            locSpan.textContent = pieces.length > 0 ? pieces.join(", ") : "Unknown Location";

            row.appendChild(ipSpan);
            row.appendChild(locSpan);
            list.appendChild(row);
        });
    } else {
        list.textContent = "No route hops available.";
    }

  } catch (e) {
    console.error("Popup Error:", e);
    document.getElementById('loading').textContent = "Error loading data. Try rescanning.";
  }
}

document.getElementById('settingsBtn').addEventListener('click', () => {
    browser.runtime.openOptionsPage();
});

document.getElementById('rescanBtn').addEventListener('click', async () => {
    const btn = document.getElementById('rescanBtn');
    btn.textContent = "Scanning...";
    btn.disabled = true;
    await browser.runtime.sendMessage({ command: "forceRescan" });
    setTimeout(() => { window.close(); }, 1000);
});

loadData();