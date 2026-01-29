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
    const res = await browser.storage.local.get([key, 'abuseApiKey', 'vpnApiKey']);
    const data = res[key];
    const settings = res;

    if (!data) {
        document.getElementById('loading').textContent = "No analysis data found (Wait for banner).";
        return;
    }

    // --- CHECK PERMISSIONS DYNAMICALLY ---
    const originsNeeded = [];
    if (settings.abuseApiKey) originsNeeded.push("https://api.abuseipdb.com/");
    if (settings.vpnApiKey) originsNeeded.push("https://vpnapi.io/");
    originsNeeded.push("https://ipinfo.io/"); // Always check map

    // We only show the warning if a KEY is present but PERMISSION is missing
    let showPermWarning = false;
    const permissionsToCheck = { origins: [] };

    // Check Abuse
    if (settings.abuseApiKey) {
        const has = await browser.permissions.contains({ origins: ["https://api.abuseipdb.com/"] });
        if (!has) { showPermWarning = true; permissionsToCheck.origins.push("https://api.abuseipdb.com/"); }
    }
    // Check VPN
    if (settings.vpnApiKey) {
        const has = await browser.permissions.contains({ origins: ["https://vpnapi.io/"] });
        if (!has) { showPermWarning = true; permissionsToCheck.origins.push("https://vpnapi.io/"); }
    }
    // Check Map
    const mapHas = await browser.permissions.contains({ origins: ["https://ipinfo.io/"] });
    if (!mapHas) { showPermWarning = true; permissionsToCheck.origins.push("https://ipinfo.io/"); }

    if (showPermWarning) {
        document.getElementById('permissionWarning').style.display = 'block';
        document.getElementById('permBtn').onclick = async () => {
             const granted = await browser.permissions.request(permissionsToCheck);
             if (granted) {
                 document.getElementById('rescanBtn').click();
             }
        };
    } else {
        document.getElementById('permissionWarning').style.display = 'none';
    }

    document.getElementById('loading').style.display = 'none';
    document.getElementById('content').style.display = 'block';

    const net = data.network || {};
    const loc = data.location || {};
    const sec = data.security || {};

    // Use specific flags from background.js
    const missingAbuse = data.missingAbuse; 
    const missingVpn = data.missingVpn;

    const badge = document.getElementById('mainStatus');
    badge.textContent = data.statusText;
    badge.style.backgroundColor = data.theme.border;

    const ipEl = document.getElementById('ipDisplay');
    ipEl.textContent = data.sourceIp;
    
    // Only link if we have Abuse data
    if (!missingAbuse) {
        ipEl.style.cursor = "pointer";
        ipEl.style.textDecoration = "underline";
        ipEl.title = "View full report on AbuseIPDB";
        ipEl.onclick = function() {
            browser.tabs.create({ url: `https://www.abuseipdb.com/check/${data.sourceIp}` });
        };
    } else {
        ipEl.style.textDecoration = "none";
        ipEl.style.cursor = "default";
    }

    const scoreEl = document.getElementById('scoreVal');
    if (missingAbuse) {
        scoreEl.textContent = "N/A";
        scoreEl.style.color = "#999";
        scoreEl.title = "AbuseIPDB Key or Permission missing";
    } else {
        scoreEl.textContent = data.abuseScore + "%";
        scoreEl.style.color = data.abuseScore > 0 ? data.theme.border : '#2e7d32';
    }
    
    // Country is from VPNAPI usually, so check missingVpn or check if data exists
    document.getElementById('countryVal').textContent = loc.country || "Unknown";

    const setFlag = (id, isActive) => {
      const el = document.getElementById(id);
      if (missingVpn) {
          el.textContent = "-"; 
          el.style.color = "#999";
          el.style.fontWeight = "normal";
          return;
      }
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
      }
    };

    setFlag('vpnVal', sec.vpn);
    setFlag('proxyVal', sec.proxy);
    setFlag('torVal', sec.tor);
    setFlag('relayVal', sec.relay);

    const setAuth = (id, val) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = val.toUpperCase();
        if (val === 'pass') {
            el.style.color = '#2e7d32';
            el.style.fontWeight = 'bold';
        } else if (val === 'fail') {
            el.style.color = '#c62828';
            el.style.fontWeight = '900';
        } else if (val === 'softfail' || val === 'none') {
            el.style.color = '#ef6c00';
        }
    };
    const auth = data.auth || { spf: 'none', dkim: 'none', arc: 'none', dmarc: 'none' };
    setAuth('spfVal', auth.spf);
    setAuth('dkimVal', auth.dkim);
    setAuth('dmarcVal', auth.dmarc); 
    setAuth('arcVal', auth.arc);

    if (missingVpn && missingAbuse) {
        // If everything is missing, we don't know much about the network
        document.getElementById('ispVal').textContent = "Auth Only Mode";
        document.getElementById('asnVal').textContent = "";
        document.getElementById('usageVal').textContent = "-";
        document.getElementById('tzVal').textContent = "-";
        document.getElementById('domainVal').textContent = "-";
        document.getElementById('cityVal').textContent = "Unknown";
    } else {
        document.getElementById('ispVal').textContent = net.org || "Unknown ISP";
        document.getElementById('asnVal').textContent = net.asn ? `(${net.asn})` : "";
        document.getElementById('usageVal').textContent = net.usageType || "Unknown";
        document.getElementById('tzVal').textContent = loc.timeZone || "Unknown";
        document.getElementById('domainVal').textContent = net.domain || "N/A";
        const regionStr = loc.region ? `, ${loc.region}` : "";
        document.getElementById('cityVal').textContent = `${loc.city || 'Unknown'}${regionStr}, ${loc.country || 'Unknown'}`;
    }

    // --- ROUTE LIST ---
    const list = document.getElementById('routeList');
    list.textContent = ""; 
    
    if (data.routeData && data.routeData.length > 0) {
        data.routeData.forEach((hop, index) => {
            const row = document.createElement('div');
            row.className = 'hop';
            const ipSpan = document.createElement('span');
            ipSpan.textContent = `${index + 1}. ${hop.ip}`;
            
            const locSpan = document.createElement('span');
            locSpan.style.color = "var(--sub-text)";
            
            let pieces = [];
            if (hop.city && hop.city !== '?') pieces.push(hop.city);
            if (hop.country && hop.country !== '?') pieces.push(hop.country);
            
            if (pieces.length > 0) {
                locSpan.textContent = pieces.join(", ");
            } else {
                locSpan.textContent = "";
            }

            row.appendChild(ipSpan);
            row.appendChild(locSpan);
            list.appendChild(row);
        });
    } else {
        list.textContent = "No route hops detected.";
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