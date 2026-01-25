browser.messageDisplay.onMessageDisplayed.addListener(async (tabId, messageId) => {
  
  // 1. Load Keys
  const settings = await browser.storage.local.get(['abuseApiKey', 'vpnApiKey', 'ipinfoToken']);
  if (!settings.abuseApiKey || !settings.vpnApiKey) return; 

  // 2. Get Headers & Extract Chain
  const fullMessage = await browser.messages.getFull(messageId.id);
  const headers = fullMessage.headers;
  const receivedHeaders = headers['received'] || [];
  
  // Regex for Public IPs Only
  const publicIpRegex = /\b(?!(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.))((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;

  let hopIps = [];
  
  // Extract ALL public IPs from the chain (Top = Recipient, Bottom = Source)
  // We reverse it so [0] is Source and [Length] is Destination
  for (let i = receivedHeaders.length - 1; i >= 0; i--) {
    const match = receivedHeaders[i].match(publicIpRegex);
    if (match) hopIps.push(match[0]);
  }

  // If no public IPs found, exit
  if (hopIps.length === 0) return;

  const sourceIp = hopIps[0]; // The Origin

  // 3. Prepare URLs
  let ipinfoBaseUrl = "https://ipinfo.io/";
  const ipinfoSuffix = settings.ipinfoToken ? `/json?token=${settings.ipinfoToken}` : "/json";

  try {
    // 4. Run Checks
    // Security Check (Source Only)
    const securityPromise = Promise.all([
        fetch(`https://vpnapi.io/api/${sourceIp}?key=${settings.vpnApiKey}`).then(r => r.json()),
        fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${sourceIp}&maxAgeInDays=90`, {
          headers: { 'Key': settings.abuseApiKey, 'Accept': 'application/json' }
        }).then(r => r.json())
    ]);

    // Path Mapping (All Hops) - Fetch in parallel
    const mapPromise = Promise.all(
        hopIps.map(ip => fetch(ipinfoBaseUrl + ip + ipinfoSuffix).then(r => r.json()).catch(e => ({ ip: ip, country: '?' })))
    );

    const [[vpnRes, abuseRes], routeData] = await Promise.all([securityPromise, mapPromise]);

    const security = vpnRes.security;
    const abuse = abuseRes.data;

    // 5. Logic & Scoring
    const isVpn = security.vpn || security.tor || security.proxy;
    const abuseScore = abuse.abuseConfidenceScore;
    
    // Determine Color Theme
    let theme = { bg: '#e8f5e9', border: '#2e7d32', text: '#1b5e20' }; // Green
    let statusText = "CLEAN";

    if (abuseScore > 50) {
        theme = { bg: '#ffebee', border: '#c62828', text: '#b71c1c' }; // Red
        statusText = "HIGH RISK";
    } else if (isVpn || abuseScore > 15) {
        theme = { bg: '#fff3e0', border: '#ef6c00', text: '#e65100' }; // Orange
        statusText = "CAUTION";
    }

    // 6. Build Route String (e.g. "CN -> US -> US")
    const routeString = routeData
        .map(h => `<span title="${h.org || 'Unknown ISP'}">${h.country || '??'}</span>`)
        .join(' &rarr; ');

    // 7. Inject UI
    browser.messageDisplayScripts.register({
      messages: [messageId.id],
      js: [{
        code: `
          (function() {
            if (document.getElementById('eagle-eye-bar')) return;
            
            const box = document.createElement('div');
            box.id = 'eagle-eye-bar';
            box.style = "font-family: 'Segoe UI', system-ui, sans-serif; padding: 10px 15px; margin-bottom: 10px; border-left: 6px solid ${theme.border}; background: ${theme.bg}; color: #333; box-shadow: 0 1px 3px rgba(0,0,0,0.1);";
            
            box.innerHTML = \`
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
                <div>
                   <strong style="color: ${theme.text}; font-size: 1.1em;">${statusText}</strong>
                   <span style="color: #999; margin: 0 8px;">|</span>
                   <strong>Source:</strong> ${vpnRes.location.country_code} (${vpnRes.network.autonomous_system_organization})
                </div>
                <div style="font-size: 0.9em;">
                   <strong>Abuse Score:</strong> ${abuseScore}% 
                   <span style="color: #999; margin: 0 5px;">|</span>
                   VPN: <b>${security.vpn ? 'YES' : 'No'}</b>
                </div>
              </div>
              
              <div style="font-size: 0.85em; color: #555; display: flex; align-items: center;">
                 <strong style="margin-right: 8px;">Route:</strong> 
                 ${routeString}
                 <span style="flex-grow: 1;"></span>
                 <span style="opacity: 0.7;">Source IP: ${sourceIp}</span>
              </div>
            \`;
            
            document.body.prepend(box);
          })();
        `
      }]
    });

  } catch (err) {
    console.error("EagleEye Analysis Failed:", err);
  }
});