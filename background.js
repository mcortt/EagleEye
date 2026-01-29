// Register Global Injector
browser.messageDisplayScripts.register({ js: [{ file: "injector.js" }] });

// Listen for messages from Popup (Rescan)
browser.runtime.onMessage.addListener(async (request, sender) => {
    if (request.command === "forceRescan") {
        const tab = (await browser.tabs.query({ active: true, currentWindow: true }))[0];
        const message = await browser.messageDisplay.getDisplayedMessage(tab.id);
        if (message) {
            await analyzeMessage(tab.id, message.id, true);
            return { status: "started" };
        }
    }
});

browser.messageDisplay.onMessageDisplayed.addListener(async (tab, message) => {
    await analyzeMessage(tab.id, message.id, false);
});

async function analyzeMessage(tabId, messageId, bypassCache) {
  const settings = await browser.storage.local.get([
      'abuseApiKey', 'vpnApiKey', 'ipinfoToken', 'countryBlacklist', 
      'enableMap', 'bannerMode', 'cloudWhitelist', 'customCloud', 'riskThreshold'
  ]);
  
  // --- STEP 1: FETCH HEADERS ---
  const fullMessage = await browser.messages.getFull(messageId);
  const headers = fullMessage.headers;
  
  // --- AUTH EXTRACTION ---
  const stdAuth = headers['authentication-results'] || headers['Authentication-Results'] || [];
  const arcAuth = headers['arc-authentication-results'] || headers['ARC-Authentication-Results'] || [];
  const stdArray = Array.isArray(stdAuth) ? stdAuth : [stdAuth];
  const arcArray = Array.isArray(arcAuth) ? arcAuth : [arcAuth];
  const authHeaderString = [...stdArray, ...arcArray].filter(Boolean).join(' ');
  const auth = parseAuthHeader(authHeaderString);

  // --- IP EXTRACTION ---
  const receivedHeaders = headers['received'] || [];
  const ipv4Regex = /\b(?!(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.))(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b/;
  const ipv6Regex = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/;

  let hopIps = [];
  for (let i = receivedHeaders.length - 1; i >= 0; i--) {
    const line = receivedHeaders[i];
    const matchV4 = line.match(ipv4Regex);
    if (matchV4) { hopIps.push(matchV4[0]); continue; }
    const matchV6 = line.match(ipv6Regex);
    if (matchV6 && !matchV6[0].startsWith('fe80') && matchV6[0] !== '::1') { hopIps.push(matchV6[0]); }
  }

  if (hopIps.length === 0) return;
  const sourceIp = hopIps[0];

  // --- STEP 2: CACHE CHECK ---
  const cacheKey = `cache_${sourceIp}`;
  if (!bypassCache) {
      const cached = await browser.storage.local.get(cacheKey);
      if (cached[cacheKey]) {
          const entry = cached[cacheKey];
          if (Date.now() - entry.timestamp < 86400000) {
              console.log(`EagleEye: Using Cached Data for ${sourceIp}`);
              processAndDisplay(entry.data, settings, messageId, tabId, sourceIp, auth);
              return;
          }
      }
  }

  // --- STEP 3: CONDITIONAL FETCHING (Decoupled) ---
  try {
    console.log(`EagleEye: Analyzing ${sourceIp}...`);

    let vpnRes = {};
    let abuseRes = { data: { abuseConfidenceScore: 0 } };
    let routeData = [];
    
    // --- CHECK ABUSEIPDB (Risk Score) ---
    let canCheckAbuse = false;
    if (settings.abuseApiKey) {
        canCheckAbuse = await browser.permissions.contains({ origins: ["https://api.abuseipdb.com/*"] });
    }

    // --- CHECK VPNAPI (VPN/Proxy) ---
    let canCheckVpn = false;
    if (settings.vpnApiKey) {
        canCheckVpn = await browser.permissions.contains({ origins: ["https://vpnapi.io/*"] });
    }

    const securityPromises = [];

    // 1. VPN Check
    if (canCheckVpn) {
        securityPromises.push(
            fetch(`https://vpnapi.io/api/${sourceIp}?key=${settings.vpnApiKey}`)
            .then(r => r.json())
            .catch(() => ({}))
        );
    } else {
        securityPromises.push(Promise.resolve({}));
    }

    // 2. Abuse Check
    if (canCheckAbuse) {
        securityPromises.push(
            fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${sourceIp}&maxAgeInDays=90`, {
              headers: { 'Key': settings.abuseApiKey, 'Accept': 'application/json' }
            })
            .then(r => r.json())
            .catch(() => ({ data: { abuseConfidenceScore: 0 } }))
        );
    } else {
        securityPromises.push(Promise.resolve({ data: { abuseConfidenceScore: 0 } }));
    }

    // --- CHECK IPINFO (Map) ---
    let mapPromise = Promise.resolve(hopIps.map(ip => ({ ip: ip })));
    if (settings.enableMap !== false) {
         const mapPerm = await browser.permissions.contains({ origins: ["https://ipinfo.io/*"] });
         if (mapPerm) {
             let ipinfoSuffix = "/json";
             if (settings.ipinfoToken) ipinfoSuffix += `?token=${settings.ipinfoToken}`;
             
             mapPromise = Promise.all(
                hopIps.map(ip => fetch("https://ipinfo.io/" + ip + ipinfoSuffix)
                    .then(r => r.json())
                    .then(json => ({ ...json, ip })) 
                    .catch(e => ({ ip: ip, city: '?', region: '?', country: '?' }))
                )
             );
         }
    }

    const [vpnResult, abuseResult] = await Promise.all(securityPromises);
    const routeResult = await mapPromise;

    vpnRes = vpnResult;
    abuseRes = abuseResult;
    routeData = routeResult;

    // We pass flags to processAndDisplay so it knows what was missing (Key vs. just 0 result)
    const rawData = { vpnRes, abuseRes, routeData, missingAbuse: !canCheckAbuse, missingVpn: !canCheckVpn };

    await browser.storage.local.set({ 
        [cacheKey]: { timestamp: Date.now(), data: rawData } 
    });

    processAndDisplay(rawData, settings, messageId, tabId, sourceIp, auth);

  } catch (err) {
    console.error("EagleEye Error:", err);
  }
}

async function processAndDisplay(rawData, settings, messageId, tabId, sourceIp, auth) {
    const { vpnRes, abuseRes, routeData, missingAbuse, missingVpn } = rawData;
    auth = auth || { spf: 'none', dkim: 'none', arc: 'none' };
    
    const security = vpnRes.security || {};
    const location = vpnRes.location || {};
    const rawNetwork = vpnRes.network || {}; 
    const abuse = abuseRes.data || { abuseConfidenceScore: 0 };
    
    const countryCode = location.country_code || "XX";
    const asn = rawNetwork.autonomous_system_number || "";
    const usageType = abuse.usageType || "Unknown";
    const domain = abuse.domain || "";
    const timeZone = location.time_zone || "";
    const org = (rawNetwork.autonomous_system_organization || "").toUpperCase();
    const abuseScore = abuse.abuseConfidenceScore || 0;

    const threshold = (settings.riskThreshold !== undefined) ? settings.riskThreshold : 50;
    
    const blacklist = (settings.countryBlacklist || "").split(',').map(s => s.trim().toUpperCase());
    const isBlacklisted = blacklist.includes(countryCode);
    const isVpn = security.vpn || security.tor || security.proxy || security.relay;
    
    let allowedProviders = settings.cloudWhitelist || ["AMAZON", "GOOGLE", "MICROSOFT", "CLOUDFLARE", "ORACLE", "IBM", "SALESFORCE", "RACKSPACE"];
    if (settings.customCloud) {
        const customList = settings.customCloud.split(',').map(s => s.trim().toUpperCase()).filter(s => s.length > 0);
        allowedProviders = [...allowedProviders, ...customList];
    }
    const isAllowedCloud = allowedProviders.some(provider => org.includes(provider));

    // --- RISK HIERARCHY ---
    let theme = { bg: '#e8f5e9', border: '#2e7d32', text: '#1b5e20' }; 
    let statusText = "CLEAN";
    let riskLevel = "clean"; 

    const isSpoofed = (auth.spf === 'fail' && auth.arc !== 'pass');
    const isTampered = (auth.dkim === 'fail');

    // 1. RED
    // Note: If missingAbuse is true, abuseScore is 0, so it won't trigger red unless other factors apply.
    if (isBlacklisted || (!missingAbuse && abuseScore >= threshold) || isTampered || isSpoofed) {
        theme = { bg: '#ffebee', border: '#b71c1c', text: '#b71c1c' };
        riskLevel = "high";
        
        if (isBlacklisted) statusText = "BLOCKED COUNTRY";
        else if (isTampered) statusText = "SECURITY FAIL (DKIM)";
        else if (isSpoofed) statusText = "SPOOF DETECTED (SPF)";
        else statusText = "HIGH RISK SENDER";
    } 
    // 2. ORANGE
    else if ((!missingAbuse && abuseScore > 15) || (isVpn && !isAllowedCloud) || auth.spf === 'softfail' || auth.dmarc === 'fail') {
        theme = { bg: '#fff3e0', border: '#ef6c00', text: '#e65100' };
        riskLevel = "caution";

        if (auth.spf === 'softfail' || auth.dmarc === 'fail' || auth.arc === 'fail') statusText = "CAUTION: AUTH ISSUE";
        else if (isVpn) statusText = "CAUTION: HIDDEN IDENTITY";
        else statusText = "CAUTION: SUSPICIOUS IP";
    } 
    // 3. GREEN
    else {
        // If we have no API keys at all, we fall back to "AUTH VALID"
        if (missingAbuse && missingVpn) {
            statusText = "AUTH VALID (NO API)";
        } else if (isAllowedCloud && isVpn) {
            statusText = "CLOUD SERVER";
        } else {
            statusText = "CLEAN SENDER";
        }
    }

    let badgeColor = "#2e7d32";
    if (riskLevel === 'high') badgeColor = "#c62828";
    if (riskLevel === 'caution') badgeColor = "#ef6c00";

    // Badge Logic
    let badgeText = (!missingAbuse) ? abuseScore.toString() : ((riskLevel === 'clean') ? "OK" : "!");
    if (isBlacklisted) badgeText = "!";

    browser.messageDisplayAction.setBadgeText({ tabId: tabId, text: badgeText });
    browser.messageDisplayAction.setBadgeBackgroundColor({ tabId: tabId, color: badgeColor });
    browser.messageDisplayAction.setBadgeTextColor({ tabId: tabId, color: "#ffffff" });

    // Save Data with specific missing flags
    const analysisData = {
        timestamp: Date.now(),
        theme, statusText, riskLevel,
        location: { 
            country: location.country || "Unknown", 
            code: countryCode, 
            city: location.city || "Unknown", 
            region: location.region || "",
            timeZone
        },
        network: { org, asn, domain, usageType },
        abuseScore, security, routeData, sourceIp, isAllowedCloud, auth,
        missingAbuse, // Flag for Risk Score UI
        missingVpn    // Flag for VPN UI
    };

    await browser.storage.local.set({ ['analysis_' + messageId]: analysisData });

    const mode = settings.bannerMode || 'always';
    let shouldShow = false;
    if (mode === 'always') shouldShow = true;
    else if (mode === 'never') shouldShow = false;
    else if (mode === 'high_risk' && riskLevel === 'high') shouldShow = true;
    else if (mode === 'caution' && (riskLevel === 'caution' || riskLevel === 'high')) shouldShow = true;

    if (shouldShow) {
        let bannerData = JSON.parse(JSON.stringify(analysisData));
        if (analysisData.isAllowedCloud) bannerData.security.vpn = false; 

        setTimeout(() => {
            browser.tabs.sendMessage(tabId, {
                command: "eagleEyeRender",
                data: bannerData
            }).catch(() => {});
        }, 500);
    }
}

// Garbage Collector
browser.runtime.onStartup.addListener(cleanupStorage);
browser.runtime.onInstalled.addListener(cleanupStorage);

async function cleanupStorage() {
    console.log("EagleEye: Running Storage Cleanup...");
    const allData = await browser.storage.local.get(null);
    const keysToDelete = [];
    const now = Date.now();
    const protectedKeys = ['abuseApiKey', 'vpnApiKey', 'ipinfoToken', 'countryBlacklist', 'enableMap', 'bannerMode', 'cloudWhitelist', 'customCloud', 'riskThreshold'];
    const CACHE_TTL = 7 * 24 * 60 * 60 * 1000; 
    const ANALYSIS_TTL = 24 * 60 * 60 * 1000; 

    for (const [key, value] of Object.entries(allData)) {
        if (protectedKeys.includes(key)) continue;
        if (key.startsWith('cache_')) {
            if (value.timestamp && (now - value.timestamp > CACHE_TTL)) keysToDelete.push(key);
        } else if (key.startsWith('analysis_')) {
            if (!value.timestamp || (now - value.timestamp > ANALYSIS_TTL)) keysToDelete.push(key);
        }
    }
    if (keysToDelete.length > 0) await browser.storage.local.remove(keysToDelete);
}

function parseAuthHeader(headerValue) {
    if (!headerValue) return { spf: 'none', dkim: 'none', arc: 'none', dmarc: 'none' };
    const extract = (key) => {
        const regex = new RegExp(`\\b${key}\\s*=\\s*"?([a-z0-9.-]+)"?`, 'gi');
        const matches = [...headerValue.matchAll(regex)];
        if (matches.length === 0) return 'none';
        for (const m of matches) {
            if (m[1].toLowerCase() === 'pass') return 'pass';
        }
        return matches[0][1].toLowerCase();
    };
    return {
        spf: extract('spf'),
        dkim: extract('dkim'),
        dmarc: extract('dmarc'),
        arc: extract('arc')
    };
}