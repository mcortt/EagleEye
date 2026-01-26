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
  
    if (!settings.abuseApiKey || !settings.vpnApiKey) {
      const errorData = {
          statusText: "API KEYS MISSING",
          theme: { bg: '#ffebee', border: '#b71c1c', text: '#b71c1c' },
          error: "setup_required",
          sourceIp: "0.0.0.0"
      };
      
      // Save this to the specific message ID so the popup can see it
      await browser.storage.local.set({ ['analysis_' + messageId]: errorData });
      
      // Update the toolbar badge to a warning "!"
      browser.messageDisplayAction.setBadgeText({ tabId: tabId, text: "!" });
      browser.messageDisplayAction.setBadgeBackgroundColor({ tabId: tabId, color: "#b71c1c" });
      return;
    }
  // --- STEP 1: ALWAYS FETCH HEADERS FIRST (Moved up) ---
  // We need these for Auth results AND to find the IP.
  const fullMessage = await browser.messages.getFull(messageId);
  const headers = fullMessage.headers;
  
// --- v1.1 AUTH EXTRACTION (The Dragnet) ---
  // We need to grab both standard Auth results AND specific ARC Auth results.
  // Microsoft often puts the ARC 'pass' in a separate 'arc-authentication-results' header.
  
  const stdAuth = headers['authentication-results'] || headers['Authentication-Results'] || [];
  const arcAuth = headers['arc-authentication-results'] || headers['ARC-Authentication-Results'] || [];

  // Normalize both to arrays (in case there is only one header string)
  const stdArray = Array.isArray(stdAuth) ? stdAuth : [stdAuth];
  const arcArray = Array.isArray(arcAuth) ? arcAuth : [arcAuth];

  // Merge them all into one giant string.
  // We filter(Boolean) to remove any null/undefined entries if a header is missing.
  const authHeaderString = [...stdArray, ...arcArray].filter(Boolean).join(' ');
  
  // Now parse the giant block
  const auth = parseAuthHeader(authHeaderString);

  // IP EXTRACTION
  const receivedHeaders = headers['received'] || [];
  const ipv4Regex = /\b(?!(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.))(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b/;
  const ipv6Regex = /([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])/;

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

  // --- STEP 2: CACHE CHECK (Now includes 'auth') ---
  const cacheKey = `cache_${sourceIp}`;
  if (!bypassCache) {
      const cached = await browser.storage.local.get(cacheKey);
      if (cached[cacheKey]) {
          const entry = cached[cacheKey];
          // 24 Hour Expiry
          if (Date.now() - entry.timestamp < 86400000) {
              console.log(`EagleEye: Using Cached Data for ${sourceIp}`);
              // FIX: Pass the fresh 'auth' variable we just parsed
              processAndDisplay(entry.data, settings, messageId, tabId, sourceIp, auth);
              return;
          }
      }
  }

  try {
    console.log(`EagleEye: Fetching Fresh Data for ${sourceIp}...`);
    const securityPromise = Promise.all([
        fetch(`https://vpnapi.io/api/${sourceIp}?key=${settings.vpnApiKey}`).then(r => r.json()),
        fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${sourceIp}&maxAgeInDays=90`, {
          headers: { 'Key': settings.abuseApiKey, 'Accept': 'application/json' }
        }).then(r => r.json())
    ]);

    let mapPromise = Promise.resolve([]); 
    if (settings.enableMap !== false) {
        let ipinfoSuffix = settings.ipinfoToken ? `/json?token=${settings.ipinfoToken}` : "/json";
        mapPromise = Promise.all(
            hopIps.map(ip => fetch("https://ipinfo.io/" + ip + ipinfoSuffix)
                .then(r => r.json())
                .catch(e => ({ ip: ip, city: '?', region: '?', country: '?' }))
            )
        );
    }

    const [[vpnRes, abuseRes], routeData] = await Promise.all([securityPromise, mapPromise]);
    const rawData = { vpnRes, abuseRes, routeData };

    await browser.storage.local.set({ 
        [cacheKey]: { timestamp: Date.now(), data: rawData } 
    });

    // FIX: Pass 'auth' here too
    processAndDisplay(rawData, settings, messageId, tabId, sourceIp, auth);

  } catch (err) {
    console.error("EagleEye Error:", err);
  }
}
async function processAndDisplay(rawData, settings, messageId, tabId, sourceIp, auth) {
    const { vpnRes, abuseRes, routeData } = rawData;
    auth = auth || { spf: 'none', dkim: 'none', arc: 'none' };
    
    // Raw API Data
    const security = vpnRes.security || {};
    const location = vpnRes.location || {};
    const rawNetwork = vpnRes.network || {}; // Renamed to avoid confusion
    const abuse = abuseRes.data || { abuseConfidenceScore: 0 };
    const countryCode = location.country_code || "XX";
    const threshold = (settings.riskThreshold !== undefined) ? settings.riskThreshold : 50;

    // Extract Specific Fields
    const asn = rawNetwork.autonomous_system_number || "";
    const usageType = abuse.usageType || "Unknown Usage";
    const domain = abuse.domain || "";
    const timeZone = location.time_zone || "";
    
    const blacklist = (settings.countryBlacklist || "").split(',').map(s => s.trim().toUpperCase());
    const isBlacklisted = blacklist.includes(countryCode);
    
    let isVpn = security.vpn || security.tor || security.proxy || security.relay;
    
    // -- CLOUD ALLOWLIST LOGIC --
    let allowedProviders = settings.cloudWhitelist || [
        "AMAZON", "GOOGLE", "MICROSOFT", "CLOUDFLARE", 
        "ORACLE", "IBM", "SALESFORCE", "RACKSPACE"
    ];
     
    if (settings.customCloud) {
        const customList = settings.customCloud.split(',').map(s => s.trim().toUpperCase()).filter(s => s.length > 0);
        allowedProviders = [...allowedProviders, ...customList];
    }

    const org = (rawNetwork.autonomous_system_organization || "").toUpperCase();
    const isAllowedCloud = allowedProviders.some(provider => org.includes(provider));

    const abuseScore = abuse.abuseConfidenceScore;
    let theme = { bg: '#e8f5e9', border: '#2e7d32', text: '#1b5e20' }; 
    let statusText = "CLEAN";
    let riskLevel = "clean"; 

    // --- HIERARCHY v1.1 ---

    // 1. RED ZONE (Danger)
    // Triggers: 
    // - Blocked Country
    // - Abuse Score >= User Limit
    // - DKIM FAIL (Tampering)
    // - SPF FAIL (Spoofing) ... UNLESS ARC is 'pass' (Valid Forward)
    const isSpoofed = (auth.spf === 'fail' && auth.arc !== 'pass');
    const isTampered = (auth.dkim === 'fail');

    if (isBlacklisted || abuseScore >= threshold || isTampered || isSpoofed) {
        theme = { bg: '#ffebee', border: '#b71c1c', text: '#b71c1c' };
        riskLevel = "high";
        
        // Smart Status Text
        if (isBlacklisted) statusText = "BLOCKED COUNTRY";
        else if (isTampered) statusText = "SECURITY FAIL (DKIM)";
        else if (isSpoofed) statusText = "SPOOF DETECTED (SPF)";
        else statusText = "HIGH RISK SENDER";
    } 
    
    // 2. ORANGE ZONE (Caution)
    // Triggers: 
    // - Abuse > 15 (Noise Floor)
    // - VPN (Hidden Identity)
    // - SPF Softfail (Questionable)
    // - DMARC Fail (Policy violation)
    else if (abuseScore > 15 || (isVpn && !isAllowedCloud) || auth.spf === 'softfail' || auth.dmarc === 'fail') {
        theme = { bg: '#fff3e0', border: '#ef6c00', text: '#e65100' };
        riskLevel = "caution";

        if (auth.spf === 'softfail' || auth.dmarc === 'fail' || auth.arc === 'fail') {
             statusText = "CAUTION: AUTH ISSUE";
        } else if (isVpn) {
             statusText = "CAUTION: HIDDEN IDENTITY";
        } else {
             statusText = "CAUTION: SUSPICIOUS IP";
        }
    } 
    
    // 3. GREEN ZONE (Safe)
    else {
        if (isAllowedCloud && isVpn) {
            statusText = "CLOUD SERVER";
        } else {
            statusText = "CLEAN SENDER";
        }
        theme = { bg: '#e8f5e9', border: '#2e7d32', text: '#1b5e20' };
        riskLevel = "clean";
    }

    // --- TOOLBAR BADGE UPDATE ---
    // This updates the button icon with the score and color
    let badgeColor = "#2e7d32"; // Green default
    if (riskLevel === 'high') badgeColor = "#c62828";
    if (riskLevel === 'caution') badgeColor = "#ef6c00";

    // If blocked, show "!", otherwise show the score
    let badgeText = isBlacklisted ? "!" : abuseScore.toString();

    // Thunderbirds API to set the badge on the specific tab
    browser.messageDisplayAction.setBadgeText({ tabId: tabId, text: badgeText });
    browser.messageDisplayAction.setBadgeBackgroundColor({ tabId: tabId, color: badgeColor });
    // Text color white for contrast
    browser.messageDisplayAction.setBadgeTextColor({ tabId: tabId, color: "#ffffff" });

    // --- SAVE DATA ---
    const analysisData = {
        timestamp: Date.now(),
        theme, statusText, riskLevel,
        location: { 
            country: location.country || "Unknown", 
            code: countryCode, 
            city: location.city || "Unknown City", 
            region: location.region || "",
            timeZone
        },
        network: {
            org,
            asn,
            domain,
            usageType
        },
        abuseScore, security, routeData, sourceIp, isAllowedCloud, auth
    };

    await browser.storage.local.set({ ['analysis_' + messageId]: analysisData });

    const mode = settings.bannerMode || 'always';
    let shouldShow = false;
    if (mode === 'always') shouldShow = true;
    else if (mode === 'never') shouldShow = false;
    else if (mode === 'high_risk' && riskLevel === 'high') shouldShow = true;
    else if (mode === 'caution' && (riskLevel === 'caution' || riskLevel === 'high')) shouldShow = true;

    if (shouldShow) {
        // Create a copy of the data for the banner
        let bannerData = JSON.parse(JSON.stringify(analysisData));

        // VISUAL FIX: If it is a known Cloud, turn off the "VPN" flag 
        // purely for the Banner so we don't scare the user with double badges.
        if (analysisData.isAllowedCloud) {
            bannerData.security.vpn = false; 
        }

        setTimeout(() => {
            browser.tabs.sendMessage(tabId, {
                command: "eagleEyeRender",
                data: bannerData // Send the "Clean" data
            }).catch(() => {});
        }, 500);
    }
}

// --- GARBAGE COLLECTOR ---

// Run cleanup on startup
browser.runtime.onStartup.addListener(cleanupStorage);
browser.runtime.onInstalled.addListener(cleanupStorage);

async function cleanupStorage() {
    console.log("EagleEye: Running Storage Cleanup...");
    const allData = await browser.storage.local.get(null);
    const keysToDelete = [];
    const now = Date.now();
    
    // Settings to KEEP (Don't delete these!)
    const protectedKeys = [
        'abuseApiKey', 'vpnApiKey', 'ipinfoToken', 'countryBlacklist', 
        'enableMap', 'bannerMode', 'cloudWhitelist', 'customCloud', 'riskThreshold'
    ];

    // Expiration Times
    const CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 7 Days for IP Cache
    const ANALYSIS_TTL = 24 * 60 * 60 * 1000;  // 24 Hours for Email Banners

    for (const [key, value] of Object.entries(allData)) {
        if (protectedKeys.includes(key)) continue;

        // Check 1: IP Cache (cache_1.2.3.4)
        if (key.startsWith('cache_')) {
            if (value.timestamp && (now - value.timestamp > CACHE_TTL)) {
                keysToDelete.push(key);
            }
        }
        
        // Check 2: Analysis Data (analysis_123)
        else if (key.startsWith('analysis_')) {
            // Delete if older than 24 hours OR if it has no timestamp (legacy data)
            if (!value.timestamp || (now - value.timestamp > ANALYSIS_TTL)) {
                keysToDelete.push(key);
            }
        }
    }

    if (keysToDelete.length > 0) {
        await browser.storage.local.remove(keysToDelete);
        console.log(`EagleEye: Cleaned up ${keysToDelete.length} expired entries.`);
    } else {
        console.log("EagleEye: Storage is clean.");
    }
}

// --- AUTHENTICATION PARSER HELPER (v1.2 Optimistic) ---
function parseAuthHeader(headerValue) {
    if (!headerValue) return { spf: 'none', dkim: 'none', arc: 'none', dmarc: 'none' };

    const extract = (key) => {
        // 1. Use Global Flag ('g') to find ALL occurrences, not just the first one
        const regex = new RegExp(`\\b${key}\\s*=\\s*"?([a-z0-9.-]+)"?`, 'gi');
        const matches = [...headerValue.matchAll(regex)];
        
        if (matches.length === 0) return 'none';
        
        // 2. Priority Logic: If ANY match is 'pass', return 'pass'.
        // This fixes the "Fail, Pass" edge case.
        for (const m of matches) {
            if (m[1].toLowerCase() === 'pass') return 'pass';
        }
        
        // 3. Otherwise, return the first result (likely 'fail' or 'none')
        return matches[0][1].toLowerCase();
    };

    return {
        spf: extract('spf'),
        dkim: extract('dkim'),
        dmarc: extract('dmarc'),
        arc: extract('arc')
    };
}