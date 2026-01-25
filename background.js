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
  
  if (!settings.abuseApiKey || !settings.vpnApiKey) return;

  const fullMessage = await browser.messages.getFull(messageId);
  const headers = fullMessage.headers;
  const receivedHeaders = headers['received'] || [];
  
  // Regex (Strict IPv4 + IPv6)
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

  // CACHE CHECK
  const cacheKey = `cache_${sourceIp}`;
  if (!bypassCache) {
      const cached = await browser.storage.local.get(cacheKey);
      if (cached[cacheKey]) {
          const entry = cached[cacheKey];
          // 24 Hour Expiry
          if (Date.now() - entry.timestamp < 86400000) {
              console.log(`EagleEye: Using Cached Data for ${sourceIp}`);
              processAndDisplay(entry.data, settings, messageId, tabId, sourceIp);
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

    processAndDisplay(rawData, settings, messageId, tabId, sourceIp);

  } catch (err) {
    console.error("EagleEye Error:", err);
  }
}

async function processAndDisplay(rawData, settings, messageId, tabId, sourceIp) {
    const { vpnRes, abuseRes, routeData } = rawData;
    
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

    // --- HIERARCHY ---
    if (isBlacklisted) {
        theme = { bg: '#ffebee', border: '#b71c1c', text: '#b71c1c' };
        statusText = "BLOCKED COUNTRY";
        riskLevel = "high";
    } else if (abuseScore >= threshold) { 
        theme = { bg: '#ffebee', border: '#c62828', text: '#c62828' };
        statusText = "HIGH RISK";
        riskLevel = "high";
    } else if (isVpn) {
        if (isAllowedCloud) {
            statusText = "CLOUD SERVER"; 
        } else {
            theme = { bg: '#fff3e0', border: '#ef6c00', text: '#e65100' };
            statusText = "CAUTION (VPN/VPS)";
            riskLevel = "caution";
        }
    } else if (abuseScore > 15) {
        theme = { bg: '#fff3e0', border: '#ef6c00', text: '#e65100' };
        statusText = "CAUTION";
        riskLevel = "caution";
    }

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
        // This is your Custom Network Object
        network: {
            org,
            asn,
            domain,
            usageType
        },
        // Removed 'network' from this list to prevent overwriting
        abuseScore, security, routeData, sourceIp, isAllowedCloud
    };

    await browser.storage.local.set({ ['analysis_' + messageId]: analysisData });

    const mode = settings.bannerMode || 'always';
    let shouldShow = false;
    if (mode === 'always') shouldShow = true;
    else if (mode === 'never') shouldShow = false;
    else if (mode === 'high_risk' && riskLevel === 'high') shouldShow = true;
    else if (mode === 'caution' && (riskLevel === 'caution' || riskLevel === 'high')) shouldShow = true;

    if (shouldShow) {
        setTimeout(() => {
            browser.tabs.sendMessage(tabId, {
                command: "eagleEyeRender",
                data: analysisData
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