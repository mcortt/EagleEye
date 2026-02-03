// Remove any helper functions that use 'await' before the request.

document.getElementById('riskThreshold').addEventListener('input', (e) => {
    document.getElementById('threshVal').innerText = e.target.value + "%";
});

document.getElementById('save').addEventListener('click', async () => {
    // 1. GET VALUES (Synchronously - Fast!)
    const abuseKey = document.getElementById('abuseKey').value.trim();
    const vpnKey = document.getElementById('vpnKey').value.trim();
    const ipinfoKey = document.getElementById('ipinfoKey').value.trim();
    const blacklist = document.getElementById('blacklist').value.toUpperCase();
    const showMap = document.getElementById('showMap').checked;
    const bannerMode = document.getElementById('bannerMode').value;
    const customCloud = document.getElementById('customCloud').value.toUpperCase();
    const riskThreshold = document.getElementById('riskThreshold').value;
    const cloudWhitelist = Array.from(document.querySelectorAll('.cloud-cb:checked')).map(cb => cb.value);
    
    const msg = document.getElementById('msg');
    
    // 2. BUILD THE LIST (Synchronously - Fast!)
    // We do NOT check if we have them. We just list what we need.
    const neededOrigins = [];

    if (abuseKey) neededOrigins.push("https://api.abuseipdb.com/*");
    if (vpnKey) neededOrigins.push("https://vpnapi.io/*");
    if (showMap) neededOrigins.push("https://ipinfo.io/*");

    // 3. REQUEST PERMISSIONS (The VERY FIRST Await)
    // This ensures the browser sees this as a direct result of the click.
    let permissionsOk = true;

    if (neededOrigins.length > 0) {
        msg.innerText = "Requesting permissions...";
        msg.style.color = "#0078d7";
        
        try {
            // This prompt handles "Already Granted" permissions automatically (it won't ask again).
            // It only prompts for the new ones.
            const granted = await browser.permissions.request({ origins: neededOrigins });
            if (!granted) {
                console.log("EagleEye: User denied permission request.");
                permissionsOk = false;
            }
        } catch (e) {
            console.error("EagleEye Permission Error:", e);
            permissionsOk = false;
        }
    }

    // 4. SAVE SETTINGS (After the critical UI part is done)
    msg.innerText = "Saving...";
    
    await browser.storage.local.set({ 
        abuseApiKey: abuseKey, 
        vpnApiKey: vpnKey, 
        ipinfoToken: ipinfoKey,
        countryBlacklist: blacklist,
        enableMap: showMap,
        bannerMode: bannerMode,
        cloudWhitelist: cloudWhitelist,
        customCloud: customCloud,
        riskThreshold: parseInt(riskThreshold)
    });
    
    // 5. FINAL STATUS
    if (!permissionsOk) {
        msg.style.color = "#ef6c00"; // Orange
        msg.innerText = "Settings saved, but permissions were denied. Some features will be disabled.";
    } else {
        msg.style.color = "#2e7d32";
        msg.innerText = "Settings Saved Successfully!";
    }
    
    setTimeout(() => msg.innerText = "", 4000);
});

// Load settings on startup (No changes needed here)
browser.storage.local.get([
    'abuseApiKey', 'vpnApiKey', 'ipinfoToken', 'countryBlacklist', 
    'enableMap', 'bannerMode', 'cloudWhitelist', 'customCloud', 'riskThreshold'
]).then(res => {
    if (res.abuseApiKey) document.getElementById('abuseKey').value = res.abuseApiKey;
    if (res.vpnApiKey) document.getElementById('vpnKey').value = res.vpnApiKey;
    if (res.ipinfoToken) document.getElementById('ipinfoKey').value = res.ipinfoToken;
    if (res.countryBlacklist) document.getElementById('blacklist').value = res.countryBlacklist;
    document.getElementById('showMap').checked = (res.enableMap === true);
    if (res.bannerMode) document.getElementById('bannerMode').value = res.bannerMode;
    if (res.customCloud) document.getElementById('customCloud').value = res.customCloud;
    
    const val = res.riskThreshold !== undefined ? res.riskThreshold : 50;
    document.getElementById('riskThreshold').value = val;
    document.getElementById('threshVal').innerText = val + "%";
    
    const defaultCloud = [
        "AMAZON", "GOOGLE", "MICROSOFT", "CLOUDFLARE", 
        "ORACLE", "IBM", "SALESFORCE", "RACKSPACE"
    ];
    
    const savedCloud = res.cloudWhitelist || defaultCloud;
    document.querySelectorAll('.cloud-cb').forEach(cb => {
        cb.checked = savedCloud.includes(cb.value);
    });
});