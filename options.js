document.getElementById('riskThreshold').addEventListener('input', (e) => {
  document.getElementById('threshVal').innerText = e.target.value + "%";
});

document.getElementById('save').addEventListener('click', async () => {
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

  if (!abuseKey || !vpnKey) {
     msg.style.color = "#d32f2f";
     msg.innerText = "Error: AbuseIPDB and vpnapi keys are required.";
     return;
  }

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
  
  msg.style.color = "#2e7d32";
  msg.innerText = "Settings Saved Successfully!";
  setTimeout(() => msg.innerText = "", 2000);
});

browser.storage.local.get([
  'abuseApiKey', 'vpnApiKey', 'ipinfoToken', 'countryBlacklist', 
  'enableMap', 'bannerMode', 'cloudWhitelist', 'customCloud', 'riskThreshold'
]).then(res => {
  if (res.abuseApiKey) document.getElementById('abuseKey').value = res.abuseApiKey;
  if (res.vpnApiKey) document.getElementById('vpnKey').value = res.vpnApiKey;
  if (res.ipinfoToken) document.getElementById('ipinfoKey').value = res.ipinfoToken;
  if (res.countryBlacklist) document.getElementById('blacklist').value = res.countryBlacklist;
  document.getElementById('showMap').checked = (res.enableMap !== false);
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