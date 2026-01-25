document.getElementById('save').addEventListener('click', async () => {
  const abuseKey = document.getElementById('abuseKey').value.trim();
  const vpnKey = document.getElementById('vpnKey').value.trim();
  const ipinfoKey = document.getElementById('ipinfoKey').value.trim();
  
  const msg = document.getElementById('msg');

  if (!abuseKey || !vpnKey) {
     msg.style.color = "#d32f2f";
     msg.innerText = "Error: AbuseIPDB and vpnapi keys are required.";
     return;
  }

  await browser.storage.local.set({ 
    abuseApiKey: abuseKey, 
    vpnApiKey: vpnKey, 
    ipinfoToken: ipinfoKey 
  });
  
  msg.style.color = "#2e7d32";
  msg.innerText = "Settings Saved!";
  setTimeout(() => msg.innerText = "", 2000);
});

browser.storage.local.get(['abuseApiKey', 'vpnApiKey', 'ipinfoToken']).then(res => {
  if (res.abuseApiKey) document.getElementById('abuseKey').value = res.abuseApiKey;
  if (res.vpnApiKey) document.getElementById('vpnKey').value = res.vpnApiKey;
  if (res.ipinfoToken) document.getElementById('ipinfoKey').value = res.ipinfoToken;
});