browser.runtime.onMessage.addListener((request) => {
  if (request.command === "eagleEyeRender") {
    
    const existing = document.getElementById('eagle-eye-bar');
    if (existing) existing.remove();

    const d = request.data;
    const isDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

    const palettes = {
        light: {
            clean:   { bg: '#e8f5e9', border: '#2e7d32', text: '#1b5e20' },
            caution: { bg: '#fff3e0', border: '#ef6c00', text: '#e65100' },
            high:    { bg: '#ffebee', border: '#c62828', text: '#b71c1c' }
        },
        dark: {
            clean:   { bg: '#0d200d', border: '#43a047', text: '#a5d6a7' },
            caution: { bg: '#251600', border: '#fb8c00', text: '#ffcc80' },
            high:    { bg: '#250505', border: '#e53935', text: '#ef9a9a' }
        }
    };

    const mode = isDark ? 'dark' : 'light';
    const level = d.riskLevel === 'high' ? 'high' : (d.riskLevel === 'caution' ? 'caution' : 'clean');
    const theme = palettes[mode][level];

    const badge = (label, active) => {
        let color, opacity;
        if (active) {
            color = (level === 'clean') ? '#ef6c00' : '#c62828';
            opacity = '1';
        } else {
            color = isDark ? '#444' : '#ddd';
            opacity = isDark ? '0.6' : '0.4';
        }
        return `<span style="background:${color}; color:white; padding:2px 5px; border-radius:3px; font-size:0.75em; margin-right:4px; opacity:${opacity}; font-weight:bold;">${label}</span>`;
    };

    const routeString = d.routeData && d.routeData.length > 0 
        ? d.routeData.map(h => {
            const reg = h.region ? `, ${h.region}` : "";
            return `<span title="${h.org || ''}">${h.city || '?'}${reg}, ${h.country || '??'}</span>`;
        }).join(' &rarr; ')
        : "No route data available";

    const box = document.createElement('div');
    box.id = 'eagle-eye-bar';
    box.style = `font-family: 'Segoe UI', system-ui, sans-serif; padding: 12px; margin-bottom: 10px; border-left: 6px solid ${theme.border}; background: ${theme.bg}; color: ${isDark ? '#e0e0e0' : '#333'}; box-shadow: 0 1px 3px rgba(0,0,0,0.1);`;

    box.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
        <div style="display: flex; align-items: center;">
            <strong style="color: ${theme.text}; font-size: 1.1em; margin-right: 10px;">${d.statusText}</strong>
            ${badge("VPN", d.security.vpn)}
            ${badge("TOR", d.security.tor)}
            ${badge("PROXY", d.security.proxy)}
            ${badge("RELAY", d.security.relay)}
        </div>
        <div style="font-size: 0.9em;">
            <strong>Risk Score:</strong> <span style="font-weight: 900; font-size: 1.1em; color: ${theme.text};">${d.abuseScore}%</span>
        </div>
      </div>
      
      <div style="font-size: 0.9em; margin-bottom: 4px;">
        <strong>Origin:</strong> ${d.location.city}, ${d.location.region} (${d.location.country}) 
        <span style="color: ${isDark ? '#aaa' : '#777'}"> 
            &bull; ${d.network.org} <span style="font-size:0.9em; opacity:0.8;">(${d.network.asn})</span>
        </span>
      </div>

      <div style="font-size: 0.85em; color: ${isDark ? '#bbb' : '#555'}; border-top: 1px solid ${isDark ? '#444' : 'rgba(0,0,0,0.1)'}; padding-top: 6px; margin-top: 6px;">
         <strong>Route:</strong> ${routeString}
      </div>
    `;
    
    document.body.prepend(box);
  }
});