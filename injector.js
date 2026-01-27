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

    // Helper to create badges (Simplified: assumes always active if called)
    const createBadge = (label) => {
        const span = document.createElement('span');
        span.textContent = label;
        span.style.cssText = "padding: 2px 5px; border-radius: 3px; font-size: 0.75em; margin-right: 4px; font-weight: bold; color: white; opacity: 1;";
        
        // Color depends on risk level (Orange for caution, Red for high risk/clean)
        // Usually if a VPN is detected in "Clean" mode, it's weird, but we default to Orange if not high risk.
        span.style.backgroundColor = (level === 'high') ? '#c62828' : '#ef6c00';
        
        return span;
    };

    // Main Container
    const box = document.createElement('div');
    box.id = 'eagle-eye-bar';
    box.style.cssText = `font-family: 'Segoe UI', system-ui, sans-serif; padding: 12px; margin-bottom: 10px; border-left: 6px solid ${theme.border}; background: ${theme.bg}; color: ${isDark ? '#e0e0e0' : '#333'}; box-shadow: 0 1px 3px rgba(0,0,0,0.1);`;

    // Row 1: Header & Score
    const row1 = document.createElement('div');
    row1.style.cssText = "display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;";

    const leftGroup = document.createElement('div');
    leftGroup.style.display = "flex";
    leftGroup.style.alignItems = "center";

    const statusText = document.createElement('strong');
    statusText.textContent = d.statusText;
    statusText.style.cssText = `color: ${theme.text}; font-size: 1.1em; margin-right: 10px;`;
    
    leftGroup.appendChild(statusText);

    // --- CHANGED LOGIC START ---
    // Only append badges if the value is truthy
    if (d.security.vpn) leftGroup.appendChild(createBadge("VPN"));
    if (d.security.tor) leftGroup.appendChild(createBadge("TOR"));
    if (d.security.proxy) leftGroup.appendChild(createBadge("PROXY"));
    if (d.security.relay) leftGroup.appendChild(createBadge("RELAY"));
    // --- CHANGED LOGIC END ---

    const rightGroup = document.createElement('div');
    rightGroup.style.fontSize = "0.9em";
    
    const riskLabel = document.createElement('strong');
    riskLabel.textContent = "Risk Score: ";
    const riskVal = document.createElement('span');
    riskVal.textContent = d.abuseScore + "%";
    riskVal.style.cssText = `font-weight: 900; font-size: 1.1em; color: ${theme.text};`;

    rightGroup.appendChild(riskLabel);
    rightGroup.appendChild(riskVal);

    row1.appendChild(leftGroup);
    row1.appendChild(rightGroup);
    box.appendChild(row1);

    // Row 2: Origin
    const row2 = document.createElement('div');
    row2.style.cssText = "font-size: 0.9em; margin-bottom: 4px;";
    
    const originLabel = document.createElement('strong');
    originLabel.textContent = "Origin: ";
    
    const locationText = document.createTextNode(`${d.location.city}, ${d.location.region} (${d.location.country}) `);
    
    const networkSpan = document.createElement('span');
    networkSpan.style.color = isDark ? '#aaa' : '#777';
    networkSpan.textContent = ` • ${d.network.org} `;
    
    const asnSpan = document.createElement('span');
    asnSpan.style.fontSize = "0.9em";
    asnSpan.style.opacity = "0.8";
    asnSpan.textContent = `(${d.network.asn})`;
    networkSpan.appendChild(asnSpan);

    row2.appendChild(originLabel);
    row2.appendChild(locationText);
    row2.appendChild(networkSpan);
    box.appendChild(row2);

    // Row 3: Route
    const row3 = document.createElement('div');
    row3.style.cssText = `font-size: 0.85em; color: ${isDark ? '#bbb' : '#555'}; border-top: 1px solid ${isDark ? '#444' : 'rgba(0,0,0,0.1)'}; padding-top: 6px; margin-top: 6px;`;
    
    const routeLabel = document.createElement('strong');
    routeLabel.textContent = "Route: ";
    row3.appendChild(routeLabel);

    if (d.routeData && d.routeData.length > 0) {
        d.routeData.forEach((h, i) => {
            const hopSpan = document.createElement('span');
            const region = h.region ? `, ${h.region}` : "";
            hopSpan.textContent = `${h.city || '?'}${region}, ${h.country || '??'}`;
            hopSpan.title = h.org || "";
            row3.appendChild(hopSpan);

            if (i < d.routeData.length - 1) {
                const arrow = document.createTextNode(" → ");
                row3.appendChild(arrow);
            }
        });
    } else {
        row3.appendChild(document.createTextNode("No route data available"));
    }

    box.appendChild(row3);
    document.body.prepend(box);
  }
});