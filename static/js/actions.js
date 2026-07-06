// Fetch Firewall Status
async function loadFirewall() {
    try {
        const res = await fetch('/api/actions/firewall');
        const data = await res.json();
        
        const fwToggle = document.getElementById('fwToggle');
        const fwToggleLabel = document.getElementById('fwToggleLabel');
        const fwBadge = document.getElementById('fwStatusBadge');
        const wrapper = document.getElementById('fwPortsWrapper');

        if (data.ok) {
            fwToggle.disabled = false;
            fwToggle.checked = data.enabled;
            fwToggleLabel.textContent = data.enabled ? 'Enabled' : 'Disabled';
            
            if (data.enabled) {
                fwBadge.className = 'status-active';
                fwBadge.textContent = 'Active';
            } else {
                fwBadge.className = 'status-inactive';
                fwBadge.textContent = 'Inactive';
            }

            if (!data.ports || data.ports.length === 0) {
                wrapper.innerHTML = '<div class="text-center text-muted py-4">No specific port rules found.</div>';
            } else {
                let html = '<table class="hs-table"><thead><tr><th>Rule (Port/Proto)</th><th>Action</th><th></th></tr></thead><tbody>';
                data.ports.forEach(p => {
                    const badgeClass = p.action.toLowerCase() === 'allow' ? 'badge-allow' : 'badge-deny';
                    html += `
                        <tr>
                            <td class="fw-bold">${p.port_proto}</td>
                            <td><span class="${badgeClass}">${p.action.toUpperCase()}</span></td>
                            <td class="text-end">
                                <button class="btn btn-sm btn-outline-danger fw-btn-delete" data-rule="${p.port_proto}" title="Delete Rule">
                                    <i class="bi bi-trash"></i>
                                </button>
                            </td>
                        </tr>
                    `;
                });
                html += '</tbody></table>';
                wrapper.innerHTML = html;
                
                // Add delete listeners
                document.querySelectorAll('.fw-btn-delete').forEach(btn => {
                    btn.addEventListener('click', async function() {
                        if(confirm('Delete this rule?')) {
                            const parts = this.dataset.rule.split('/');
                            await applyFwRule(parts[0], parts[1] || 'tcp', 'delete');
                        }
                    });
                });
            }
        } else {
            wrapper.innerHTML = '<div class="text-danger py-4">Error loading firewall status</div>';
        }
    } catch (e) {
        document.getElementById('fwPortsWrapper').innerHTML = '<div class="text-danger py-4">Network error loading firewall</div>';
    }
}

async function applyFwRule(port, proto, action) {
    try {
        const res = await fetch('/api/actions/firewall/port', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ csrf_token: window.CSRF_TOKEN, port, proto, action })
        });
        const data = await res.json();
        if (data.ok) {
            document.getElementById('fwRuleResult').innerHTML = '<span class="text-success">Rule applied successfully!</span>';
            setTimeout(loadFirewall, 500);
        } else {
            document.getElementById('fwRuleResult').innerHTML = `<span class="text-danger">Failed: ${data.error}</span>`;
        }
    } catch (e) {
        document.getElementById('fwRuleResult').innerHTML = `<span class="text-danger">Request failed</span>`;
    }
}

// Fetch SSH Status
async function loadSsh() {
    try {
        const res = await fetch('/api/actions/ssh');
        const data = await res.json();
        
        const wrapper = document.getElementById('sshChecksWrapper');

        if (data.ok) {
            let html = '<table class="hs-table"><thead><tr><th>Parameter</th><th>Value</th></tr></thead><tbody>';
            const params = [
                { key: 'port', label: 'SSH Port' },
                { key: 'permit_root_login', label: 'PermitRootLogin' },
                { key: 'password_auth', label: 'PasswordAuthentication' },
                { key: 'pubkey_auth', label: 'PubkeyAuthentication' },
                { key: 'x11_forwarding', label: 'X11Forwarding' },
                { key: 'max_auth_tries', label: 'MaxAuthTries' }
            ];
            
            params.forEach(p => {
                const val = data[p.key] || 'unknown';
                let color = '#1e293b';
                
                // Color coding for security
                if(val.toLowerCase() === 'yes') color = (p.key==='permit_root_login' || p.key==='password_auth') ? '#ef4444' : '#16a34a';
                if(val.toLowerCase() === 'no') color = (p.key==='permit_root_login' || p.key==='password_auth') ? '#16a34a' : '#ef4444';
                
                html += `
                    <tr>
                        <td class="fw-bold">${p.label}</td>
                        <td style="color:${color}; font-weight:600;">${val}</td>
                    </tr>
                `;
            });
            html += '</tbody></table>';
            wrapper.innerHTML = html;
        } else {
            wrapper.innerHTML = '<div class="text-danger py-4">Error loading SSH status</div>';
        }
    } catch (e) {
        document.getElementById('sshChecksWrapper').innerHTML = '<div class="text-danger py-4">Network error loading SSH</div>';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadFirewall();
    loadSsh();

    // FW Toggle
    const fwToggle = document.getElementById('fwToggle');
    if (fwToggle) {
        fwToggle.addEventListener('change', async function() {
            this.disabled = true;
            const enable = this.checked;
            try {
                const res = await fetch('/api/actions/firewall/toggle', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ csrf_token: window.CSRF_TOKEN, enable })
                });
                await res.json();
                setTimeout(loadFirewall, 500);
            } catch (e) {
                alert('Failed to toggle firewall');
                this.disabled = false;
            }
        });
    }

    // FW Apply Rule
    const btnFwApply = document.getElementById('btnFwApply');
    if (btnFwApply) {
        btnFwApply.addEventListener('click', () => {
            const port = document.getElementById('fwPortInput').value;
            const proto = document.getElementById('fwProtoInput').value;
            const action = document.getElementById('fwActionInput').value;
            if (!port) return alert('Enter a port number');
            applyFwRule(port, proto, action);
        });
    }

    // FW Quick Ports
    document.querySelectorAll('.quick-port-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const port = this.dataset.port;
            const proto = this.dataset.proto;
            applyFwRule(port, proto, 'allow');
        });
    });

    // SSH Apply
    const btnSshApply = document.getElementById('btnSshApply');
    if (btnSshApply) {
        btnSshApply.addEventListener('click', async () => {
            const setting = document.getElementById('sshParamSelect').value;
            const value = document.getElementById('sshValueInput').value;
            if (!setting || !value) return alert('Select directive and enter value');
            
            try {
                const res = await fetch('/api/actions/ssh/configure', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ csrf_token: window.CSRF_TOKEN, setting, value })
                });
                const data = await res.json();
                if (data.ok) {
                    document.getElementById('sshRuleResult').innerHTML = '<span class="text-success">Saved! Note: You may need to restart SSH service for changes to take effect.</span>';
                    setTimeout(loadSsh, 500);
                } else {
                    document.getElementById('sshRuleResult').innerHTML = `<span class="text-danger">Failed: ${data.error}</span>`;
                }
            } catch (e) {
                document.getElementById('sshRuleResult').innerHTML = `<span class="text-danger">Request failed</span>`;
            }
        });
    }
});
