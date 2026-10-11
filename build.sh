#!/bin/bash

# ============================================================
# PARENTAL CONTROL - GODMODE BUILD SCRIPT
# ============================================================

echo "🔧============================================================"
echo "🔧  PARENTAL CONTROL BUILD SCRIPT v2.0 - GODMODE"
echo "🔧============================================================"
echo ""

# Step 1: Show current directory
echo "📁 Current directory: $(pwd)"
echo ""

# Step 2: Show all files in project root
echo "📁 Files in project root:"
ls -la
echo ""

# Step 3: Create required directories
echo "📁 Creating web/public directory..."
mkdir -p web/public
echo "✅ web/public directory ready"
echo ""

# Step 4: Copy or create index.html
echo "📄 Checking for index.html..."

if [ -f "web/public/index.html" ]; then
    echo "✅ index.html already exists in web/public/"
    echo "📄 File size: $(wc -c < web/public/index.html) bytes"
else
    echo "⚠️ index.html not found in web/public/"
    echo "📄 Searching for index.html in other locations..."
    
    # Search for index.html
    FOUND_INDEX=$(find . -name "index.html" -type f 2>/dev/null | head -1)
    
    if [ -n "$FOUND_INDEX" ]; then
        echo "📄 Found index.html at: $FOUND_INDEX"
        echo "📄 Copying to web/public/index.html..."
        cp "$FOUND_INDEX" web/public/index.html
        echo "✅ index.html copied successfully!"
    else
        echo "❌ index.html not found anywhere! Creating default..."
        
        # Create the FULL GODMODE index.html
        cat > web/public/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Parental Control - GODMODE</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a1a; color: #fff; min-height: 100vh; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 30px 0; border-bottom: 1px solid #1a1a2e; margin-bottom: 30px; }
        .header h1 { font-size: 32px; font-weight: 800; }
        .header h1 i { color: #4CAF50; margin-right: 12px; }
        .header .subtitle { color: #6c757d; font-size: 14px; margin-top: 8px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #1a1a2e; border-radius: 12px; padding: 20px; text-align: center; border: 1px solid #2a2a3e; }
        .stat-card:hover { border-color: #4CAF50; transform: translateY(-4px); transition: all 0.3s ease; }
        .stat-card .number { font-size: 32px; font-weight: 800; color: #4CAF50; }
        .stat-card .label { color: #6c757d; font-size: 13px; margin-top: 4px; }
        .stat-card .icon { font-size: 28px; margin-bottom: 8px; }
        .card { background: #1a1a2e; border-radius: 12px; padding: 24px; margin-bottom: 20px; border: 1px solid #2a2a3e; }
        .card-title { font-size: 18px; font-weight: 700; margin-bottom: 16px; color: #fff; }
        .card-title i { color: #4CAF50; margin-right: 8px; }
        .device-item { background: #0a0a1a; padding: 12px 16px; border-radius: 8px; margin-bottom: 8px; border-left: 3px solid #4CAF50; }
        .device-item .name { font-weight: 600; }
        .device-item .model { color: #6c757d; font-size: 13px; }
        .device-item .status { float: right; color: #4CAF50; font-size: 12px; }
        .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
        .status-dot.active { background: #4CAF50; }
        .status-dot.inactive { background: #dc3545; }
        .status-badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .status-badge.running { background: #1a3a2a; color: #4CAF50; }
        .status-badge.stopped { background: #3a1a1a; color: #dc3545; }
        .btn { padding: 8px 20px; border-radius: 8px; font-weight: 600; border: none; cursor: pointer; transition: all 0.3s ease; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .btn-primary { background: #0d6efd; color: #fff; }
        .btn-success { background: #198754; color: #fff; }
        .btn-danger { background: #dc3545; color: #fff; }
        .btn-warning { background: #ffc107; color: #000; }
        .btn-group { display: flex; gap: 10px; flex-wrap: wrap; }
        .console { background: #0a0a1a; padding: 16px; border-radius: 8px; font-family: 'Consolas', monospace; font-size: 12px; max-height: 200px; overflow-y: auto; color: #4ec9b0; }
        .console .log-timestamp { color: #6c757d; margin-right: 8px; }
        .console .log-success { color: #6a9955; }
        .console .log-error { color: #f14c4c; }
        .console .log-info { color: #4ec9b0; }
        .screenshot-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 16px; }
        .screenshot-item { background: #0a0a1a; border-radius: 8px; overflow: hidden; text-align: center; padding: 12px; border: 1px solid #2a2a3e; }
        .screenshot-item:hover { border-color: #4CAF50; transform: translateY(-4px); transition: all 0.3s ease; }
        .screenshot-item .preview { height: 100px; display: flex; align-items: center; justify-content: center; font-size: 40px; color: #6c757d; }
        .screenshot-item .name { font-size: 11px; color: #6c757d; margin-top: 8px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .loading { text-align: center; padding: 60px 20px; }
        .spinner { width: 48px; height: 48px; border: 4px solid #1a1a2e; border-top-color: #4CAF50; border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 16px; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 9999; }
        .toast { background: #1a1a2e; padding: 12px 20px; border-radius: 8px; border-left: 4px solid #4CAF50; margin-bottom: 8px; animation: slideUp 0.3s ease; }
        .toast.error { border-left-color: #dc3545; }
        @keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        @media (max-width: 768px) { .stats-grid { grid-template-columns: 1fr 1fr; } }
        @media (max-width: 480px) { .stats-grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Parental Control</h1>
            <div class="subtitle">GODMODE v3.0 • Real-time Monitoring Dashboard</div>
        </div>

        <div id="dashboard">
            <div class="stats-grid" id="statsGrid">
                <div class="stat-card"><div class="icon">👤</div><div class="number" id="devicesCount">0</div><div class="label">Connected Devices</div></div>
                <div class="stat-card"><div class="icon">📸</div><div class="number" id="screenshotsCount">0</div><div class="label">Screenshots</div></div>
                <div class="stat-card"><div class="icon">📷</div><div class="number" id="cameraCount">0</div><div class="label">Camera Photos</div></div>
                <div class="stat-card"><div class="icon">📱</div><div class="number" id="appsCount">0</div><div class="label">Running Apps</div></div>
            </div>

            <div class="card">
                <div class="card-title"><i class="fas fa-server"></i> System Controls</div>
                <div class="btn-group">
                    <button class="btn btn-success" onclick="startMonitoring()"><i class="fas fa-play"></i> Start</button>
                    <button class="btn btn-danger" onclick="stopMonitoring()"><i class="fas fa-stop"></i> Stop</button>
                    <button class="btn btn-primary" onclick="captureScreenshot()"><i class="fas fa-camera"></i> Screenshot</button>
                    <button class="btn btn-warning" onclick="refreshData()"><i class="fas fa-sync"></i> Refresh</button>
                </div>
            </div>

            <div class="card">
                <div class="card-title"><i class="fas fa-users"></i> Connected Devices</div>
                <div id="devicesList"><div class="device-item"><span class="status-dot inactive"></span> No devices connected yet</div></div>
            </div>

            <div class="card">
                <div class="card-title"><i class="fas fa-image"></i> Recent Screenshots</div>
                <div class="screenshot-grid" id="screenshotGrid">
                    <div style="grid-column:1/-1;text-align:center;color:#6c757d;padding:20px;">No screenshots yet</div>
                </div>
            </div>

            <div class="card">
                <div class="card-title"><i class="fas fa-terminal"></i> Live Console</div>
                <div class="console" id="consoleLog">
                    <div><span class="log-timestamp">[System]</span><span class="log-info">Dashboard initialized</span></div>
                    <div><span class="log-timestamp">[System]</span><span class="log-info">Waiting for device connections...</span></div>
                </div>
            </div>
        </div>

        <div id="loading" class="loading" style="display:none;">
            <div class="spinner"></div>
            <p>Loading dashboard...</p>
        </div>
    </div>

    <div class="toast-container" id="toastContainer"></div>

    <script>
        const API_URL = window.location.origin;
        let refreshInterval = null;

        function addConsoleLog(message, type = 'info') {
            const log = document.getElementById('consoleLog');
            const timestamp = new Date().toLocaleTimeString();
            const entry = document.createElement('div');
            const className = type === 'success' ? 'log-success' : type === 'error' ? 'log-error' : 'log-info';
            entry.innerHTML = `<span class="log-timestamp">[${timestamp}]</span><span class="${className}">${message}</span>`;
            log.appendChild(entry);
            while (log.children.length > 50) log.removeChild(log.firstChild);
            log.scrollTop = log.scrollHeight;
        }

        function showToast(message, type = 'info') {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.textContent = message;
            container.appendChild(toast);
            setTimeout(() => { toast.remove(); }, 5000);
        }

        async function apiCall(endpoint, method = 'GET', data = null) {
            try {
                const options = { method, headers: { 'Content-Type': 'application/json' } };
                if (data) options.body = JSON.stringify(data);
                const response = await fetch(endpoint, options);
                if (!response.ok) return { error: `HTTP ${response.status}` };
                return await response.json();
            } catch (e) { return { error: e.message }; }
        }

        async function refreshData() {
            try {
                const status = await apiCall('/api/status');
                if (status.error) {
                    addConsoleLog(`Error: ${status.error}`, 'error');
                    return;
                }

                const devices = status.devices || {};
                const stats = status.stats || {};
                const deviceCount = Object.keys(devices).length;

                document.getElementById('devicesCount').textContent = deviceCount;
                document.getElementById('screenshotsCount').textContent = stats.screenshots || 0;
                document.getElementById('cameraCount').textContent = stats.camera_photos || 0;
                document.getElementById('appsCount').textContent = stats.app_usage || 0;

                const devicesList = document.getElementById('devicesList');
                if (deviceCount === 0) {
                    devicesList.innerHTML = '<div class="device-item"><span class="status-dot inactive"></span> No devices connected yet</div>';
                } else {
                    devicesList.innerHTML = Object.values(devices).map(d => `
                        <div class="device-item">
                            <span class="status-dot active"></span>
                            <span class="name">${d.name || 'Unknown'}</span>
                            <span class="model">(${d.model || 'Unknown'})</span>
                            <span class="status">${d.status || 'active'}</span>
                        </div>
                    `).join('');
                }

                // Load screenshots
                const screenshots = await apiCall('/api/screenshots?limit=6');
                const grid = document.getElementById('screenshotGrid');
                if (!screenshots.error && screenshots.length > 0) {
                    grid.innerHTML = screenshots.map(s => `
                        <div class="screenshot-item">
                            <div class="preview"><i class="fas fa-image"></i></div>
                            <div class="name">${s.filename || 'screenshot'}</div>
                        </div>
                    `).join('');
                } else {
                    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;color:#6c757d;padding:20px;">No screenshots yet</div>';
                }

                addConsoleLog(`Refreshed: ${deviceCount} devices, ${stats.screenshots || 0} screenshots`, 'success');
            } catch (e) {
                addConsoleLog(`Refresh error: ${e.message}`, 'error');
            }
        }

        async function startMonitoring() {
            const result = await apiCall('/api/start', 'POST');
            if (result.status === 'started') {
                addConsoleLog('✅ Monitoring started', 'success');
                showToast('Monitoring started successfully', 'success');
                refreshData();
            } else {
                addConsoleLog('❌ Failed to start monitoring', 'error');
                showToast('Failed to start monitoring', 'error');
            }
        }

        async function stopMonitoring() {
            const result = await apiCall('/api/stop', 'POST');
            if (result.status === 'stopped') {
                addConsoleLog('⏹️ Monitoring stopped', 'info');
                showToast('Monitoring stopped', 'info');
                refreshData();
            } else {
                addConsoleLog('❌ Failed to stop monitoring', 'error');
            }
        }

        async function captureScreenshot() {
            const result = await apiCall('/api/screenshot', 'POST');
            if (result.success) {
                addConsoleLog(`📸 Screenshot captured: ${result.filename}`, 'success');
                showToast(`Screenshot captured: ${result.filename}`, 'success');
                refreshData();
            } else {
                addConsoleLog(`❌ Screenshot failed: ${result.error || 'Unknown error'}`, 'error');
                showToast('Screenshot capture failed', 'error');
            }
        }

        // Auto-refresh every 10 seconds
        setInterval(refreshData, 10000);

        // Initial load
        document.addEventListener('DOMContentLoaded', () => {
            addConsoleLog('🚀 GODMODE Dashboard loaded', 'info');
            refreshData();
        });

        console.log('🚀 GODMODE Dashboard v3.0');
        console.log('📌 Keyboard Shortcuts: Ctrl+S=Screenshot, Ctrl+R=Refresh');
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 's') { e.preventDefault(); captureScreenshot(); }
            if (e.ctrlKey && e.key === 'r') { e.preventDefault(); refreshData(); }
        });
    </script>
</body>
</html>
EOF
        echo "✅ Default GODMODE index.html created"
        echo "📄 File size: $(wc -c < web/public/index.html) bytes"
    fi
fi

# Step 5: Final verification
echo ""
echo "============================================================"
echo "📁 Files in web/public:"
ls -la web/public/
echo "============================================================"

if [ -f "web/public/index.html" ]; then
    echo ""
    echo "✅✅✅ index.html is ready! ✅✅✅"
    echo "📄 File size: $(wc -c < web/public/index.html) bytes"
    echo ""
    echo "📄 First 10 lines:"
    echo "----------------------------------------"
    head -10 web/public/index.html
    echo "----------------------------------------"
else
    echo "❌❌❌ index.html is STILL missing! ❌❌❌"
    exit 1
fi

echo ""
echo "============================================================"
echo "✅ BUILD SCRIPT COMPLETE!"
echo "============================================================"
echo "📊 Dashboard will be available at: /"
echo "📱 Android endpoints: /api/monitor/*"
echo "🔍 Debug: /api/debug/webdir"
echo "============================================================"