const { useState, useEffect } = React;

// API base URL
const API_BASE_URL = 'http://localhost:5000';

// API endpoints with error handling
const API = {
    async fetch(endpoint, options = {}) {
        try {
            const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
            console.log(`Fetching ${url}...`);
            
            // Add CORS headers
            const defaultOptions = {
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            };
            
            const response = await fetch(url, { ...defaultOptions, ...options });
            if (!response.ok) {
                throw new Error(`API Error: ${response.status} ${response.statusText}`);
            }
            const data = await response.json();
            console.log(`Received data from ${url}:`, data);
            return data;
        } catch (error) {
            console.error(`API Error (${endpoint}):`, error);
            throw error;
        }
    },
    
    endpoints: {
        status: '/api/system/status',
        blockIp: (ip) => `/api/firewall/block/${ip}`,
        unblockIp: (ip) => `/api/firewall/unblock/${ip}`,
        networkStats: '/api/network/stats',
        networkAnomalies: '/api/network/anomalies',
        firewallStatus: '/api/firewall/status',
        analyzeThreat: '/api/threat/analyze',
        handleThreat: '/api/threat/handle',
        healing: {
            status: '/api/healing/status',
            backup: '/api/healing/backup',
            restore: '/api/healing/restore'
        },
        settings: '/api/settings'
    }
};

// System Status Panel Component
const SystemStatusPanel = ({ status }) => (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
        <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">System Health</h3>
            <div className="space-y-2">
                <div className="flex justify-between items-center">
                    <span>CPU Usage</span>
                    <span className={status.cpu_usage > 80 ? 'text-red-600' : 'text-green-600'}>
                        {status.cpu_usage}%
                    </span>
                </div>
                <div className="flex justify-between items-center">
                    <span>Memory Usage</span>
                    <span className={status.memory_usage > 80 ? 'text-red-600' : 'text-green-600'}>
                        {status.memory_usage}%
                    </span>
                </div>
                <div className="flex justify-between items-center">
                    <span>Disk Usage</span>
                    <span className={status.disk_usage > 80 ? 'text-red-600' : 'text-green-600'}>
                        {status.disk_usage}%
                    </span>
                </div>
            </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Network Status</h3>
            <div className="space-y-2">
                <div className="flex justify-between items-center">
                    <span>Active Connections</span>
                    <span>{status.network?.active_connections || 0}</span>
                </div>
                <div className="flex justify-between items-center">
                    <span>Bandwidth Usage</span>
                    <span>{(status.network?.bandwidth_usage || 0).toFixed(2)} MB/s</span>
                </div>
                <div className="flex justify-between items-center">
                    <span>Packet Loss</span>
                    <span className={status.network?.packet_loss > 5 ? 'text-red-600' : 'text-green-600'}>
                        {(status.network?.packet_loss || 0).toFixed(2)}%
                    </span>
                </div>
            </div>
        </div>

        <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-2">Security Status</h3>
            <div className="space-y-2">
                <div className="flex justify-between items-center">
                    <span>Firewall Status</span>
                    <span className={status.firewall?.active ? 'text-green-600' : 'text-red-600'}>
                        {status.firewall?.active ? 'Active' : 'Inactive'}
                    </span>
                </div>
                <div className="flex justify-between items-center">
                    <span>Active Threats</span>
                    <span className={status.anomalies?.length > 0 ? 'text-red-600' : 'text-green-600'}>
                        {status.anomalies?.length || 0}
                    </span>
                </div>
                <div className="flex justify-between items-center">
                    <span>System Health</span>
                    <span className={status.aiAnalysis?.healthScore > 70 ? 'text-green-600' : 'text-red-600'}>
                        {status.aiAnalysis?.healthScore || 100}/100
                    </span>
                </div>
            </div>
        </div>
    </div>
);

// Settings Panel Component
const SettingsPanel = ({ settings, onSave }) => {
    const [whatsappSettings, setWhatsappSettings] = useState({
        enabled: settings?.whatsapp?.enabled || false,
        numbers: settings?.whatsapp?.recipient_numbers?.join('\n') || ''
    });

    const handleSave = () => {
        const numbers = whatsappSettings.numbers
            .split('\n')
            .map(n => n.trim())
            .filter(n => n);
        
        onSave({
            whatsapp: {
                enabled: whatsappSettings.enabled,
                recipient_numbers: numbers
            }
        });
    };

    return (
        <div className="bg-white p-6 rounded-lg shadow mb-4">
            <h2 className="text-xl font-semibold mb-4">Alert Settings</h2>
            
            <div className="mb-6">
                <h3 className="text-lg font-medium mb-3">WhatsApp Notifications</h3>
                <div className="space-y-4">
                    <div className="flex items-center">
                        <input
                            type="checkbox"
                            id="whatsapp-enabled"
                            className="h-4 w-4 text-blue-600"
                            checked={whatsappSettings.enabled}
                            onChange={(e) => setWhatsappSettings(prev => ({
                                ...prev,
                                enabled: e.target.checked
                            }))}
                        />
                        <label htmlFor="whatsapp-enabled" className="ml-2">
                            Enable WhatsApp Notifications
                        </label>
                    </div>
                    
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                            Recipient WhatsApp Numbers
                        </label>
                        <p className="text-xs text-gray-500 mb-2">
                            Enter one number per line in international format (e.g., +1234567890)
                        </p>
                        <textarea
                            className="w-full h-32 px-3 py-2 border rounded-md"
                            placeholder="+1234567890&#10;+0987654321"
                            value={whatsappSettings.numbers}
                            onChange={(e) => setWhatsappSettings(prev => ({
                                ...prev,
                                numbers: e.target.value
                            }))}
                        />
                    </div>
                </div>
            </div>

            <div className="flex justify-end">
                <button
                    onClick={handleSave}
                    className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
                >
                    Save Settings
                </button>
            </div>
        </div>
    );
};

// Main App Component
const App = () => {
    const [systemStatus, setSystemStatus] = useState(null);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(true);
    const [lastUpdate, setLastUpdate] = useState(null);
    const [showSettings, setShowSettings] = useState(false);
    const [settings, setSettings] = useState(null);
    const [historicalData, setHistoricalData] = useState({
        networkStats: [],
        threats: [],
        systemMetrics: []
    });

    const addHistoricalData = (category, data) => {
        setHistoricalData(prev => ({
            ...prev,
            [category]: [...prev[category], { timestamp: new Date(), data }].slice(-100)
        }));
    };

    const fetchStatus = async () => {
        try {
            setLoading(true);
            const data = await API.fetch(API.endpoints.status);
            setSystemStatus(data);
            setLastUpdate(new Date());
            setError(null);
            
            // Update historical data
            if (data.network) {
                addHistoricalData('networkStats', data.network);
            }
            if (data.anomalies && data.anomalies.length > 0) {
                data.anomalies.forEach(threat => 
                    addHistoricalData('threats', threat)
                );
            }
            if (data.aiAnalysis) {
                addHistoricalData('systemMetrics', {
                    healthScore: data.aiAnalysis.healthScore,
                    threatLevel: data.aiAnalysis.threat_level,
                    activeThreats: data.anomalies?.length || 0
                });
            }
        } catch (err) {
            setError('Failed to fetch system status: ' + err.message);
            console.error('Status fetch error:', err);
        } finally {
            setLoading(false);
        }
    };

    const fetchSettings = async () => {
        try {
            const data = await API.fetch(API.endpoints.settings);
            setSettings(data);
        } catch (err) {
            console.error('Failed to fetch settings:', err);
        }
    };

    const saveSettings = async (newSettings) => {
        try {
            await API.post(API.endpoints.settings, newSettings);
            await fetchSettings();
        } catch (err) {
            console.error('Failed to save settings:', err);
        }
    };

    // Initial fetch and set up intervals
    useEffect(() => {
        fetchStatus();
        fetchSettings();
        const statusInterval = setInterval(fetchStatus, 5000);
        return () => clearInterval(statusInterval);
    }, []);

    if (loading && !systemStatus) {
        return (
            <div className="flex items-center justify-center min-h-screen">
                <div className="loading text-4xl mr-4">⚡</div>
                <span>Loading AGIS Defence Dashboard...</span>
            </div>
        );
    }

    if (error) {
        return (
            <div className="min-h-screen p-4">
                <h1 className="text-2xl font-bold mb-4">AGIS Defence Dashboard</h1>
                <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
                    <strong className="font-bold">Error: </strong>
                    <span>{error}</span>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gray-100">
            <header className="bg-blue-600 text-white p-4">
                <div className="container mx-auto flex justify-between items-center">
                    <div>
                <h1 className="text-2xl font-bold">AGIS Defence Dashboard</h1>
                <p className="text-sm">AI-Powered Security Monitoring</p>
                    </div>
                    <button
                        onClick={() => setShowSettings(!showSettings)}
                        className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-400"
                    >
                        {showSettings ? 'Hide Settings' : 'Settings'}
                    </button>
                </div>
            </header>

            <main className="container mx-auto p-4">
                {showSettings && settings && (
                    <SettingsPanel settings={settings} onSave={saveSettings} />
                )}
                
                {systemStatus && (
                    <>
                        <SystemStatusPanel status={systemStatus} />
                        <SecurityMetricsPanel 
                            metrics={systemStatus.aiAnalysis} 
                            historicalData={historicalData}
                        />
                        <ThreatPanel 
                            threats={systemStatus.anomalies} 
                            historicalThreats={historicalData.threats}
                        />
                    </>
                )}
            </main>

            <footer className="bg-gray-200 p-4 text-center text-sm">
                Last updated: {lastUpdate?.toLocaleString()}
            </footer>
        </div>
    );
};

// Render the app
ReactDOM.render(<App />, document.getElementById('root'));