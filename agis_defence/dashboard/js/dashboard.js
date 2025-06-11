// Initialize React hooks
const { useState, useEffect } = React;

// System Health Panel Component
const SystemHealthPanel = ({ data }) => (
    <div className="bg-white p-4 rounded-lg shadow">
        <h3 className="text-lg font-semibold mb-4">System Health</h3>
        <div className="space-y-4">
            <div>
                <div className="flex justify-between items-center mb-1">
                    <span>CPU Usage</span>
                    <span className={data.system.cpu_usage > 80 ? 'text-red-600' : 'text-green-600'}>
                        {data.system.cpu_usage}%
                    </span>
                </div>
            </div>
            <div>
                <div className="flex justify-between items-center mb-1">
                    <span>Memory Usage</span>
                    <span className={data.system.memory_usage > 80 ? 'text-red-600' : 'text-green-600'}>
                        {data.system.memory_usage}%
                    </span>
                </div>
            </div>
            <div>
                <div className="flex justify-between items-center mb-1">
                    <span>Disk Usage</span>
                    <span className={data.system.disk_usage > 80 ? 'text-red-600' : 'text-green-600'}>
                        {data.system.disk_usage}%
                    </span>
                </div>
            </div>
        </div>
    </div>
);

// Network Status Panel Component
const NetworkStatusPanel = ({ data }) => (
    <div className="bg-white p-4 rounded-lg shadow">
        <h3 className="text-lg font-semibold mb-4">Network Status</h3>
        <div className="space-y-4">
            <div>
                <div className="flex justify-between items-center mb-1">
                    <span>Active Connections</span>
                    <span className="text-blue-600">{data.network.active_connections}</span>
                </div>
            </div>
            <div>
                <div className="flex justify-between items-center mb-1">
                    <span>Bandwidth Usage</span>
                    <span className="text-blue-600">{data.network.incoming_traffic} MB/s</span>
                </div>
            </div>
            <div>
                <div className="flex justify-between items-center mb-1">
                    <span>Packet Loss</span>
                    <span className="text-green-600">{data.network.packet_loss}%</span>
                </div>
            </div>
        </div>
    </div>
);

// Security Status Panel Component
const SecurityStatusPanel = ({ data }) => (
    <div className="bg-white p-4 rounded-lg shadow">
        <h3 className="text-lg font-semibold mb-4">Security Status</h3>
        <div className="space-y-4">
            <div>
                <div className="flex justify-between items-center mb-1">
                    <span>Firewall Status</span>
                    <span className="text-green-600">Active (Simulation)</span>
                </div>
            </div>
            <div>
                <div className="flex justify-between items-center mb-1">
                    <span>Active Threats</span>
                    <span className={data.threats.active_threats > 0 ? 'text-red-600' : 'text-green-600'}>
                        {data.threats.active_threats}
                    </span>
                </div>
            </div>
            <div>
                <div className="flex justify-between items-center mb-1">
                    <span>System Health</span>
                    <span className="text-red-600">{data.system.health_score.toFixed(2)}/100</span>
                </div>
            </div>
        </div>
    </div>
);

// AI Security Monitor Panel Component
const AISecurityMonitorPanel = ({ data }) => (
    <div className="bg-white p-4 rounded-lg shadow">
        <h3 className="text-lg font-semibold mb-4">AI Security Monitor</h3>
        <div className="space-y-4">
            <div className="flex justify-between items-center">
                <span>Threat Level</span>
                <span className={`text-${data.aiAnalysis.threat_level === 'high' ? 'red' : data.aiAnalysis.threat_level === 'medium' ? 'yellow' : 'green'}-600`}>
                    {data.aiAnalysis.threat_level}
                </span>
            </div>
            <div className="flex justify-between items-center">
                <span>Analysis Confidence</span>
                <span>{data.aiAnalysis.confidence.toFixed(2)}%</span>
            </div>
            <div className="flex justify-between items-center">
                <span>Detection Coverage</span>
                <span>{data.aiAnalysis.coverage}%</span>
            </div>
        </div>
    </div>
);

// Recent AI Actions Panel Component
const RecentAIActionsPanel = ({ data }) => (
    <div className="bg-white p-4 rounded-lg shadow">
        <h3 className="text-lg font-semibold mb-4">Recent AI Actions</h3>
        <div className="space-y-4">
            {data.threats.recent_actions.map((action, index) => (
                <div key={index} className="border-b pb-2 last:border-b-0">
                    <div className="flex justify-between items-center">
                        <span className={`px-2 py-1 rounded text-sm ${action.type === 'block' ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>
                            {action.type}
                        </span>
                        <span className={`px-2 py-1 rounded text-sm ${action.severity === 'high' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'}`}>
                            {action.severity}
                        </span>
                    </div>
                    <div className="mt-1">
                        <div className="text-sm">{action.details}</div>
                        <div className="text-xs text-gray-500">Threat: {action.threat_type}</div>
                    </div>
                </div>
            ))}
        </div>
    </div>
);

// Security Threats Panel Component
const SecurityThreatsPanel = ({ data }) => (
    <div className="bg-white p-4 rounded-lg shadow">
        <h3 className="text-lg font-semibold mb-4">Security Threats</h3>
        <div className="space-y-4">
            {Object.entries(data.aiAnalysis.threat_distribution).map(([type, count], index) => (
                <div key={index} className="border-b pb-2 last:border-b-0">
                    <div className="flex justify-between items-center">
                        <span className="text-red-600">{type}</span>
                        <span className="text-gray-600">{count}</span>
                    </div>
                </div>
            ))}
        </div>
    </div>
);

// Threat Distribution Panel Component
const ThreatDistributionPanel = ({ data }) => {
    const totalThreats = Object.values(data.aiAnalysis.threat_distribution).reduce((a, b) => a + b, 0);
    
    return (
        <div className="bg-white p-4 rounded-lg shadow">
            <h3 className="text-lg font-semibold mb-4">Threat Distribution</h3>
            <div className="space-y-4">
                {Object.entries(data.aiAnalysis.threat_distribution).map(([type, count], index) => {
                    const percentage = ((count / totalThreats) * 100).toFixed(1);
                    return (
                        <div key={index}>
                            <div className="flex justify-between items-center mb-1">
                                <span>{type}</span>
                                <span>{count}</span>
                            </div>
                            <div className="w-full bg-gray-200 rounded-full h-2">
                                <div 
                                    className="h-2 rounded-full bg-blue-600"
                                    style={{ width: `${percentage}%` }}
                                ></div>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

// Data Recovery Panel Component
const DataRecoveryPanel = ({ data }) => (
    <div className="bg-white p-4 rounded-lg shadow">
        <h3 className="text-lg font-semibold mb-4">Data Recovery Status</h3>
        <div className="space-y-4">
            <div className="flex justify-between items-center">
                <span>Recovered Items</span>
                <span className="text-green-600">{data.recovered_data_count}</span>
            </div>
            <div className="flex justify-between items-center">
                <span>Protected Data</span>
                <span className="text-blue-600">{data.protected_items || 0}</span>
            </div>
            <div className="flex justify-between items-center">
                <span>Recovery Success Rate</span>
                <span className={`text-${data.recovery_success_rate > 80 ? 'green' : 'yellow'}-600`}>
                    {data.recovery_success_rate || 0}%
                </span>
            </div>
        </div>
    </div>
);

// Main App Component
const App = () => {
    const [data, setData] = useState(null);
    const [error, setError] = useState(null);
    const [lastUpdate, setLastUpdate] = useState(Date.now());

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await fetch('/api/system/status');
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const result = await response.json();
                setData(result);
                setLastUpdate(Date.now());
                setError(null);
            } catch (error) {
                console.error('Error fetching data:', error);
                setError(error.message);
            }
        };

        fetchData();

        // Set up periodic updates every 5 seconds
        const interval = setInterval(fetchData, 5000);

        // Cleanup
        return () => clearInterval(interval);
    }, []);

    if (error) {
        return (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative" role="alert">
                <strong className="font-bold">Error!</strong>
                <span className="block sm:inline"> {error}</span>
            </div>
        );
    }

    if (!data) {
        return (
            <div className="flex items-center justify-center p-8">
                <div className="loading text-2xl">⌛</div>
                <span className="ml-4 text-lg text-gray-600">Loading AGIS Defence Dashboard...</span>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <SystemHealthPanel data={data} />
                <NetworkStatusPanel data={data} />
                <SecurityStatusPanel data={data} />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-4">
                    <AISecurityMonitorPanel data={data} />
                    <RecentAIActionsPanel data={data} />
                    <DataRecoveryPanel data={data} />
                </div>
                <div>
                    <ThreatDistributionPanel data={data} />
                    <SecurityThreatsPanel data={data} />
                </div>
            </div>
        </div>
    );
};

// Render the app
const container = document.getElementById('root');
const root = ReactDOM.createRoot(container);
root.render(
    <ErrorBoundary>
        <App />
    </ErrorBoundary>
); 