document.addEventListener('DOMContentLoaded', function() {
    // Initialize dashboard
    initializeDashboard();
    
    // Set up real-time updates
    setupRealtimeUpdates();
    
    // Initialize charts
    initializeCharts();
});

function initializeDashboard() {
    // Load initial data
    fetchUserData();
    fetchSystemLogs();
    fetchUpdateHistory();
    updateStatistics();
}

function setupRealtimeUpdates() {
    // Set up WebSocket connection for real-time updates
    const ws = new WebSocket('wss://your-server/admin-updates');
    
    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        handleRealtimeUpdate(data);
    };
    
    ws.onerror = function(error) {
        console.error('WebSocket error:', error);
    };
}

function handleRealtimeUpdate(data) {
    switch(data.type) {
        case 'user_activity':
            updateUserActivity(data);
            break;
        case 'system_log':
            addSystemLog(data);
            break;
        case 'threat_detected':
            updateThreatStats(data);
            break;
        case 'system_health':
            updateSystemHealth(data);
            break;
    }
}

function fetchUserData() {
    fetch('/api/admin/users')
        .then(response => response.json())
        .then(users => {
            const tableBody = document.getElementById('userTableBody');
            tableBody.innerHTML = '';
            
            users.forEach(user => {
                const row = createUserRow(user);
                tableBody.appendChild(row);
            });
        })
        .catch(error => console.error('Error fetching user data:', error));
}

function createUserRow(user) {
    const row = document.createElement('tr');
    row.innerHTML = `
        <td class="px-6 py-4 whitespace-nowrap">
            <div class="flex items-center">
                <div class="flex-shrink-0 h-10 w-10">
                    <img class="h-10 w-10 rounded-full" src="${user.avatar || '/static/images/default-avatar.png'}" alt="">
                </div>
                <div class="ml-4">
                    <div class="text-sm font-medium text-gray-900">${user.name}</div>
                    <div class="text-sm text-gray-500">${user.email}</div>
                </div>
            </div>
        </td>
        <td class="px-6 py-4 whitespace-nowrap">
            <div class="text-sm text-gray-900">${user.licenseType}</div>
            <div class="text-sm text-gray-500">Expires: ${user.licenseExpiry}</div>
        </td>
        <td class="px-6 py-4 whitespace-nowrap">
            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${user.active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">
                ${user.active ? 'Active' : 'Inactive'}
            </span>
        </td>
        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
            ${user.lastActive}
        </td>
        <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
            <button class="text-blue-600 hover:text-blue-900 mr-2" onclick="editUser('${user.id}')">Edit</button>
            <button class="text-red-600 hover:text-red-900" onclick="deactivateUser('${user.id}')">Deactivate</button>
        </td>
    `;
    return row;
}

function fetchSystemLogs() {
    fetch('/api/admin/logs')
        .then(response => response.json())
        .then(logs => {
            const logContainer = document.getElementById('logEntries');
            logContainer.innerHTML = '';
            
            logs.forEach(log => {
                const entry = createLogEntry(log);
                logContainer.appendChild(entry);
            });
        })
        .catch(error => console.error('Error fetching system logs:', error));
}

function createLogEntry(log) {
    const entry = document.createElement('div');
    entry.className = 'p-4 border rounded-lg';
    entry.innerHTML = `
        <div class="flex items-center justify-between">
            <div class="flex items-center">
                <span class="inline-block w-2 h-2 rounded-full mr-2 ${getLogSeverityColor(log.severity)}"></span>
                <span class="font-medium">${log.type}</span>
            </div>
            <span class="text-gray-500 text-sm">${log.timestamp}</span>
        </div>
        <p class="mt-2 text-gray-600">${log.message}</p>
        ${log.details ? `<pre class="mt-2 bg-gray-50 p-2 rounded text-sm">${log.details}</pre>` : ''}
    `;
    return entry;
}

function getLogSeverityColor(severity) {
    switch(severity.toLowerCase()) {
        case 'error':
            return 'bg-red-500';
        case 'warning':
            return 'bg-yellow-500';
        case 'info':
            return 'bg-blue-500';
        default:
            return 'bg-gray-500';
    }
}

function fetchUpdateHistory() {
    fetch('/api/admin/updates')
        .then(response => response.json())
        .then(updates => {
            const container = document.getElementById('updateHistory');
            container.innerHTML = '';
            
            updates.forEach(update => {
                const entry = createUpdateEntry(update);
                container.appendChild(entry);
            });
        })
        .catch(error => console.error('Error fetching update history:', error));
}

function createUpdateEntry(update) {
    const entry = document.createElement('div');
    entry.className = 'border-b pb-4';
    entry.innerHTML = `
        <div class="flex justify-between items-start">
            <div>
                <h4 class="font-medium">Version ${update.version}</h4>
                <p class="text-sm text-gray-500">${update.date}</p>
            </div>
            <span class="px-2 py-1 text-xs rounded ${update.status === 'successful' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">
                ${update.status}
            </span>
        </div>
        <p class="mt-2 text-sm text-gray-600">${update.description}</p>
    `;
    return entry;
}

function initializeCharts() {
    // Initialize Threat Distribution Chart
    const threatCtx = document.getElementById('threatChart').getContext('2d');
    new Chart(threatCtx, {
        type: 'doughnut',
        data: {
            labels: ['Brute Force', 'DDoS', 'SQL Injection', 'XSS', 'Other'],
            datasets: [{
                data: [30, 25, 20, 15, 10],
                backgroundColor: [
                    '#3B82F6',
                    '#EF4444',
                    '#10B981',
                    '#F59E0B',
                    '#6B7280'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });

    // Initialize User Activity Chart
    const activityCtx = document.getElementById('activityChart').getContext('2d');
    new Chart(activityCtx, {
        type: 'line',
        data: {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [{
                label: 'Active Users',
                data: [65, 70, 68, 75, 80, 77, 73],
                borderColor: '#3B82F6',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function updateStatistics() {
    fetch('/api/admin/statistics')
        .then(response => response.json())
        .then(stats => {
            document.getElementById('activeUsersCount').textContent = stats.activeUsers;
            document.getElementById('threatsBlockedCount').textContent = stats.threatsBlocked;
            // Update other statistics as needed
        })
        .catch(error => console.error('Error updating statistics:', error));
}

// User Management Functions
function editUser(userId) {
    // Implement user editing functionality
    console.log('Editing user:', userId);
}

function deactivateUser(userId) {
    if (confirm('Are you sure you want to deactivate this user?')) {
        fetch(`/api/admin/users/${userId}/deactivate`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                fetchUserData(); // Refresh user list
            } else {
                alert('Failed to deactivate user');
            }
        })
        .catch(error => console.error('Error deactivating user:', error));
    }
}

// Set up periodic updates
setInterval(updateStatistics, 30000); // Update every 30 seconds 