// Initialize Socket.IO
const socket = io();

// Connect to WebSocket
socket.on('connect', () => {
    console.log('Connected to server');
    updateStats();
});

// Update statistics periodically
function updateStats() {
    fetch('/api/admin/statistics')
        .then(response => response.json())
        .then(data => {
            document.getElementById('activeUsers').textContent = data.activeUsers;
            document.getElementById('threatsBlocked').textContent = data.threatsBlocked;
        })
        .catch(error => console.error('Error fetching statistics:', error));
}

// User Management Functions
function showCreateUserModal() {
    const modal = document.getElementById('createUserModal');
    if (modal) {
        modal.classList.remove('hidden');
        // Reset form
        document.getElementById('createUserForm').reset();
    }
}

function hideCreateUserModal() {
    const modal = document.getElementById('createUserModal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

function showEditUserModal(user) {
    const modal = document.getElementById('editUserModal');
    const form = document.getElementById('editUserForm');
    if (modal && form) {
        form.querySelector('input[name="user_id"]').value = user.id;
        form.querySelector('input[name="name"]').value = user.name;
        form.querySelector('input[name="email"]').value = user.email;
        form.querySelector('select[name="license_type"]').value = user.licenseType;
        modal.classList.remove('hidden');
    }
}

function hideEditUserModal() {
    const modal = document.getElementById('editUserModal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

function showExtendLicenseModal(userId) {
    const modal = document.getElementById('extendLicenseModal');
    const form = document.getElementById('extendLicenseForm');
    if (modal && form) {
        form.querySelector('input[name="user_id"]').value = userId;
        modal.classList.remove('hidden');
    }
}

function hideExtendLicenseModal() {
    const modal = document.getElementById('extendLicenseModal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

// Close modals when clicking outside
document.addEventListener('click', function(event) {
    const modals = [
        { modal: 'createUserModal', hide: hideCreateUserModal },
        { modal: 'editUserModal', hide: hideEditUserModal },
        { modal: 'extendLicenseModal', hide: hideExtendLicenseModal }
    ];

    modals.forEach(({ modal, hide }) => {
        const modalElement = document.getElementById(modal);
        if (modalElement && !modalElement.classList.contains('hidden')) {
            // Check if click is outside the modal content
            if (!event.target.closest('.modal-content') && event.target.id === modal) {
                hide();
            }
        }
    });
});

// Update user list with enhanced display
function updateUserList() {
    fetch('/api/admin/users')
        .then(response => response.json())
        .then(users => {
            const userList = document.getElementById('userList');
            userList.innerHTML = '';
            users.forEach(user => {
                const licenseStatus = new Date(user.licenseExpiry) > new Date() ? 'Valid' : 'Expired';
                const licenseClass = licenseStatus === 'Valid' ? 'text-green-600' : 'text-red-600';
                
                const userItem = document.createElement('li');
                userItem.className = 'py-4';
                userItem.innerHTML = `
                    <div class="flex items-center justify-between">
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center space-x-3">
                                <p class="text-sm font-medium text-gray-900 truncate">${user.name}</p>
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                    user.active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                                }">
                                    ${user.active ? 'Active' : 'Inactive'}
                                </span>
                            </div>
                            <p class="text-sm text-gray-500 truncate">${user.email}</p>
                            <div class="mt-1 flex items-center space-x-4 text-sm text-gray-500">
                                <span>License: ${user.licenseType}</span>
                                <span class="${licenseClass}">Status: ${licenseStatus}</span>
                                <span>Expires: ${new Date(user.licenseExpiry).toLocaleDateString()}</span>
                            </div>
                        </div>
                        <div class="flex space-x-2">
                            <button onclick="showEditUserModal(${JSON.stringify(user)})" 
                                    class="bg-blue-100 hover:bg-blue-200 text-blue-700 font-bold py-1 px-3 rounded text-sm">
                                Edit
                            </button>
                            <button onclick="showExtendLicenseModal(${user.id})"
                                    class="bg-green-100 hover:bg-green-200 text-green-700 font-bold py-1 px-3 rounded text-sm">
                                Extend
                            </button>
                            ${user.active ? `
                                <button onclick="deactivateUser(${user.id})"
                                        class="bg-red-100 hover:bg-red-200 text-red-700 font-bold py-1 px-3 rounded text-sm">
                                    Deactivate
                                </button>
                            ` : ''}
                        </div>
                    </div>
                `;
                userList.appendChild(userItem);
            });
        })
        .catch(error => console.error('Error fetching users:', error));
}

// Deactivate user
function deactivateUser(userId) {
    if (confirm('Are you sure you want to deactivate this user?')) {
        fetch(`/api/admin/users/${userId}/deactivate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateUserList();
                updateStats();
            }
        })
        .catch(error => console.error('Error deactivating user:', error));
    }
}

// Update system logs every 5 seconds
function startSystemLogsUpdate() {
    // Initial update
    updateSystemLogs();
    
    // Set up periodic updates
    setInterval(updateSystemLogs, 5000);
}

function updateSystemLogs() {
    fetch('/api/admin/logs')
        .then(response => response.json())
        .then(logs => {
            const logContainer = document.getElementById('systemLogs');
            logContainer.innerHTML = '';
            
            logs.forEach(log => {
                const logEntry = document.createElement('li');
                logEntry.className = 'py-4';
                logEntry.innerHTML = `
                    <div class="flex flex-col">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center">
                                <span class="inline-block w-2 h-2 rounded-full mr-2 ${getLogSeverityColor(log.severity)}"></span>
                                <span class="font-medium text-sm">${log.type}</span>
                            </div>
                            <span class="text-gray-500 text-xs">${new Date(log.timestamp).toLocaleString()}</span>
                        </div>
                        <p class="mt-1 text-sm text-gray-600">${log.message}</p>
                        ${log.details ? `<pre class="mt-1 text-xs bg-gray-50 p-2 rounded">${log.details}</pre>` : ''}
                    </div>
                `;
                logContainer.appendChild(logEntry);
            });
        })
        .catch(error => console.error('Error updating system logs:', error));
}

function getLogSeverityColor(severity) {
    const colors = {
        'error': 'bg-red-500',
        'warning': 'bg-yellow-500',
        'info': 'bg-blue-500',
        'success': 'bg-green-500'
    };
    return colors[severity.toLowerCase()] || 'bg-gray-500';
}

// Initialize charts
let cpuChart, memoryChart, diskChart, networkChart;
let lastNetworkIn = 0;
let lastNetworkOut = 0;
let lastTimestamp = Date.now();

function initializeCharts() {
    // CPU Chart
    const cpuCtx = document.getElementById('cpuChart').getContext('2d');
    cpuChart = new Chart(cpuCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'CPU Usage',
                data: [],
                borderColor: 'rgb(59, 130, 246)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });

    // Memory Chart
    const memoryCtx = document.getElementById('memoryChart').getContext('2d');
    memoryChart = new Chart(memoryCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Memory Usage',
                data: [],
                borderColor: 'rgb(34, 197, 94)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });

    // Disk Chart
    const diskCtx = document.getElementById('diskChart').getContext('2d');
    diskChart = new Chart(diskCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Disk Usage',
                data: [],
                borderColor: 'rgb(234, 179, 8)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });

    // Network Chart
    const networkCtx = document.getElementById('networkChart').getContext('2d');
    networkChart = new Chart(networkCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Network In (KB/s)',
                data: [],
                borderColor: 'rgb(59, 130, 246)',
                tension: 0.1
            }, {
                label: 'Network Out (KB/s)',
                data: [],
                borderColor: 'rgb(239, 68, 68)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Format bytes to human readable format
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Update system metrics
function updateMetrics(data) {
    // Update CPU
    document.getElementById('cpuLabel').textContent = `${data.cpu.toFixed(1)}%`;
    document.getElementById('cpuBar').style.width = `${data.cpu}%`;
    
    // Update Memory
    document.getElementById('memoryLabel').textContent = `${data.memory.toFixed(1)}%`;
    document.getElementById('memoryBar').style.width = `${data.memory}%`;
    
    // Update Disk
    document.getElementById('diskLabel').textContent = `${data.disk.toFixed(1)}%`;
    document.getElementById('diskBar').style.width = `${data.disk}%`;
    
    // Calculate network speed
    const now = Date.now();
    const timeDiff = (now - lastTimestamp) / 1000; // Convert to seconds
    
    const networkInSpeed = (data.network.in - lastNetworkIn) / timeDiff;
    const networkOutSpeed = (data.network.out - lastNetworkOut) / timeDiff;
    
    document.getElementById('networkIn').textContent = formatBytes(networkInSpeed) + '/s';
    document.getElementById('networkOut').textContent = formatBytes(networkOutSpeed) + '/s';
    
    // Update timestamps and last values
    lastNetworkIn = data.network.in;
    lastNetworkOut = data.network.out;
    lastTimestamp = now;
    
    // Update charts
    const timestamp = new Date().toLocaleTimeString();
    
    // Update CPU Chart
    if (cpuChart.data.labels.length > 20) {
        cpuChart.data.labels.shift();
        cpuChart.data.datasets[0].data.shift();
    }
    cpuChart.data.labels.push(timestamp);
    cpuChart.data.datasets[0].data.push(data.cpu);
    cpuChart.update();
    
    // Update Memory Chart
    if (memoryChart.data.labels.length > 20) {
        memoryChart.data.labels.shift();
        memoryChart.data.datasets[0].data.shift();
    }
    memoryChart.data.labels.push(timestamp);
    memoryChart.data.datasets[0].data.push(data.memory);
    memoryChart.update();
    
    // Update Disk Chart
    if (diskChart.data.labels.length > 20) {
        diskChart.data.labels.shift();
        diskChart.data.datasets[0].data.shift();
    }
    diskChart.data.labels.push(timestamp);
    diskChart.data.datasets[0].data.push(data.disk);
    diskChart.update();
    
    // Update Network Chart
    if (networkChart.data.labels.length > 20) {
        networkChart.data.labels.shift();
        networkChart.data.datasets.forEach(dataset => dataset.data.shift());
    }
    networkChart.data.labels.push(timestamp);
    networkChart.data.datasets[0].data.push(networkInSpeed / 1024);  // Convert to KB/s
    networkChart.data.datasets[1].data.push(networkOutSpeed / 1024);  // Convert to KB/s
    networkChart.update();
}

// Update system information
function updateSystemInfo(data) {
    document.getElementById('platformInfo').textContent = data.platform || 'N/A';
    document.getElementById('processorInfo').textContent = data.processor || 'N/A';
    document.getElementById('architectureInfo').textContent = data.architecture || 'N/A';
    document.getElementById('hostnameInfo').textContent = data.hostname || 'N/A';
    document.getElementById('ipAddressInfo').textContent = data.ip_address || 'N/A';
}

// Fetch system information
function fetchSystemInfo() {
    fetch('/api/admin/system-info')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            updateSystemInfo(data);
        })
        .catch(error => {
            console.error('Error fetching system information:', error);
            // Set error state for system info
            const errorMessage = 'Error loading system information';
            document.getElementById('platformInfo').textContent = errorMessage;
            document.getElementById('processorInfo').textContent = errorMessage;
            document.getElementById('architectureInfo').textContent = errorMessage;
            document.getElementById('hostnameInfo').textContent = errorMessage;
            document.getElementById('ipAddressInfo').textContent = errorMessage;
            
            // Show error notification
            showNotification('error', 'Failed to load system information. Please try again later.');
        });
}

// Show notification function
function showNotification(type, message) {
    const notification = document.createElement('div');
    notification.className = `fixed bottom-4 right-4 p-4 rounded-lg shadow-lg ${
        type === 'error' ? 'bg-red-100 text-red-700 border border-red-400' :
        type === 'success' ? 'bg-green-100 text-green-700 border border-green-400' :
        'bg-blue-100 text-blue-700 border border-blue-400'
    }`;
    notification.innerHTML = message;
    document.body.appendChild(notification);
    
    // Remove notification after 5 seconds
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Handle new threats
function handleNewThreat(threat) {
    const threatsList = document.getElementById('activeThreats');
    const threatItem = document.createElement('li');
    threatItem.className = 'py-4';
    
    const severityClass = {
        'high': 'bg-red-100 text-red-800',
        'medium': 'bg-yellow-100 text-yellow-800',
        'low': 'bg-blue-100 text-blue-800'
    }[threat.severity] || 'bg-gray-100 text-gray-800';
    
    threatItem.innerHTML = `
        <div class="flex space-x-3">
            <div class="flex-1 space-y-1">
                <div class="flex items-center justify-between">
                    <h3 class="text-sm font-medium text-gray-900">${threat.type}</h3>
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityClass}">
                        ${threat.severity}
                    </span>
                </div>
                <p class="text-sm text-gray-500">${threat.details}</p>
                <p class="text-xs text-gray-400">${new Date().toLocaleString()}</p>
            </div>
        </div>
    `;
    
    threatsList.insertBefore(threatItem, threatsList.firstChild);
    updateThreatCount();
}

// Update threat count
function updateThreatCount() {
    const count = document.getElementById('activeThreats').children.length;
    const threatCount = document.getElementById('threatCount');
    threatCount.textContent = `${count} Active`;
    threatCount.className = `px-2 py-1 text-xs font-medium rounded-full ${
        count > 0 ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
    }`;
}

// Socket event handlers
socket.on('user_activity_update', (data) => {
    updateUserList();
    updateStats();
});

socket.on('new_log', (log) => {
    updateSystemLogs();
});

socket.on('metrics_update', (data) => {
    updateMetrics(data);
});

socket.on('new_threat', (threat) => {
    handleNewThreat(threat);
});

// Form submission handlers
document.addEventListener('DOMContentLoaded', function() {
    const createUserForm = document.getElementById('createUserForm');
    if (createUserForm) {
        createUserForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const submitButton = this.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            
            const formData = new FormData(this);
            const data = {
                name: formData.get('name'),
                email: formData.get('email'),
                license_type: formData.get('license_type')
            };

            // Validate form data
            if (!data.name || !data.email || !data.license_type) {
                showNotification('error', 'Please fill in all required fields');
                submitButton.disabled = false;
                return;
            }

            fetch('/api/admin/users/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    hideCreateUserModal();
                    updateUserList();
                    updateStats();
                    showNotification('success', 'User created successfully');
                } else {
                    throw new Error(data.error || 'Error creating user');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('error', error.message || 'Error creating user');
            })
            .finally(() => {
                submitButton.disabled = false;
            });
        });
    }

    const editUserForm = document.getElementById('editUserForm');
    if (editUserForm) {
        editUserForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const userId = formData.get('user_id');
            const data = {
                name: formData.get('name'),
                email: formData.get('email'),
                license_type: formData.get('license_type')
            };

            fetch(`/api/admin/users/${userId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideEditUserModal();
                    updateUserList();
                    // Show success message
                    alert('User updated successfully');
                } else {
                    alert(data.error || 'Error updating user');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error updating user');
            });
        });
    }

    const extendLicenseForm = document.getElementById('extendLicenseForm');
    if (extendLicenseForm) {
        extendLicenseForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const userId = formData.get('user_id');
            const data = {
                duration_days: parseInt(formData.get('duration_days'))
            };

            fetch(`/api/admin/users/${userId}/extend-license`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideExtendLicenseModal();
                    updateUserList();
                    // Show success message
                    alert('License extended successfully');
                } else {
                    alert(data.error || 'Error extending license');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error extending license');
            });
        });
    }

    startSystemLogsUpdate();
    fetchSystemInfo();
    // Update system info every 30 seconds
    setInterval(fetchSystemInfo, 30000);
});

// Initialize dashboard with user management
document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    updateSystemInfo();
    updateStats();
    updateUserList();
    updateSystemLogs();
    
    // Update data periodically
    setInterval(updateStats, 30000);  // Every 30 seconds
    setInterval(updateSystemLogs, 60000);  // Every minute
    setInterval(updateSystemInfo, 300000);  // Every 5 minutes
}); 