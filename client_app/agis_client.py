import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
import requests
import psutil
import logging
from datetime import datetime
import websockets
import asyncio
from pathlib import Path

class AGISClientApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("AGIS Defence System")
        self.geometry("800x600")
        
        # Initialize system tray icon
        self.setup_tray_icon()
        
        # Initialize monitoring
        self.monitoring_active = False
        self.ai_agent_active = False
        
        # Create UI
        self.create_ui()
        
        # Start monitoring
        self.start_monitoring()
        
    def create_ui(self):
        """Create the main user interface."""
        # Create notebook for tabs
        notebook = ttk.Notebook(self)
        notebook.pack(expand=True, fill='both', padx=10, pady=5)
        
        # Dashboard tab
        dashboard_frame = ttk.Frame(notebook)
        notebook.add(dashboard_frame, text='Dashboard')
        self.create_dashboard(dashboard_frame)
        
        # Protection tab
        protection_frame = ttk.Frame(notebook)
        notebook.add(protection_frame, text='Protection')
        self.create_protection_tab(protection_frame)
        
        # Logs tab
        logs_frame = ttk.Frame(notebook)
        notebook.add(logs_frame, text='Logs')
        self.create_logs_tab(logs_frame)
        
        # Settings tab
        settings_frame = ttk.Frame(notebook)
        notebook.add(settings_frame, text='Settings')
        self.create_settings_tab(settings_frame)
        
    def create_dashboard(self, parent):
        """Create the dashboard view."""
        # Status frame
        status_frame = ttk.LabelFrame(parent, text="System Status", padding=10)
        status_frame.pack(fill='x', padx=5, pady=5)
        
        # Protection status
        self.protection_status = ttk.Label(status_frame, text="Protection: Active")
        self.protection_status.pack(anchor='w')
        
        # AI Agent status
        self.ai_status = ttk.Label(status_frame, text="AI Agent: Active")
        self.ai_status.pack(anchor='w')
        
        # Threats blocked
        self.threats_label = ttk.Label(status_frame, text="Threats Blocked: 0")
        self.threats_label.pack(anchor='w')
        
        # System metrics frame
        metrics_frame = ttk.LabelFrame(parent, text="System Metrics", padding=10)
        metrics_frame.pack(fill='x', padx=5, pady=5)
        
        # CPU Usage
        self.cpu_label = ttk.Label(metrics_frame, text="CPU Usage: 0%")
        self.cpu_label.pack(anchor='w')
        
        # Memory Usage
        self.memory_label = ttk.Label(metrics_frame, text="Memory Usage: 0%")
        self.memory_label.pack(anchor='w')
        
        # Recent threats frame
        threats_frame = ttk.LabelFrame(parent, text="Recent Threats", padding=10)
        threats_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Threats listbox
        self.threats_list = tk.Listbox(threats_frame)
        self.threats_list.pack(fill='both', expand=True)
        
    def create_protection_tab(self, parent):
        """Create the protection settings view."""
        # Protection options frame
        options_frame = ttk.LabelFrame(parent, text="Protection Options", padding=10)
        options_frame.pack(fill='x', padx=5, pady=5)
        
        # Real-time protection
        self.realtime_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Real-time Protection", 
                       variable=self.realtime_var,
                       command=self.toggle_realtime_protection).pack(anchor='w')
        
        # AI Protection
        self.ai_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="AI-powered Protection",
                       variable=self.ai_var,
                       command=self.toggle_ai_protection).pack(anchor='w')
        
        # Data Recovery
        self.recovery_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Automatic Data Recovery",
                       variable=self.recovery_var,
                       command=self.toggle_data_recovery).pack(anchor='w')
        
    def create_logs_tab(self, parent):
        """Create the logs view."""
        # Logs frame
        logs_frame = ttk.Frame(parent, padding=10)
        logs_frame.pack(fill='both', expand=True)
        
        # Logs text area
        self.logs_text = tk.Text(logs_frame, wrap=tk.WORD, height=20)
        self.logs_text.pack(fill='both', expand=True)
        
        # Export button
        ttk.Button(logs_frame, text="Export Logs",
                  command=self.export_logs).pack(pady=5)
        
    def create_settings_tab(self, parent):
        """Create the settings view."""
        settings_frame = ttk.Frame(parent, padding=10)
        settings_frame.pack(fill='both', expand=True)
        
        # License information
        license_frame = ttk.LabelFrame(settings_frame, text="License Information", padding=10)
        license_frame.pack(fill='x', padx=5, pady=5)
        
        self.license_label = ttk.Label(license_frame, text="License: Active")
        self.license_label.pack(anchor='w')
        
        self.expiry_label = ttk.Label(license_frame, text="Expires: Not Available")
        self.expiry_label.pack(anchor='w')
        
        # Update settings
        update_frame = ttk.LabelFrame(settings_frame, text="Updates", padding=10)
        update_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(update_frame, text="Check for Updates",
                  command=self.check_updates).pack(pady=5)
        
        # Auto-update option
        self.auto_update_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(update_frame, text="Automatic Updates",
                       variable=self.auto_update_var).pack(anchor='w')
        
    def start_monitoring(self):
        """Start system monitoring."""
        self.monitoring_active = True
        threading.Thread(target=self.monitor_system, daemon=True).start()
        threading.Thread(target=self.monitor_threats, daemon=True).start()
        
    def monitor_system(self):
        """Monitor system metrics."""
        while self.monitoring_active:
            try:
                # Update CPU usage
                cpu_percent = psutil.cpu_percent()
                self.cpu_label.config(text=f"CPU Usage: {cpu_percent}%")
                
                # Update memory usage
                memory = psutil.virtual_memory()
                self.memory_label.config(text=f"Memory Usage: {memory.percent}%")
                
                # Send metrics to server
                self.send_metrics({
                    'cpu': cpu_percent,
                    'memory': memory.percent,
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                self.log_error(f"Error monitoring system: {str(e)}")
                
            threading.Event().wait(1)  # Update every second
            
    def monitor_threats(self):
        """Monitor for security threats."""
        while self.monitoring_active:
            try:
                # Check for threats
                threats = self.check_threats()
                
                if threats:
                    for threat in threats:
                        # Update UI
                        self.threats_list.insert(0, f"{threat['timestamp']} - {threat['type']}")
                        
                        # Log threat
                        self.log_threat(threat)
                        
                        # Take action
                        self.handle_threat(threat)
                
            except Exception as e:
                self.log_error(f"Error monitoring threats: {str(e)}")
                
            threading.Event().wait(5)  # Check every 5 seconds
            
    def check_threats(self):
        """Check for security threats."""
        # This would integrate with the AI agent for threat detection
        return []
        
    def handle_threat(self, threat):
        """Handle detected threats."""
        try:
            # Log the threat
            self.log_message(f"Threat detected: {threat['type']}")
            
            # Update threat count
            current_count = int(self.threats_label['text'].split(': ')[1])
            self.threats_label.config(text=f"Threats Blocked: {current_count + 1}")
            
            # Show notification
            self.show_notification(
                "Threat Detected",
                f"AGIS Defence has blocked a {threat['type']} threat."
            )
            
            # Take action based on threat type
            if threat['severity'] == 'high':
                self.block_threat(threat)
            else:
                self.monitor_threat(threat)
                
        except Exception as e:
            self.log_error(f"Error handling threat: {str(e)}")
            
    def block_threat(self, threat):
        """Block a detected threat."""
        try:
            # Implement threat blocking logic
            pass
        except Exception as e:
            self.log_error(f"Error blocking threat: {str(e)}")
            
    def monitor_threat(self, threat):
        """Monitor a potential threat."""
        try:
            # Implement threat monitoring logic
            pass
        except Exception as e:
            self.log_error(f"Error monitoring threat: {str(e)}")
            
    def toggle_realtime_protection(self):
        """Toggle real-time protection."""
        if self.realtime_var.get():
            self.protection_status.config(text="Protection: Active")
        else:
            self.protection_status.config(text="Protection: Inactive")
            
    def toggle_ai_protection(self):
        """Toggle AI protection."""
        if self.ai_var.get():
            self.ai_status.config(text="AI Agent: Active")
        else:
            self.ai_status.config(text="AI Agent: Inactive")
            
    def toggle_data_recovery(self):
        """Toggle data recovery."""
        pass
        
    def export_logs(self):
        """Export system logs."""
        try:
            filename = f"agis_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(self.logs_text.get('1.0', tk.END))
            messagebox.showinfo("Success", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
            
    def check_updates(self):
        """Check for software updates."""
        try:
            # Implement update check logic
            pass
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check for updates: {str(e)}")
            
    def setup_tray_icon(self):
        """Set up system tray icon."""
        try:
            # Implement system tray icon
            pass
        except Exception as e:
            self.log_error(f"Error setting up tray icon: {str(e)}")
            
    def send_metrics(self, metrics):
        """Send metrics to server."""
        try:
            # Implement metric sending logic
            pass
        except Exception as e:
            self.log_error(f"Error sending metrics: {str(e)}")
            
    def log_message(self, message):
        """Log a message."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.logs_text.insert('1.0', f"[{timestamp}] {message}\n")
        
    def log_error(self, error):
        """Log an error."""
        self.log_message(f"ERROR: {error}")
        
    def log_threat(self, threat):
        """Log a threat."""
        self.log_message(f"THREAT: {threat['type']} - {threat['details']}")
        
    def show_notification(self, title, message):
        """Show a system notification."""
        try:
            # Implement notification logic
            pass
        except Exception as e:
            self.log_error(f"Error showing notification: {str(e)}")

def main():
    app = AGISClientApp()
    app.mainloop()

if __name__ == "__main__":
    main() 