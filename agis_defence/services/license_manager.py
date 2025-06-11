import jwt
from datetime import datetime, timedelta
import logging
from typing import Dict, Optional
import sqlite3
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

class LicenseManager:
    def __init__(self):
        self.db_path = Path("data/licenses.db")
        self.db_path.parent.mkdir(exist_ok=True)
        self.lock = threading.Lock()
        self._init_database()
        
    def _init_database(self):
        """Initialize the license database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS licenses (
                        client_id TEXT PRIMARY KEY,
                        license_key TEXT UNIQUE,
                        subscription_type TEXT,
                        start_date TEXT,
                        end_date TEXT,
                        status TEXT,
                        permissions TEXT,
                        max_systems INTEGER
                    )
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS active_systems (
                        system_id TEXT PRIMARY KEY,
                        client_id TEXT,
                        last_active TEXT,
                        FOREIGN KEY (client_id) REFERENCES licenses(client_id)
                    )
                """)
                
        except Exception as e:
            logger.error(f"Database initialization failed: {str(e)}")
            raise

    def register_license(self, client_data: Dict) -> bool:
        """Register a new license"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT INTO licenses (
                            client_id, license_key, subscription_type,
                            start_date, end_date, status, permissions, max_systems
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        client_data['client_id'],
                        client_data['license_key'],
                        client_data['subscription_type'],
                        datetime.now().isoformat(),
                        (datetime.now() + self._get_subscription_duration(client_data['subscription_type'])).isoformat(),
                        'active',
                        client_data.get('permissions', 'basic'),
                        self._get_max_systems(client_data['subscription_type'])
                    ))
                    return True
        except Exception as e:
            logger.error(f"License registration failed: {str(e)}")
            return False

    def validate_license(self, client_id: str, license_key: str) -> Dict:
        """Validate a license and return status"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT subscription_type, end_date, status, permissions, max_systems
                    FROM licenses
                    WHERE client_id = ? AND license_key = ?
                """, (client_id, license_key))
                
                result = cursor.fetchone()
                if not result:
                    return {'valid': False, 'reason': 'Invalid license'}
                    
                subscription_type, end_date, status, permissions, max_systems = result
                
                # Check if license is expired
                if datetime.fromisoformat(end_date) < datetime.now():
                    return {'valid': False, 'reason': 'License expired'}
                    
                # Check if license is active
                if status != 'active':
                    return {'valid': False, 'reason': 'License inactive'}
                    
                return {
                    'valid': True,
                    'subscription_type': subscription_type,
                    'end_date': end_date,
                    'permissions': permissions,
                    'max_systems': max_systems
                }
                
        except Exception as e:
            logger.error(f"License validation failed: {str(e)}")
            return {'valid': False, 'reason': 'Validation error'}

    def register_system(self, client_id: str, system_id: str) -> bool:
        """Register a new system for a client"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    # Check current system count
                    cursor = conn.execute("""
                        SELECT COUNT(*), l.max_systems
                        FROM active_systems a
                        JOIN licenses l ON l.client_id = a.client_id
                        WHERE a.client_id = ?
                    """, (client_id,))
                    
                    current_count, max_systems = cursor.fetchone()
                    
                    if current_count >= max_systems:
                        logger.warning(f"Maximum systems reached for client {client_id}")
                        return False
                        
                    # Register new system
                    conn.execute("""
                        INSERT INTO active_systems (system_id, client_id, last_active)
                        VALUES (?, ?, ?)
                    """, (system_id, client_id, datetime.now().isoformat()))
                    
                    return True
                    
        except Exception as e:
            logger.error(f"System registration failed: {str(e)}")
            return False

    def update_system_activity(self, system_id: str):
        """Update last active timestamp for a system"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE active_systems
                    SET last_active = ?
                    WHERE system_id = ?
                """, (datetime.now().isoformat(), system_id))
                
        except Exception as e:
            logger.error(f"Activity update failed: {str(e)}")

    def get_client_permissions(self, client_id: str) -> Optional[Dict]:
        """Get permissions for a client"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT permissions
                    FROM licenses
                    WHERE client_id = ?
                """, (client_id,))
                
                result = cursor.fetchone()
                if result:
                    return {'permissions': result[0]}
                return None
                
        except Exception as e:
            logger.error(f"Error getting permissions: {str(e)}")
            return None

    def _get_subscription_duration(self, subscription_type: str) -> timedelta:
        """Get duration based on subscription type"""
        durations = {
            '3_months': timedelta(days=90),
            '6_months': timedelta(days=180),
            '1_year': timedelta(days=365)
        }
        return durations.get(subscription_type, timedelta(days=30))

    def _get_max_systems(self, subscription_type: str) -> int:
        """Get maximum allowed systems based on subscription"""
        limits = {
            '3_months': 2,
            '6_months': 5,
            '1_year': 10
        }
        return limits.get(subscription_type, 1)

    def cleanup_inactive_systems(self, inactive_threshold: timedelta = timedelta(days=30)):
        """Clean up inactive system registrations"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        DELETE FROM active_systems
                        WHERE datetime(last_active) < datetime(?)
                    """, ((datetime.now() - inactive_threshold).isoformat(),))
                    
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")

    def get_subscription_info(self, client_id: str) -> Optional[Dict]:
        """Get subscription information for a client"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT subscription_type, start_date, end_date, status
                    FROM licenses
                    WHERE client_id = ?
                """, (client_id,))
                
                result = cursor.fetchone()
                if result:
                    return {
                        'subscription_type': result[0],
                        'start_date': result[1],
                        'end_date': result[2],
                        'status': result[3]
                    }
                return None
                
        except Exception as e:
            logger.error(f"Error getting subscription info: {str(e)}")
            return None 