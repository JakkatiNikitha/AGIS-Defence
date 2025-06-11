import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client
from typing import List, Dict, Any
from .config import ALERT_CONFIG

class AlertManager:
    def __init__(self):
        self.config = ALERT_CONFIG
        self._twilio_client = None

    @property
    def twilio_client(self) -> Client:
        """Lazy initialization of Twilio client"""
        if not self._twilio_client and self.config['whatsapp']['enabled']:
            self._twilio_client = Client(
                self.config['whatsapp']['twilio_account_sid'],
                self.config['whatsapp']['twilio_auth_token']
            )
        return self._twilio_client

    def send_alert(self, subject: str, message: str, threat_level: str = 'low') -> None:
        """Send alerts through configured channels"""
        try:
            if self.config['email']['enabled'] and all([
                self.config['email']['smtp_server'],
                self.config['email']['smtp_port'],
                self.config['email']['sender_email'],
                self.config['email']['recipient_email']
            ]):
                self._send_email_alert(subject, message)
        except Exception as e:
            print(f"Failed to send email alert: {str(e)}")

        try:
            if (self.config['whatsapp']['enabled'] and 
                self.config['whatsapp']['twilio_account_sid'] and 
                self.config['whatsapp']['twilio_auth_token'] and 
                self.config['whatsapp']['twilio_from_number'] and 
                self.config['whatsapp']['recipient_numbers']):
                self._send_whatsapp_alert(message)
        except Exception as e:
            print(f"Failed to send WhatsApp alert: {str(e)}")

    def _send_email_alert(self, subject: str, message: str) -> None:
        """Send email alert"""
        msg = MIMEMultipart()
        msg['From'] = self.config['email']['sender_email']
        msg['To'] = self.config['email']['recipient_email']
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))

        server = smtplib.SMTP(
            self.config['email']['smtp_server'], 
            self.config['email']['smtp_port']
        )
        server.starttls()
        server.login(
            self.config['email']['sender_email'],
            os.getenv('EMAIL_PASSWORD', '')
        )
        server.send_message(msg)
        server.quit()

    def _send_whatsapp_alert(self, message: str) -> None:
        """Send WhatsApp alert via Twilio"""
        if not self.twilio_client:
            return

        for number in self.config['whatsapp']['recipient_numbers']:
            self.twilio_client.messages.create(
                body=message,
                from_=f"whatsapp:{self.config['whatsapp']['twilio_from_number']}",
                to=f"whatsapp:{number}"
            )

    def update_settings(self, settings: Dict[str, Any]) -> None:
        """Update alert settings"""
        if 'whatsapp' in settings:
            self.config['whatsapp'].update({
                'enabled': settings['whatsapp'].get('enabled', self.config['whatsapp']['enabled']),
                'recipient_numbers': settings['whatsapp'].get('recipient_numbers', self.config['whatsapp']['recipient_numbers'])
            })
            # Reset Twilio client to pick up new settings
            self._twilio_client = None

# Create a global instance
alert_manager = AlertManager() 