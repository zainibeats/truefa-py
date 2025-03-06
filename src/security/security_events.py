"""
Security Events Module

This module provides functionality for tracking and handling security events
in the application. It helps monitor potential security issues and can trigger
appropriate responses.

Key Features:
- Security event tracking
- Event categorization and counting
- Automatic response to repeated security events
"""

import time
import logging
import threading

# Configure logging
logger = logging.getLogger(__name__)

class SecurityEventTracker:
    """
    Tracks security events and provides response mechanisms.
    """
    
    def __init__(self, cooldown_period=300):
        """
        Initialize the security event tracker.
        
        Args:
            cooldown_period: Cooldown period in seconds after an alert (default: 300)
        """
        self._error_states = {
            'debug_attempts': 0,
            'path_violations': 0,
            'buffer_overflows': 0,
            'format_attacks': 0,
            'permission_violations': 0,
            'integrity_violations': 0,
        }
        self._lock = threading.Lock()
        self._last_alert_time = 0
        self._cooldown_period = cooldown_period
        
    def record_event(self, event_type, details=None):
        """
        Record a security event and take appropriate action.
        
        Args:
            event_type: Type of security event
            details: Additional details about the event (optional)
            
        Returns:
            bool: True if event was recorded, False otherwise
        """
        with self._lock:
            current_time = time.time()
            
            # Map event type to counter
            counter_map = {
                'debug_attempt': 'debug_attempts',
                'invalid_path': 'path_violations',
                'buffer_overflow': 'buffer_overflows',
                'format_attack': 'format_attacks',
                'permission_violation': 'permission_violations', 
                'integrity_violation': 'integrity_violations',
            }
            
            counter = counter_map.get(event_type)
            if not counter:
                logger.warning(f"Unknown security event type: {event_type}")
                return False
                
            # Increment the counter
            self._error_states[counter] += 1
            
            # Log the event
            log_message = f"Security event detected: {event_type}"
            if details:
                log_message += f", Details: {details}"
            logger.warning(log_message)
            
            # Check if we should alert
            should_alert = False
            alert_threshold = 1  # Default threshold for most events
            
            # Custom thresholds for different event types
            if event_type == 'debug_attempt':
                alert_threshold = 3  # Alert after 3 debug attempts
            elif event_type == 'path_violations':
                alert_threshold = 2  # Alert after 2 path violations
                
            if self._error_states[counter] >= alert_threshold:
                # Check if we're in the cooldown period
                if (current_time - self._last_alert_time) > self._cooldown_period:
                    should_alert = True
                    self._last_alert_time = current_time
            
            # Special case for integrity violations - always alert
            if event_type == 'integrity_violation':
                should_alert = True
                
            # Handle the alert
            if should_alert:
                self._handle_security_alert(event_type, self._error_states[counter])
                
            return True
    
    def _handle_security_alert(self, event_type, count):
        """
        Handle a security alert.
        
        Args:
            event_type: Type of security event
            count: Number of occurrences
        """
        alert_message = f"SECURITY ALERT: {event_type} detected ({count} occurrences)"
        logger.critical(alert_message)
        print(alert_message)
        
        # Could add additional response mechanisms here:
        # - Send email alerts
        # - Log to a separate security log
        # - Trigger application-specific security measures
        
    def get_event_count(self, event_type):
        """
        Get the count of a specific event type.
        
        Args:
            event_type: Type of security event counter to retrieve
            
        Returns:
            int: Count of the specified event type
        """
        counter_map = {
            'debug_attempt': 'debug_attempts',
            'invalid_path': 'path_violations',
            'buffer_overflow': 'buffer_overflows',
            'format_attack': 'format_attacks',
            'permission_violation': 'permission_violations',
            'integrity_violation': 'integrity_violations',
        }
        
        counter = counter_map.get(event_type)
        if not counter:
            return 0
            
        with self._lock:
            return self._error_states.get(counter, 0)
            
    def reset_counters(self):
        """Reset all security event counters."""
        with self._lock:
            for key in self._error_states:
                self._error_states[key] = 0

# Create a global instance for convenience
tracker = SecurityEventTracker()

def record_security_event(event_type, details=None):
    """Convenience function to record a security event using the global tracker."""
    return tracker.record_event(event_type, details)

def get_security_event_count(event_type):
    """Convenience function to get a security event count using the global tracker."""
    return tracker.get_event_count(event_type)

def reset_security_counters():
    """Convenience function to reset security counters using the global tracker."""
    tracker.reset_counters() 