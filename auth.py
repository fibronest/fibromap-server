# auth.py
"""
Authentication logic for FibroMAP Railway server.
Handles user authentication, session management, and security.
"""

import os
import secrets
import hashlib
import bcrypt
import re
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
import logging

from database import db_manager
from models import User, Session, AuditLog

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AuthenticationManager:
    """Handles user authentication and session management."""
    
    def __init__(self):
        """Initialize authentication manager."""
        self.session_timeout_hours = int(os.getenv('SESSION_TIMEOUT_HOURS', '8'))
        self.remember_me_days = int(os.getenv('REMEMBER_ME_DAYS', '30'))
        self.password_min_length = int(os.getenv('PASSWORD_MIN_LENGTH', '8'))
        self.max_failed_attempts = int(os.getenv('MAX_FAILED_ATTEMPTS', '5'))
        self.lockout_duration_minutes = int(os.getenv('LOCKOUT_DURATION_MINUTES', '15'))
    
    def authenticate_user(self, username: str, password: str, ip_address: str = None) -> tuple[bool, str, Optional[User]]:
        """
        Authenticate user with username/password.
        
        Args:
            username: Username or email
            password: Plain text password
            ip_address: Client IP address for logging
            
        Returns:
            Tuple of (success, message, user_object)
        """
        try:
            logger.info(f"DEBUG: Starting authentication for user: {username} from IP: {ip_address}")
            
            # Use global db_manager
            user = db_manager.get_user_by_username(username)
            
            if not user:
                logger.warning(f"DEBUG: User not found: {username}")
                return False, "Invalid credentials", None
            
            logger.info(f"DEBUG: User found - ID: {user.user_id}, Username: {user.username}")
            logger.info(f"DEBUG: Password hash exists: {bool(user.password_hash)}")
            logger.info(f"DEBUG: Failed attempts: {user.failed_attempts}")
            
            # Check if account is locked
            if user.locked_until and user.locked_until > datetime.now():
                time_remaining = (user.locked_until - datetime.now()).seconds // 60
                return False, f"Account locked. Try again in {time_remaining} minutes", None
            
            # Check if user is active
            if not user.is_active:
                return False, "Account is not active", None
            
            # TEMPORARY BYPASS - MOVE THIS BEFORE BCRYPT CHECK
            if password in ["test123", "admin123"]:  # Allow both for testing
                logger.info(f"DEBUG: USING TEMPORARY BYPASS - Password matches {password}")
                db_manager.update_user_login(user.user_id, reset_failed_attempts=True)
                
                # Log successful login
                audit_log = AuditLog(
                    user_id=user.user_id,
                    action="login_successful_bypass",  # Mark as bypass for tracking
                    details={},
                    ip_address=ip_address,
                    success=True
                )
                db_manager.log_action(audit_log)
                
                return True, "Login successful", user
            
            # Normal bcrypt verification (currently not working)
            try:
                logger.info(f"DEBUG: Attempting bcrypt verification...")
                password_bytes = password.encode('utf-8')
                hash_bytes = user.password_hash.encode('utf-8')
                
                if bcrypt.checkpw(password_bytes, hash_bytes):
                    logger.info(f"DEBUG: Password verification SUCCESS")
                    db_manager.update_user_login(user.user_id, reset_failed_attempts=True)
                    
                    audit_log = AuditLog(
                        user_id=user.user_id,
                        action="login_successful",
                        details={},
                        ip_address=ip_address,
                        success=True
                    )
                    db_manager.log_action(audit_log)
                    
                    return True, "Login successful", user
                else:
                    logger.warning(f"DEBUG: Password verification FAILED")
                    db_manager.increment_failed_attempts(user.user_id)
                    
                    remaining = max(0, 5 - (user.failed_attempts + 1))
                    
                    if remaining > 0:
                        return False, f"Invalid credentials ({remaining} attempts remaining)", None
                    else:
                        return False, "Account locked due to too many failed attempts", None
                        
            except Exception as e:
                logger.error(f"DEBUG: Password verification error: {e}", exc_info=True)
                return False, "Authentication system error", None
                
        except Exception as e:
            logger.error(f"DEBUG: Authentication error: {e}", exc_info=True)
            return False, "Authentication system error", None
    
    def create_session(self, user: User, remember_me: bool = False, 
                    ip_address: str = None, user_agent: str = None) -> Optional[str]:
        """Create a new session for authenticated user."""
        try:
            # Generate session ID and token
            session_id = secrets.token_urlsafe(32)
            session_token = secrets.token_urlsafe(64)
            
            # Hash the token for storage
            token_hash = hashlib.sha256(session_token.encode()).hexdigest()
            
            # Set expiration based on remember_me
            if remember_me:
                expires_at = datetime.now() + timedelta(days=30)
            else:
                expires_at = datetime.now() + timedelta(hours=8)
            
            # Create session object
            session = Session(
                session_id=session_id,
                user_id=user.user_id,
                token_hash=token_hash,
                expires_at=expires_at,
                ip_address=ip_address,
                user_agent=user_agent,
                is_remember_me=remember_me
            )
            
            # Save to database (use global db_manager, not self.db_manager)
            if db_manager.create_session(session):
                logger.info(f"Session created for user {user.username}")
                return session_token
            else:
                logger.error(f"Failed to save session for user {user.username}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return None
        
    def validate_session(self, session_token: str, ip_address: str = None) -> Optional[User]:
        """
        Validate a session token and return user if valid.
        
        Args:
            session_token: Full session token (session_id:token)
            ip_address: Client IP address for validation
            
        Returns:
            User object if session is valid, None otherwise
        """
        try:
            if not session_token or ':' not in session_token:
                return None
            
            # Split session token
            session_id, token = session_token.split(':', 1)
            
            # Get session from database
            session = db_manager.get_session(session_id)
            if not session:
                return None
            
            # Verify token hash
            if not self._verify_token_hash(token, session.token_hash):
                logger.warning(f"Invalid token hash for session {session_id}")
                return None
            
            # Optional: Verify IP address (if enabled)
            if os.getenv('SESSION_BIND_IP', 'false').lower() == 'true':
                if session.ip_address and session.ip_address != ip_address:
                    logger.warning(f"IP address mismatch for session {session_id}")
                    return None
            
            # Get user data
            user = db_manager.get_user_by_id(session.user_id)
            if not user or not user.is_active:
                return None
            
            # Update last activity (optional - can be disabled for performance)
            if os.getenv('UPDATE_SESSION_ACTIVITY', 'true').lower() == 'true':
                self._update_session_activity(session_id)
            
            return user
            
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return None
    
    def invalidate_session(self, session_token: str, user_id: int = None, ip_address: str = None) -> bool:
        """
        Invalidate a session (logout).
        
        Args:
            session_token: Full session token to invalidate
            user_id: User ID for audit logging
            ip_address: Client IP address for audit logging
            
        Returns:
            True if session was invalidated, False otherwise
        """
        try:
            if not session_token or ':' not in session_token:
                return False
            
            session_id, _ = session_token.split(':', 1)
            
            # Delete session from database
            success = db_manager.delete_session(session_id)
            
            if success and user_id:
                self._log_auth_attempt(user_id, "session_invalidated", ip_address, True, 
                                     {"session_id": session_id})
            
            return success
            
        except Exception as e:
            logger.error(f"Session invalidation error: {e}")
            return False
    
    def register_user(self, username: str, email: str, password: str, ip_address: str = None) -> Tuple[bool, str, Optional[User]]:
        """
        Register a new user account.
        
        Args:
            username: Desired username
            email: Email address
            password: Plain text password
            ip_address: Client IP address for audit logging
            
        Returns:
            Tuple of (success, message, user_data)
        """
        try:
            # Validate input
            validation_result = self._validate_registration_input(username, email, password)
            if not validation_result[0]:
                return False, validation_result[1], None
            
            # Clean inputs
            username = username.strip()
            email = email.strip().lower()
            
            # Hash password
            password_hash = self._hash_password(password)
            
            # Create user
            user = db_manager.create_user(username, email, password_hash)
            if user:
                self._log_auth_attempt(user.user_id, "user_registered", ip_address, True, 
                                     {"username": username, "email": email})
                return True, "User registered successfully", user
            else:
                return False, "Username or email already exists", None
                
        except Exception as e:
            logger.error(f"User registration error: {e}")
            return False, "Registration system error", None
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions. Returns number of sessions cleaned."""
        try:
            count = db_manager.cleanup_expired_sessions()
            logger.info(f"Cleaned up {count} expired sessions")
            return count
        except Exception as e:
            logger.error(f"Session cleanup error: {e}")
            return 0
    
    # Private helper methods
    
    def _verify_password(self, password: str, user: User) -> bool:
        """Verify password against stored hash."""
        try:
            # Get password hash from user (need to fetch from DB since User model doesn't include it)
            db_user = db_manager.get_user_by_username(user.username)
            if not db_user:
                return False
            
            # Note: We need to access the password_hash from the raw database query
            # This is a simplified version - in practice, you'd modify get_user_by_username
            # to optionally return the password hash
            with db_manager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT password_hash FROM users WHERE user_id = %s", (user.user_id,))
                    row = cursor.fetchone()
                    if not row:
                        return False
                    
                    password_hash = row[0]
                    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
                    
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        rounds = int(os.getenv('BCRYPT_ROUNDS', '12'))
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def _generate_session_id(self) -> str:
        """Generate a secure session ID."""
        return secrets.token_urlsafe(32)
    
    def _generate_session_token(self) -> str:
        """Generate a secure session token."""
        return secrets.token_urlsafe(32)
    
    def _hash_token(self, token: str) -> str:
        """Hash a session token for storage."""
        return hashlib.sha256(token.encode('utf-8')).hexdigest()
    
    def _verify_token_hash(self, token: str, stored_hash: str) -> bool:
        """Verify a token against its stored hash."""
        return hashlib.sha256(token.encode('utf-8')).hexdigest() == stored_hash
    
    def _is_account_locked(self, user: User) -> bool:
        """Check if user account is currently locked."""
        try:
            with db_manager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT locked_until FROM users WHERE user_id = %s", (user.user_id,))
                    row = cursor.fetchone()
                    
                    if row and row[0]:
                        locked_until = row[0]
                        return datetime.now() < locked_until
                    
                    return False
                    
        except Exception as e:
            logger.error(f"Error checking account lock status: {e}")
            return False
    
    def _update_session_activity(self, session_id: str):
        """Update session last activity timestamp."""
        try:
            with db_manager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE sessions 
                        SET last_activity = %s 
                        WHERE session_id = %s
                    """, (datetime.now(), session_id))
                    conn.commit()
        except Exception as e:
            logger.error(f"Error updating session activity: {e}")
    
    def _validate_registration_input(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        """Validate user registration input."""
        # Username validation
        if not username or len(username.strip()) < 3:
            return False, "Username must be at least 3 characters long"
        
        if len(username.strip()) > 50:
            return False, "Username must be less than 50 characters"
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', username.strip()):
            return False, "Username can only contain letters, numbers, hyphens, and underscores"
        
        # Email validation
        if not email or len(email.strip()) < 5:
            return False, "Valid email address is required"
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email.strip()):
            return False, "Invalid email format"
        
        # Password validation
        if not password or len(password) < self.password_min_length:
            return False, f"Password must be at least {self.password_min_length} characters long"
        
        if len(password) > 128:
            return False, "Password must be less than 128 characters"
        
        # Password strength check
        if not self._check_password_strength(password):
            return False, "Password must contain at least one uppercase letter, one lowercase letter, and one number"
        
        return True, "Valid"
    
    def _check_password_strength(self, password: str) -> bool:
        """Check if password meets strength requirements."""
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        
        return has_upper and has_lower and has_digit
    
    def _log_auth_attempt(self, user_id: Optional[int], action: str, ip_address: str = None, 
                         success: bool = True, details: Dict[str, Any] = None):
        """Log authentication attempt for audit trail."""
        try:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                details=details or {},
                ip_address=ip_address,
                success=success
            )
            db_manager.log_action(audit_log)
        except Exception as e:
            logger.error(f"Error logging auth attempt: {e}")


# Global authentication manager instance
auth_manager = AuthenticationManager()