# database.py
"""
PostgreSQL database operations for FibroMAP Railway server.
Handles all database connections, queries, and transactions.
"""

import os
import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
import logging

from models import (
    DatabaseSchema, User, Project, Session, ProjectPermission, 
    AuditLog, S3Version
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages PostgreSQL database connections and operations."""
    
    def __init__(self):
        """Initialize database manager with connection pool."""
        self.pool = None
        self._init_connection_pool()
        self._ensure_database_schema()
    
    def _init_connection_pool(self):
        """Initialize PostgreSQL connection pool."""
        try:
            # Get database URL from environment (Railway provides this)
            database_url = os.getenv('DATABASE_URL')
            if not database_url:
                raise ValueError("DATABASE_URL environment variable not found")
            
            # Create connection pool
            self.pool = ThreadedConnectionPool(
                minconn=1,
                maxconn=20,
                dsn=database_url
            )
            
            logger.info("Database connection pool initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize database connection pool: {e}")
            raise
    
    def _ensure_database_schema(self):
        """Ensure all database tables and indexes exist."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    # Create all tables
                    for sql in DatabaseSchema.get_create_tables_sql():
                        cursor.execute(sql)
                    
                    # Create all indexes
                    for sql in DatabaseSchema.get_create_indexes_sql():
                        cursor.execute(sql)
                    
                    conn.commit()
                    logger.info("Database schema ensured")
                    
        except Exception as e:
            logger.error(f"Failed to ensure database schema: {e}")
            raise
    
    def get_connection(self):
        """Get a database connection from the pool."""
        return self.pool.getconn()
    
    def return_connection(self, conn):
        """Return a database connection to the pool."""
        self.pool.putconn(conn)
    
    def close_all_connections(self):
        """Close all database connections."""
        if self.pool:
            self.pool.closeall()
    
    # User operations
    
    def create_user(self, username: str, email: str, password_hash: str, role: str = 'user') -> Optional[User]:
        """
        Create a new user.
        
        Args:
            username: Username (must be unique)
            email: Email address (must be unique)
            password_hash: Bcrypt hashed password
            role: User role ('user' or 'admin')
            
        Returns:
            User object if successful, None if failed
        """
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO users (username, email, password_hash, role)
                        VALUES (%s, %s, %s, %s)
                        RETURNING user_id, username, email, role, is_active, created_at, last_login
                    """, (username, email, password_hash, role))
                    
                    row = cursor.fetchone()
                    conn.commit()
                    
                    return User.from_db_row(row) if row else None
                    
        except psycopg2.IntegrityError as e:
            logger.warning(f"User creation failed - duplicate username/email: {e}")
            return None
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username or email."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT user_id, username, email, password_hash, role, is_active, 
                               created_at, last_login, failed_attempts, locked_until
                        FROM users 
                        WHERE (username = %s OR email = %s) AND is_active = true
                    """, (username, username))
                    
                    row = cursor.fetchone()
                    return User.from_db_row(row) if row else None
                    
        except Exception as e:
            logger.error(f"Error getting user by username: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT user_id, username, email, password_hash, role, is_active, 
                               created_at, last_login
                        FROM users 
                        WHERE user_id = %s AND is_active = true
                    """, (user_id,))
                    
                    row = cursor.fetchone()
                    return User.from_db_row(row) if row else None
                    
        except Exception as e:
            logger.error(f"Error getting user by ID: {e}")
            return None
    
    def update_user_login(self, user_id: int, reset_failed_attempts: bool = True) -> bool:
        """Update user's last login time and optionally reset failed attempts."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    if reset_failed_attempts:
                        cursor.execute("""
                            UPDATE users 
                            SET last_login = %s, failed_attempts = 0, locked_until = NULL
                            WHERE user_id = %s
                        """, (datetime.now(), user_id))
                    else:
                        cursor.execute("""
                            UPDATE users 
                            SET last_login = %s
                            WHERE user_id = %s
                        """, (datetime.now(), user_id))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                    
        except Exception as e:
            logger.error(f"Error updating user login: {e}")
            return False
    
    def increment_failed_attempts(self, user_id: int) -> bool:
        """Increment failed login attempts and lock account if necessary."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    # Get current failed attempts
                    cursor.execute("SELECT failed_attempts FROM users WHERE user_id = %s", (user_id,))
                    row = cursor.fetchone()
                    
                    if not row:
                        return False
                    
                    failed_attempts = row[0] + 1
                    locked_until = None
                    
                    # Lock account after 5 failed attempts
                    if failed_attempts >= 5:
                        locked_until = datetime.now() + timedelta(minutes=15)
                    
                    cursor.execute("""
                        UPDATE users 
                        SET failed_attempts = %s, locked_until = %s
                        WHERE user_id = %s
                    """, (failed_attempts, locked_until, user_id))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                    
        except Exception as e:
            logger.error(f"Error incrementing failed attempts: {e}")
            return False
    
    # Session operations
    
    def create_session(self, session: Session) -> bool:
        """Create a new user session."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO sessions (session_id, user_id, token_hash, ip_address, 
                                            user_agent, expires_at, is_remember_me)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (session.session_id, session.user_id, session.token_hash,
                          session.ip_address, session.user_agent, session.expires_at,
                          session.is_remember_me))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                    
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return False
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT session_id, user_id, token_hash, ip_address, user_agent,
                               expires_at, created_at, is_remember_me
                        FROM sessions 
                        WHERE session_id = %s AND expires_at > %s
                    """, (session_id, datetime.now()))
                    
                    row = cursor.fetchone()
                    if row:
                        return Session(
                            session_id=row[0],
                            user_id=row[1], 
                            token_hash=row[2],
                            ip_address=row[3],
                            user_agent=row[4],
                            expires_at=row[5],
                            created_at=row[6],
                            is_remember_me=row[7]
                        )
                    return None
                    
        except Exception as e:
            logger.error(f"Error getting session: {e}")
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM sessions WHERE session_id = %s", (session_id,))
                    conn.commit()
                    return cursor.rowcount > 0
                    
        except Exception as e:
            logger.error(f"Error deleting session: {e}")
            return False
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions. Returns number of sessions deleted."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM sessions WHERE expires_at <= %s", (datetime.now(),))
                    conn.commit()
                    return cursor.rowcount
                    
        except Exception as e:
            logger.error(f"Error cleaning up expired sessions: {e}")
            return 0
    
    # Project operations
    
    def create_project(self, project: Project) -> Optional[Project]:
        """Create a new project."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO projects (project_name, description, owner_id, s3_data_path, s3_images_folder)
                        VALUES (%s, %s, %s, %s, %s)
                        RETURNING project_id, project_name, description, owner_id, s3_data_path, 
                                s3_images_folder, created_at, updated_at, last_modified_by, version_count
                    """, (project.project_name, project.description, project.owner_id, 
                          project.s3_data_path, project.s3_images_folder))
                    
                    row = cursor.fetchone()
                    conn.commit()
                    
                    return Project.from_db_row(row) if row else None
                    
        except Exception as e:
            logger.error(f"Error creating project: {e}")
            return None
    
    def get_project(self, project_id: int) -> Optional[Project]:
        """Get project by ID."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT project_id, project_name, description, owner_id, s3_data_path, 
                               s3_images_folder, created_at, updated_at, last_modified_by, version_count
                        FROM projects 
                        WHERE project_id = %s AND is_active = true
                    """, (project_id,))
                    
                    row = cursor.fetchone()
                    return Project.from_db_row(row) if row else None
                    
        except Exception as e:
            logger.error(f"Error getting project: {e}")
            return None
    
    def get_user_projects(self, user_id: int) -> List[Project]:
        """Get all projects accessible to a user (owned or has permissions)."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT DISTINCT p.project_id, p.project_name, p.description, p.owner_id, 
                               p.s3_data_path, p.s3_images_folder, p.created_at, p.updated_at, 
                               p.last_modified_by, p.version_count
                        FROM projects p
                        LEFT JOIN project_permissions pp ON p.project_id = pp.project_id
                        WHERE (p.owner_id = %s OR pp.user_id = %s) AND p.is_active = true
                        ORDER BY p.updated_at DESC
                    """, (user_id, user_id))
                    
                    rows = cursor.fetchall()
                    return [Project.from_db_row(row) for row in rows]
                    
        except Exception as e:
            logger.error(f"Error getting user projects: {e}")
            return []
    
    def update_project(self, project_id: int, updated_at: datetime, last_modified_by: int, version_count: int = None) -> bool:
        """Update project metadata after save."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    if version_count is not None:
                        cursor.execute("""
                            UPDATE projects 
                            SET updated_at = %s, last_modified_by = %s, version_count = %s
                            WHERE project_id = %s
                        """, (updated_at, last_modified_by, version_count, project_id))
                    else:
                        cursor.execute("""
                            UPDATE projects 
                            SET updated_at = %s, last_modified_by = %s, version_count = version_count + 1
                            WHERE project_id = %s
                        """, (updated_at, last_modified_by, project_id))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                    
        except Exception as e:
            logger.error(f"Error updating project: {e}")
            return False
    
    def assign_project_images(self, project_id: int, s3_images_folder: str, user_id: int) -> bool:
        """Assign company images folder to project."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE projects 
                        SET s3_images_folder = %s, updated_at = %s, last_modified_by = %s
                        WHERE project_id = %s
                    """, (s3_images_folder, datetime.now(), user_id, project_id))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                    
        except Exception as e:
            logger.error(f"Error assigning project images: {e}")
            return False
    
    # Project permissions operations
    
    def grant_project_permission(self, project_id: int, user_id: int, permission_level: str, granted_by: int) -> bool:
        """Grant project permission to user."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO project_permissions (project_id, user_id, permission_level, granted_by)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (project_id, user_id) 
                        DO UPDATE SET permission_level = EXCLUDED.permission_level, 
                                     granted_by = EXCLUDED.granted_by, 
                                     granted_at = CURRENT_TIMESTAMP
                    """, (project_id, user_id, permission_level, granted_by))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                    
        except Exception as e:
            logger.error(f"Error granting project permission: {e}")
            return False
    
    def get_user_project_permission(self, project_id: int, user_id: int) -> Optional[str]:
        """Get user's permission level for a project."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    # Check if user is owner
                    cursor.execute("SELECT owner_id FROM projects WHERE project_id = %s", (project_id,))
                    row = cursor.fetchone()
                    if row and row[0] == user_id:
                        return 'admin'  # Owners have admin rights
                    
                    # Check explicit permissions
                    cursor.execute("""
                        SELECT permission_level FROM project_permissions 
                        WHERE project_id = %s AND user_id = %s
                    """, (project_id, user_id))
                    
                    row = cursor.fetchone()
                    return row[0] if row else None
                    
        except Exception as e:
            logger.error(f"Error getting user project permission: {e}")
            return None
    
    # Audit log operations
    
    def log_action(self, audit_log: AuditLog) -> bool:
        """Log an action to the audit log."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO audit_log (user_id, action, project_id, details, ip_address, success)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (audit_log.user_id, audit_log.action, audit_log.project_id,
                          json.dumps(audit_log.details), audit_log.ip_address, audit_log.success))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                    
        except Exception as e:
            logger.error(f"Error logging action: {e}")
            return False
    
    # S3 version operations
    
    def create_s3_version(self, s3_version: S3Version) -> bool:
        """Create S3 version backup record."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO s3_versions (project_id, version_name, s3_path, created_by, 
                                                is_overwritten, cleanup_after)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (s3_version.project_id, s3_version.version_name, s3_version.s3_path,
                          s3_version.created_by, s3_version.is_overwritten, s3_version.cleanup_after))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                    
        except Exception as e:
            logger.error(f"Error creating S3 version: {e}")
            return False
    
    def get_expired_s3_versions(self) -> List[S3Version]:
        """Get S3 versions that need cleanup."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT project_id, version_name, s3_path, created_by, created_at, 
                               is_overwritten, cleanup_after
                        FROM s3_versions 
                        WHERE cleanup_after <= %s
                        ORDER BY cleanup_after
                    """, (datetime.now(),))
                    
                    rows = cursor.fetchall()
                    versions = []
                    for row in rows:
                        version = S3Version(
                            project_id=row[0],
                            version_name=row[1],
                            s3_path=row[2],
                            created_by=row[3],
                            is_overwritten=row[5]
                        )
                        version.created_at = row[4]
                        version.cleanup_after = row[6]
                        versions.append(version)
                    
                    return versions
                    
        except Exception as e:
            logger.error(f"Error getting expired S3 versions: {e}")
            return []
    
    def delete_s3_version_record(self, project_id: int, version_name: str) -> bool:
        """Delete S3 version record after cleanup."""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        DELETE FROM s3_versions 
                        WHERE project_id = %s AND version_name = %s
                    """, (project_id, version_name))
                    
                    conn.commit()
                    return cursor.rowcount > 0
                    
        except Exception as e:
            logger.error(f"Error deleting S3 version record: {e}")
            return False


# Global database manager instance
db_manager = DatabaseManager()