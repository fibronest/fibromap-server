# models.py
"""
Database schema definitions for FibroMAP Railway server.
Defines PostgreSQL table structures and relationships.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

class DatabaseSchema:
    """Contains all SQL schema definitions for the FibroMAP database."""
    
    @staticmethod
    def get_create_tables_sql() -> List[str]:
        """
        Get list of SQL statements to create all required tables.
        
        Returns:
            List of SQL CREATE TABLE statements
        """
        return [
            DatabaseSchema.create_users_table(),
            DatabaseSchema.create_sessions_table(),
            DatabaseSchema.create_projects_table(),
            DatabaseSchema.create_project_permissions_table(),
            DatabaseSchema.create_audit_log_table(),
            DatabaseSchema.create_s3_versions_table()
        ]
    
    @staticmethod
    def get_create_indexes_sql() -> List[str]:
        """
        Get list of SQL statements to create all indexes.
        
        Returns:
            List of SQL CREATE INDEX statements
        """
        return [
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id)",
            "CREATE INDEX IF NOT EXISTS idx_projects_updated ON projects(updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_permissions_project ON project_permissions(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_permissions_user ON project_permissions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_s3_versions_project ON s3_versions(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_s3_versions_created ON s3_versions(created_at)"
        ]
    
    @staticmethod
    def create_users_table() -> str:
        """Create users table for authentication."""
        return """
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin')),
            is_active BOOLEAN DEFAULT true,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    
    @staticmethod
    def create_sessions_table() -> str:
        """Create sessions table for user sessions."""
        return """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id VARCHAR(64) PRIMARY KEY,
            user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
            token_hash VARCHAR(255) NOT NULL,
            ip_address INET,
            user_agent TEXT,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_remember_me BOOLEAN DEFAULT false
        )
        """
    
    @staticmethod
    def create_projects_table() -> str:
        """Create projects table for project metadata."""
        return """
        CREATE TABLE IF NOT EXISTS projects (
            project_id SERIAL PRIMARY KEY,
            project_name VARCHAR(100) NOT NULL,
            description TEXT,
            owner_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
            s3_data_path VARCHAR(500) NOT NULL,
            s3_images_folder VARCHAR(200),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_modified_by INTEGER REFERENCES users(user_id),
            version_count INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT true
        )
        """
    
    @staticmethod
    def create_project_permissions_table() -> str:
        """Create project permissions table for access control."""
        return """
        CREATE TABLE IF NOT EXISTS project_permissions (
            permission_id SERIAL PRIMARY KEY,
            project_id INTEGER REFERENCES projects(project_id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
            permission_level VARCHAR(20) DEFAULT 'read' CHECK (permission_level IN ('read', 'write', 'admin')),
            granted_by INTEGER REFERENCES users(user_id),
            granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(project_id, user_id)
        )
        """
    
    @staticmethod
    def create_audit_log_table() -> str:
        """Create audit log table for tracking actions."""
        return """
        CREATE TABLE IF NOT EXISTS audit_log (
            log_id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(user_id),
            action VARCHAR(100) NOT NULL,
            project_id INTEGER REFERENCES projects(project_id),
            details JSONB,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address INET,
            success BOOLEAN DEFAULT true
        )
        """
    
    @staticmethod
    def create_s3_versions_table() -> str:
        """Create S3 versions table for tracking version backups."""
        return """
        CREATE TABLE IF NOT EXISTS s3_versions (
            version_id SERIAL PRIMARY KEY,
            project_id INTEGER REFERENCES projects(project_id) ON DELETE CASCADE,
            version_name VARCHAR(100) NOT NULL,
            s3_path VARCHAR(500) NOT NULL,
            created_by INTEGER REFERENCES users(user_id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_overwritten BOOLEAN DEFAULT false,
            cleanup_after TIMESTAMP
        )
        """


class User:
    """User model for handling user data."""
    
    def __init__(self, user_id: int, username: str, email: str, password_hash: str = None,
                 role: str = 'user', is_active: bool = True, created_at: datetime = None, 
                 last_login: datetime = None, failed_attempts: int = 0, locked_until: datetime = None):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.is_active = is_active
        self.created_at = created_at or datetime.now()
        self.last_login = last_login
        self.failed_attempts = failed_attempts
        self.locked_until = locked_until
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary for JSON serialization."""
        return {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'failed_attempts': self.failed_attempts,
            'locked_until': self.locked_until.isoformat() if self.locked_until else None
        }
    
    @classmethod
    def from_db_row(cls, row: tuple) -> 'User':
        """Create User instance from database row."""
        return cls(
            user_id=row[0],
            username=row[1],
            email=row[2],
            password_hash=row[3],  # This was missing!
            role=row[4],
            is_active=row[5],
            created_at=row[6],
            last_login=row[7],
            failed_attempts=row[8] if len(row) > 8 else 0,
            locked_until=row[9] if len(row) > 9 else None
        )


class Project:
    """Project model for handling project data."""
    
    def __init__(self, project_id: int, project_name: str, owner_id: int, 
                 s3_data_path: str, description: str = None, s3_images_folder: str = None,
                 created_at: datetime = None, updated_at: datetime = None,
                 last_modified_by: int = None, version_count: int = 0):
        self.project_id = project_id
        self.project_name = project_name
        self.description = description
        self.owner_id = owner_id
        self.s3_data_path = s3_data_path
        self.s3_images_folder = s3_images_folder
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()
        self.last_modified_by = last_modified_by
        self.version_count = version_count
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert project to dictionary for JSON serialization."""
        return {
            'project_id': self.project_id,
            'project_name': self.project_name,
            'description': self.description,
            'owner_id': self.owner_id,
            's3_data_path': self.s3_data_path,
            's3_images_folder': self.s3_images_folder,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_modified_by': self.last_modified_by,
            'version_count': self.version_count
        }
    
    @classmethod
    def from_db_row(cls, row: tuple) -> 'Project':
        """Create Project instance from database row."""
        return cls(
            project_id=row[0],
            project_name=row[1],
            description=row[2],
            owner_id=row[3],
            s3_data_path=row[4],
            s3_images_folder=row[5],
            created_at=row[6],
            updated_at=row[7],
            last_modified_by=row[8],
            version_count=row[9]
        )


class Session:
    """Session model for handling user sessions."""
    
    def __init__(self, session_id: str, user_id: int, token_hash: str,
                 expires_at: datetime, ip_address: str = None, user_agent: str = None,
                 is_remember_me: bool = False, created_at: datetime = None):
        self.session_id = session_id
        self.user_id = user_id
        self.token_hash = token_hash
        self.expires_at = expires_at
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.is_remember_me = is_remember_me
        self.created_at = created_at or datetime.now()
    
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.now() > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for JSON serialization."""
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'expires_at': self.expires_at.isoformat(),
            'ip_address': self.ip_address,
            'is_remember_me': self.is_remember_me,
            'created_at': self.created_at.isoformat()
        }


class ProjectPermission:
    """Project permission model for access control."""
    
    def __init__(self, permission_id: int, project_id: int, user_id: int,
                 permission_level: str, granted_by: int = None, granted_at: datetime = None):
        self.permission_id = permission_id
        self.project_id = project_id
        self.user_id = user_id
        self.permission_level = permission_level
        self.granted_by = granted_by
        self.granted_at = granted_at or datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert permission to dictionary for JSON serialization."""
        return {
            'permission_id': self.permission_id,
            'project_id': self.project_id,
            'user_id': self.user_id,
            'permission_level': self.permission_level,
            'granted_by': self.granted_by,
            'granted_at': self.granted_at.isoformat() if self.granted_at else None
        }


class AuditLog:
    """Audit log model for tracking actions."""
    
    def __init__(self, user_id: int, action: str, project_id: int = None,
                 details: Dict[str, Any] = None, ip_address: str = None, success: bool = True):
        self.user_id = user_id
        self.action = action
        self.project_id = project_id
        self.details = details or {}
        self.ip_address = ip_address
        self.success = success
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit log to dictionary for JSON serialization."""
        return {
            'user_id': self.user_id,
            'action': self.action,
            'project_id': self.project_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'success': self.success,
            'timestamp': self.timestamp.isoformat()
        }


class S3Version:
    """S3 version model for tracking version backups."""
    
    def __init__(self, project_id: int, version_name: str, s3_path: str,
                 created_by: int, is_overwritten: bool = False, cleanup_after: datetime = None):
        self.project_id = project_id
        self.version_name = version_name
        self.s3_path = s3_path
        self.created_by = created_by
        self.created_at = datetime.now()
        self.is_overwritten = is_overwritten
        self.cleanup_after = cleanup_after or (datetime.now() + timedelta(hours=48))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert S3 version to dictionary for JSON serialization."""
        return {
            'project_id': self.project_id,
            'version_name': self.version_name,
            's3_path': self.s3_path,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'is_overwritten': self.is_overwritten,
            'cleanup_after': self.cleanup_after.isoformat() if self.cleanup_after else None
        }