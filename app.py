# app.py
"""
Main Flask application for FibroMAP Railway server.
Provides API endpoints for authentication, project management, and S3 access.
"""

import os
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from datetime import datetime, timedelta
from functools import wraps
import logging
from typing import Dict, Any, Optional

from auth import AuthenticationManager
from database import db_manager
from s3_manager import s3_manager, S3PathHelper
from models import User, Project, AuditLog, S3Version

auth_manager = AuthenticationManager(db_manager)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configure CORS (adjust origins for production)
CORS(app, origins=os.getenv('ALLOWED_ORIGINS', '*').split(','))

# App configuration
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['JSON_SORT_KEYS'] = False


def get_client_ip():
    """Get client IP address from request."""
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']


def require_auth(f):
    """Decorator to require authentication for endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid authorization header'}), 401
        
        token = auth_header.split(' ')[1]
        user = auth_manager.validate_session(token, get_client_ip())
        
        if not user:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        g.current_user = user
        return f(*args, **kwargs)
    
    return decorated_function


def require_admin(f):
    """Decorator to require admin role for endpoints."""
    @wraps(f)
    @require_auth
    def decorated_function(*args, **kwargs):
        if g.current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Railway."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })


# Authentication endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        remember_me = data.get('remember_me', False)
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Authenticate user
        success, message, user = auth_manager.authenticate_user(
            username, password, get_client_ip()
        )
        
        if not success:
            return jsonify({'error': message}), 401
        
        # Create session
        session_token = auth_manager.create_session(
            user, remember_me, get_client_ip(), request.headers.get('User-Agent')
        )
        
        if not session_token:
            return jsonify({'error': 'Failed to create session'}), 500
        
        # Generate S3 credentials
        try:
            s3_credentials = s3_manager.generate_user_credentials(user, ip_address=get_client_ip())
        except Exception as e:
            logger.error(f"Failed to generate S3 credentials: {e}")
            s3_credentials = None
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'session_token': session_token,
            's3_credentials': s3_credentials
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Authentication system error'}), 500


@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not all([username, email, password]):
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        # Register user
        success, message, user = auth_manager.register_user(
            username, email, password, get_client_ip()
        )
        
        if not success:
            return jsonify({'error': message}), 400
        
        return jsonify({
            'message': 'Registration successful',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration system error'}), 500


@app.route('/api/auth/refresh', methods=['POST'])
@require_auth
def refresh_credentials():
    """Refresh S3 credentials for authenticated user."""
    try:
        # Generate new S3 credentials
        s3_credentials = s3_manager.refresh_credentials(g.current_user, get_client_ip())
        
        return jsonify({
            'message': 'Credentials refreshed',
            's3_credentials': s3_credentials
        })
        
    except Exception as e:
        logger.error(f"Credential refresh error: {e}")
        return jsonify({'error': 'Failed to refresh credentials'}), 500


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """User logout endpoint."""
    try:
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            auth_manager.invalidate_session(token, g.current_user.user_id, get_client_ip())
        
        return jsonify({'message': 'Logout successful'})
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Logout system error'}), 500


# Project endpoints
@app.route('/api/projects', methods=['GET'])
@require_auth
def get_projects():
    """Get all projects accessible to the user."""
    try:
        projects = db_manager.get_user_projects(g.current_user.user_id)
        
        return jsonify({
            'projects': [project.to_dict() for project in projects]
        })
        
    except Exception as e:
        logger.error(f"Get projects error: {e}")
        return jsonify({'error': 'Failed to retrieve projects'}), 500


@app.route('/api/projects', methods=['POST'])
@require_auth
def create_project():
    """Create a new project."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        project_name = data.get('project_name', '').strip()
        description = data.get('description', '').strip()
        s3_images_folder = data.get('s3_images_folder')
        
        if not project_name:
            return jsonify({'error': 'Project name is required'}), 400
        
        # Generate S3 data path
        s3_data_path = S3PathHelper.get_project_prefix(g.current_user.user_id, 0)  # Will be updated with real project ID
        
        # Create project
        project = Project(
            project_id=0,  # Will be set by database
            project_name=project_name,
            description=description,
            owner_id=g.current_user.user_id,
            s3_data_path=s3_data_path,
            s3_images_folder=s3_images_folder
        )
        
        created_project = db_manager.create_project(project)
        
        if not created_project:
            return jsonify({'error': 'Failed to create project'}), 500
        
        # Update S3 data path with real project ID
        real_s3_path = S3PathHelper.get_project_prefix(g.current_user.user_id, created_project.project_id)
        
        # Update the s3_data_path in the database with the real project ID
        db_manager.update_project_s3_path(created_project.project_id, real_s3_path)
        created_project.s3_data_path = real_s3_path
        
        # Log project creation
        audit_log = AuditLog(
            user_id=g.current_user.user_id,
            action="project_created",
            project_id=created_project.project_id,
            details={'project_name': project_name},
            ip_address=get_client_ip()
        )
        db_manager.log_action(audit_log)
        
        return jsonify({
            'message': 'Project created successfully',
            'project': created_project.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Create project error: {e}")
        return jsonify({'error': 'Failed to create project'}), 500

@app.route('/api/projects/<int:project_id>', methods=['DELETE'])
@require_auth
def delete_project(project_id):
    """Delete a project (owner or admin only)."""
    try:
        user = g.current_user
        
        # Get project using existing method
        project = db_manager.get_project(project_id)  # Use existing method
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        
        # Check if user can delete (owner or admin)
        if user.role != 'admin' and project.owner_id != user.user_id:
            return jsonify({'error': 'Unauthorized to delete this project'}), 403
        
        # Delete the project and all associated permissions
        success = db_manager.delete_project(project_id)
        
        if success:
            # Log the deletion
            db_manager.create_audit_log(
                user_id=user.user_id,
                action='delete_project',
                project_id=project_id,
                details=f'Deleted project: {project.project_name}',
                ip_address=get_client_ip()
            )
            
            return jsonify({
                'message': 'Project deleted successfully',
                'project_id': project_id
            })
        else:
            return jsonify({'error': 'Failed to delete project'}), 500
            
    except Exception as e:
        logger.error(f"Delete project error: {e}")
        return jsonify({'error': 'Failed to delete project'}), 500
    
@app.route('/api/projects/<int:project_id>', methods=['GET'])
@require_auth
def get_project(project_id):
    """Get specific project details."""
    try:
        project = db_manager.get_project(project_id)
        
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        
        # Check if user has access to this project
        permission = db_manager.get_user_project_permission(project_id, g.current_user.user_id)
        if not permission and project.owner_id != g.current_user.user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        return jsonify({
            'project': project.to_dict(),
            'permission_level': permission or 'admin'  # Owner gets admin
        })
        
    except Exception as e:
        logger.error(f"Get project error: {e}")
        return jsonify({'error': 'Failed to retrieve project'}), 500

# Admin endpoints
@app.route('/api/admin/users', methods=['GET'])
@require_admin
def get_all_users():
    """Get all users (admin only)."""
    try:
        users = db_manager.get_all_users()
        return jsonify({
            'users': [user.to_dict() for user in users]
        })
    except Exception as e:
        logger.error(f"Get users error: {e}")
        return jsonify({'error': 'Failed to retrieve users'}), 500


@app.route('/api/admin/users', methods=['POST'])
@require_admin
def admin_create_user():
    """Create new user (admin only)."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        role = data.get('role', 'user')
        
        if not all([username, email, password]):
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        # Create user without role parameter (register_user doesn't accept it)
        success, message, user = auth_manager.register_user(
            username, email, password, get_client_ip()
        )
        
        if not success:
            return jsonify({'error': message}), 400
        
        # If admin role requested, update it after creation
        if success and role == 'admin':
            try:
                with db_manager.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE users SET role = %s WHERE user_id = %s
                    """, ('admin', user.user_id))
                    conn.commit()
                    user.role = 'admin'
                    logger.info(f"Updated user {username} to admin role")
            except Exception as e:
                logger.error(f"Failed to update user role: {e}")
                # User was created but role update failed
                return jsonify({
                    'message': 'User created but role update failed',
                    'user': user.to_dict()
                }), 201
        
        return jsonify({
            'message': 'User created successfully',
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        logger.error(f"Create user error: {e}")
        return jsonify({'error': f'Failed to create user: {str(e)}'}), 500

@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@require_admin
def reset_user_password(user_id):
    """Reset user password (admin only)."""
    try:
        data = request.get_json()
        new_password = data.get('new_password', '')
        
        if not new_password:
            return jsonify({'error': 'New password is required'}), 400
        
        success, message = auth_manager.admin_reset_password(user_id, new_password, g.current_user.user_id)
        
        if not success:
            return jsonify({'error': message}), 400
        
        return jsonify({'message': 'Password reset successfully'})
        
    except Exception as e:
        logger.error(f"Reset password error: {e}")
        return jsonify({'error': 'Failed to reset password'}), 500


@app.route('/api/admin/users/<int:user_id>/status', methods=['PUT'])
@require_admin
def toggle_user_status(user_id):
    """Toggle user active status (admin only)."""
    try:
        data = request.get_json()
        is_active = data.get('is_active', True)
        
        success, message = db_manager.update_user_status(user_id, is_active)
        
        if not success:
            return jsonify({'error': message}), 400
        
        return jsonify({'message': 'User status updated successfully'})
        
    except Exception as e:
        logger.error(f"Toggle user status error: {e}")
        return jsonify({'error': 'Failed to update user status'}), 500

@app.route('/api/admin/projects/<int:project_id>/permissions', methods=['GET'])
@require_auth
@require_admin
def get_project_permissions(project_id):
    """Get all permissions for a project (admin only)."""
    try:
        permissions = db_manager.get_project_permissions(project_id)
        
        if permissions is None:
            return jsonify({'error': 'Project not found'}), 404
        
        return jsonify({
            'permissions': permissions,
            'project_id': project_id
        })
        
    except Exception as e:
        logger.error(f"Failed to get project permissions: {e}")
        return jsonify({'error': 'Failed to retrieve permissions'}), 500


@app.route('/api/admin/projects/<int:project_id>/permissions', methods=['POST'])
@require_auth
@require_admin
def grant_project_permission(project_id):
    """Grant permission to a user for a project (admin only)."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        user_id = data.get('user_id')
        permission_level = data.get('permission_level')
        
        if not user_id or not permission_level:
            return jsonify({'error': 'user_id and permission_level are required'}), 400
        
        # Validate permission level
        valid_levels = ['read', 'write', 'owner']
        if permission_level not in valid_levels:
            return jsonify({'error': f'Invalid permission level. Must be one of: {valid_levels}'}), 400
        
        # Get current user (admin) from g instead of auth_manager
        current_user = g.current_user  # Changed from auth_manager.current_user
        if not current_user:
            return jsonify({'error': 'Could not identify current user'}), 401
        
        # Grant permission
        success = db_manager.grant_project_permission(
            project_id, user_id, permission_level, current_user.user_id
        )
        
        if success:
            # Log the action
            db_manager.create_audit_log(
                user_id=current_user.user_id,
                action='grant_permission',
                project_id=project_id,
                details=f'Granted {permission_level} permission to user {user_id}'
            )
            
            return jsonify({
                'message': f'Successfully granted {permission_level} permission',
                'project_id': project_id,
                'user_id': user_id,
                'permission_level': permission_level
            })
        else:
            return jsonify({'error': 'Failed to grant permission'}), 500
            
    except Exception as e:
        logger.error(f"Failed to grant permission: {e}")
        return jsonify({'error': 'Failed to grant permission'}), 500
    

@app.route('/api/admin/projects/<int:project_id>/permissions/<int:user_id>', methods=['PUT'])
@require_auth
@require_admin
def modify_project_permission(project_id, user_id):
    """Modify a user's permission for a project (admin only)."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        permission_level = data.get('permission_level')
        
        if not permission_level:
            return jsonify({'error': 'permission_level is required'}), 400
        
        # Validate permission level
        valid_levels = ['read', 'write', 'owner']
        if permission_level not in valid_levels:
            return jsonify({'error': f'Invalid permission level. Must be one of: {valid_levels}'}), 400
        
        # Get current user (admin) - CHANGED FROM auth_manager.current_user
        current_user = g.current_user
        if not current_user:
            return jsonify({'error': 'Could not identify current user'}), 401
        
        # Modify permission
        success = db_manager.modify_project_permission(
            project_id, user_id, permission_level, current_user.user_id
        )
        
        if success:
            # Log the action
            db_manager.create_audit_log(
                user_id=current_user.user_id,
                action='modify_permission',
                project_id=project_id,
                details=f'Modified permission for user {user_id} to {permission_level}'
            )
            
            return jsonify({
                'message': f'Successfully modified permission to {permission_level}',
                'project_id': project_id,
                'user_id': user_id,
                'permission_level': permission_level
            })
        else:
            return jsonify({'error': 'Failed to modify permission'}), 500
            
    except Exception as e:
        logger.error(f"Failed to modify permission: {e}")
        return jsonify({'error': 'Failed to modify permission'}), 500


@app.route('/api/admin/projects/<int:project_id>/permissions/<int:user_id>', methods=['DELETE'])
@require_auth
@require_admin
def revoke_project_permission(project_id, user_id):
    """Revoke a user's permission for a project (admin only)."""
    try:
        # Get current user (admin) - CHANGED FROM auth_manager.current_user
        current_user = g.current_user
        if not current_user:
            return jsonify({'error': 'Could not identify current user'}), 401
        
        # Revoke permission
        success = db_manager.revoke_project_permission(project_id, user_id)
        
        if success:
            # Log the action
            db_manager.create_audit_log(
                user_id=current_user.user_id,
                action='revoke_permission',
                project_id=project_id,
                details=f'Revoked permission for user {user_id}'
            )
            
            return jsonify({
                'message': 'Successfully revoked permission',
                'project_id': project_id,
                'user_id': user_id
            })
        else:
            return jsonify({'error': 'Failed to revoke permission'}), 500
            
    except Exception as e:
        logger.error(f"Failed to revoke permission: {e}")
        return jsonify({'error': 'Failed to revoke permission'}), 500
    
@app.route('/api/admin/projects', methods=['GET'])
@require_admin
def get_all_projects():
    """Get all projects (admin only)."""
    try:
        projects = db_manager.get_all_projects()
        return jsonify({
            'projects': [project.to_dict() for project in projects]
        })
    except Exception as e:
        logger.error(f"Get all projects error: {e}")
        return jsonify({'error': 'Failed to retrieve projects'}), 500


@app.route('/api/admin/audit-logs', methods=['GET'])
@require_admin
def get_audit_logs():
    """Get audit logs (admin only)."""
    try:
        limit = request.args.get('limit', 500, type=int)
        logs = db_manager.get_audit_logs(limit=limit)
        return jsonify({
            'logs': [log.to_dict() for log in logs]
        })
    except Exception as e:
        logger.error(f"Get audit logs error: {e}")
        return jsonify({'error': 'Failed to retrieve audit logs'}), 500

@app.route('/api/projects/<int:project_id>/check-version', methods=['POST'])
@require_auth
def check_project_version(project_id):
    """Check if project version matches for conflict detection."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        last_known_version = data.get('last_known_version')
        
        if not last_known_version:
            return jsonify({'error': 'last_known_version is required'}), 400
        
        # Get current project
        project = db_manager.get_project(project_id)
        
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        
        # Check user access
        permission = db_manager.get_user_project_permission(project_id, g.current_user.user_id)
        if not permission and project.owner_id != g.current_user.user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Check for write permission
        if permission == 'read':
            return jsonify({'error': 'Write access required'}), 403
        
        # Parse timestamps for comparison
        try:
            last_known_dt = datetime.fromisoformat(last_known_version.replace('Z', '+00:00'))
            current_dt = project.updated_at
            
            if current_dt <= last_known_dt:
                # No conflict - OK to update
                return jsonify({
                    'status': 'ok_to_update',
                    'current_version': project.updated_at.isoformat(),
                    'last_modified_by': project.last_modified_by
                })
            else:
                # Conflict detected
                last_modifier = db_manager.get_user_by_id(project.last_modified_by)
                conflict_id = f"conflict_{project_id}_{int(datetime.now().timestamp())}"
                
                return jsonify({
                    'status': 'conflict',
                    'current_version': project.updated_at.isoformat(),
                    'last_modified_by': last_modifier.username if last_modifier else 'Unknown',
                    'your_base_version': last_known_version,
                    'conflict_id': conflict_id
                })
                
        except ValueError as e:
            return jsonify({'error': 'Invalid timestamp format'}), 400
        
    except Exception as e:
        logger.error(f"Check version error: {e}")
        return jsonify({'error': 'Failed to check project version'}), 500


@app.route('/api/projects/<int:project_id>/confirm-save', methods=['POST'])
@require_auth
def confirm_project_save(project_id):
    """Confirm project save after S3 upload."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        updated_at_str = data.get('updated_at')
        version_created = data.get('version_created')
        
        if not updated_at_str:
            return jsonify({'error': 'updated_at is required'}), 400
        
        # Parse timestamp
        try:
            updated_at = datetime.fromisoformat(updated_at_str.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({'error': 'Invalid timestamp format'}), 400
        
        # Update project in database
        success = db_manager.update_project(project_id, updated_at, g.current_user.user_id)
        
        if not success:
            return jsonify({'error': 'Failed to update project'}), 500
        
        # Create version record if provided
        if version_created:
            project = db_manager.get_project(project_id)
            if project:
                version_path = f"{project.s3_data_path}/versions/{version_created}"
                s3_version = S3Version(
                    project_id=project_id,
                    version_name=version_created,
                    s3_path=version_path,
                    created_by=g.current_user.user_id
                )
                db_manager.create_s3_version(s3_version)
        
        # Log save action
        audit_log = AuditLog(
            user_id=g.current_user.user_id,
            action="project_saved",
            project_id=project_id,
            details={'version_created': version_created},
            ip_address=get_client_ip()
        )
        db_manager.log_action(audit_log)
        
        return jsonify({'message': 'Project save confirmed'})
        
    except Exception as e:
        logger.error(f"Confirm save error: {e}")
        return jsonify({'error': 'Failed to confirm project save'}), 500


@app.route('/api/projects/<int:project_id>/resolve-conflict', methods=['POST'])
@require_auth
def resolve_conflict(project_id):
    """Resolve a sync conflict."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        conflict_id = data.get('conflict_id')
        resolution = data.get('resolution')  # 'overwrite' or 'discarded'
        
        if not all([conflict_id, resolution]):
            return jsonify({'error': 'conflict_id and resolution are required'}), 400
        
        if resolution not in ['overwrite', 'discarded']:
            return jsonify({'error': 'Invalid resolution type'}), 400
        
        details = {
            'conflict_id': conflict_id,
            'resolution': resolution
        }
        
        if resolution == 'overwrite':
            overwritten_version = data.get('overwritten_version')
            new_version_timestamp = data.get('new_version_timestamp')
            
            if overwritten_version:
                details['overwritten_version'] = overwritten_version
                
                # Create overwritten version record
                project = db_manager.get_project(project_id)
                if project:
                    version_path = f"{project.s3_data_path}/versions/{overwritten_version}"
                    s3_version = S3Version(
                        project_id=project_id,
                        version_name=overwritten_version,
                        s3_path=version_path,
                        created_by=g.current_user.user_id,
                        is_overwritten=True
                    )
                    db_manager.create_s3_version(s3_version)
            
            if new_version_timestamp:
                updated_at = datetime.fromisoformat(new_version_timestamp.replace('Z', '+00:00'))
                db_manager.update_project(project_id, updated_at, g.current_user.user_id)
        
        # Log conflict resolution
        audit_log = AuditLog(
            user_id=g.current_user.user_id,
            action=f"conflict_resolved_{resolution}",
            project_id=project_id,
            details=details,
            ip_address=get_client_ip()
        )
        db_manager.log_action(audit_log)
        
        return jsonify({'message': 'Conflict resolved successfully'})
        
    except Exception as e:
        logger.error(f"Resolve conflict error: {e}")
        return jsonify({'error': 'Failed to resolve conflict'}), 500


@app.route('/api/projects/<int:project_id>/version-summary', methods=['GET'])
@require_auth
def get_version_summary(project_id):
    """Get version summary for conflict dialog."""
    try:
        since = request.args.get('since')
        
        if not since:
            return jsonify({'error': 'since parameter is required'}), 400
        
        # Get project
        project = db_manager.get_project(project_id)
        
        if not project:
            return jsonify({'error': 'Project not found'}), 404
        
        # Check user access
        permission = db_manager.get_user_project_permission(project_id, g.current_user.user_id)
        if not permission and project.owner_id != g.current_user.user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get last modifier info
        last_modifier = db_manager.get_user_by_id(project.last_modified_by) if project.last_modified_by else None
        
        # This is a simplified version - in practice, you might want to 
        # analyze actual file changes to provide more detailed summaries
        return jsonify({
            'current_version': {
                'timestamp': project.updated_at.isoformat(),
                'modified_by': last_modifier.username if last_modifier else 'Unknown',
                'files_changed': ['fiber_data.parquet', 'texture_data.parquet'],  # Placeholder
                'summary': 'Project data updated'  # Placeholder
            },
            'your_changes': {
                'files_changed': ['fiber_data.parquet'],  # Would come from conflict context
                'summary': 'Local changes pending'  # Placeholder
            }
        })
        
    except Exception as e:
        logger.error(f"Get version summary error: {e}")
        return jsonify({'error': 'Failed to get version summary'}), 500


# Admin endpoints
@app.route('/api/admin/projects/<int:project_id>/assign-images', methods=['PUT'])
@require_admin
def assign_project_images(project_id):
    """Admin endpoint to assign company images to a project."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'JSON data required'}), 400
        
        s3_images_folder = data.get('s3_images_folder')
        
        if not s3_images_folder:
            return jsonify({'error': 's3_images_folder is required'}), 400
        
        # Update project
        success = db_manager.assign_project_images(project_id, s3_images_folder, g.current_user.user_id)
        
        if not success:
            return jsonify({'error': 'Failed to assign images or project not found'}), 404
        
        # Log admin action
        audit_log = AuditLog(
            user_id=g.current_user.user_id,
            action="admin_assign_images",
            project_id=project_id,
            details={'s3_images_folder': s3_images_folder},
            ip_address=get_client_ip()
        )
        db_manager.log_action(audit_log)
        
        return jsonify({'message': 'Images assigned successfully'})
        
    except Exception as e:
        logger.error(f"Assign images error: {e}")
        return jsonify({'error': 'Failed to assign images'}), 500


# Cleanup endpoint (for scheduled jobs)
@app.route('/api/internal/cleanup', methods=['POST'])
def cleanup_expired_data():
    """Internal endpoint for cleanup jobs (should be secured in production)."""
    try:
        # Check for internal auth token
        internal_token = request.headers.get('X-Internal-Token')
        expected_token = os.getenv('INTERNAL_CLEANUP_TOKEN')
        
        if not expected_token or internal_token != expected_token:
            return jsonify({'error': 'Unauthorized'}), 401
        
        # Cleanup expired sessions
        sessions_cleaned = auth_manager.cleanup_expired_sessions()
        
        # Get expired S3 versions for cleanup
        expired_versions = db_manager.get_expired_s3_versions()
        
        return jsonify({
            'message': 'Cleanup completed',
            'sessions_cleaned': sessions_cleaned,
            'versions_to_cleanup': len(expired_versions),
            'expired_versions': [v.to_dict() for v in expired_versions]
        })
        
    except Exception as e:
        logger.error(f"Cleanup error: {e}")
        return jsonify({'error': 'Cleanup failed'}), 500


# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# Debug endpoint (TEMPORARY - REMOVE IN PRODUCTION)
@app.route('/api/debug/env', methods=['GET'])
def debug_environment():
    """Debug endpoint to check environment variables."""
    import sys
    
    # Check for a simple auth to prevent public access
    auth_header = request.headers.get('X-Debug-Token')
    if auth_header != 'debug-fibromap-2024':
        return jsonify({'error': 'Unauthorized'}), 401
    
    env_vars = {
        'AWS_ACCESS_KEY_ID': os.getenv('AWS_ACCESS_KEY_ID'),
        'AWS_SECRET_ACCESS_KEY': '***hidden***' if os.getenv('AWS_SECRET_ACCESS_KEY') else None,
        'AWS_REGION': os.getenv('AWS_REGION'),
        'AWS_DEFAULT_REGION': os.getenv('AWS_DEFAULT_REGION'),
        'AWS_ROLE_ARN': os.getenv('AWS_ROLE_ARN'),
        'AWS_EXTERNAL_ID': os.getenv('AWS_EXTERNAL_ID'),
        'S3_BUCKET': os.getenv('S3_BUCKET'),
        'AWS_DATA_BUCKET': os.getenv('AWS_DATA_BUCKET'),
        'DATABASE_URL': '***hidden***' if os.getenv('DATABASE_URL') else None,
        
        # Check all environment variables (names only)
        'all_env_vars': list(os.environ.keys())
    }
    
    return jsonify({
        'message': 'Environment variables check',
        'env_vars': env_vars,
        'python_version': sys.version,
        'current_time': datetime.now().isoformat()
    })

@app.errorhandler(Exception)
def handle_exception(e):
    """Handle unhandled exceptions."""
    logger.error(f"Unhandled exception: {e}")
    return jsonify({'error': 'An unexpected error occurred'}), 500


if __name__ == '__main__':
    # Development server
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    
    logger.info(f"Starting FibroMAP server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)