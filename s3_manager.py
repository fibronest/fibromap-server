# s3_manager.py
"""
S3 credential management for FibroMAP Railway server.
Generates temporary AWS STS credentials for client access to S3 buckets.
"""

import os
import boto3
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
import logging

from database import db_manager
from models import User, Project, AuditLog

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class S3CredentialManager:
    """Manages AWS STS credential generation for FibroMAP S3 access."""
    
    def __init__(self):
        """Initialize S3 credential manager."""
        # Read environment variables
        self.data_bucket = os.getenv('S3_BUCKET', 'fibromapdata')  # Using S3_BUCKET as shown in your Railway env
        self.images_bucket = os.getenv('AWS_IMAGES_BUCKET', 'fibromap-images')
        self.aws_region = os.getenv('AWS_REGION', 'us-east-1')
        self.credential_duration_hours = int(os.getenv('CREDENTIAL_DURATION_HOURS', '12'))
        
        # Get AWS credentials - try multiple possible names
        self.aws_access_key = os.getenv('AWS_ACCESS_KEY_ID') or os.getenv('AWS_ACCESS_KEY')
        self.aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY') or os.getenv('AWS_SECRET_KEY')
        self.aws_role_arn = os.getenv('AWS_ROLE_ARN')
        self.aws_external_id = os.getenv('AWS_EXTERNAL_ID', 'fibromap-2024')
        
        # Debug logging
        logger.info(f"S3 Manager Initialization:")
        logger.info(f"  Data bucket: {self.data_bucket}")
        logger.info(f"  Region: {self.aws_region}")
        logger.info(f"  Access Key present: {bool(self.aws_access_key)}")
        logger.info(f"  Secret Key present: {bool(self.aws_secret_key)}")
        logger.info(f"  Role ARN: {self.aws_role_arn}")
        
        if not self.aws_access_key:
            logger.error("AWS_ACCESS_KEY_ID not found in environment!")
            logger.error(f"Available env vars: {list(os.environ.keys())}")
        
        if not self.aws_secret_key:
            logger.error("AWS_SECRET_ACCESS_KEY not found in environment!")
        
        # Initialize AWS clients
        self.sts_client = None
        self.s3_client = None
        
        if self.aws_access_key and self.aws_secret_key:
            try:
                if self.aws_role_arn:
                    # Create STS client for role assumption
                    self.sts_client = boto3.client(
                        'sts',
                        aws_access_key_id=self.aws_access_key,
                        aws_secret_access_key=self.aws_secret_key,
                        region_name=self.aws_region
                    )
                    logger.info("STS client created for role assumption")
                
                # Create S3 client for direct operations
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_secret_key,
                    region_name=self.aws_region
                )
                logger.info("S3 client created successfully")
                
            except Exception as e:
                logger.error(f"Failed to create AWS clients: {e}")
        else:
            logger.error("Cannot create AWS clients - missing credentials")

    def generate_user_credentials(self, user: User, user_projects: List[Project] = None, 
                                ip_address: str = None) -> Dict[str, Any]:
        """
        Generate temporary S3 credentials for a user.
        
        Args:
            user: User object
            user_projects: List of user's accessible projects (optional)
            ip_address: Client IP address for audit logging
            
        Returns:
            Dictionary containing data bucket credentials
        """
        try:
            # Generate data bucket credentials only (skip images for now)
            data_credentials = self._generate_data_bucket_credentials(user)
            
            # Log credential generation
            self._log_credential_generation(user.user_id, ip_address, success=True)
            
            result = {
                'data_bucket': data_credentials,
                'region': self.aws_region,
                'expires_at': (datetime.now() + timedelta(hours=self.credential_duration_hours)).isoformat()
            }
            
            # Skip images bucket for now
            # images_credentials = self._generate_images_bucket_credentials(user, user_projects)
            # if images_credentials:
            #     result['images_bucket'] = images_credentials
            
            return result
            
        except Exception as e:
            logger.error(f"Error generating user credentials: {e}")
            self._log_credential_generation(user.user_id, ip_address, success=False, 
                                        error=str(e))
            # Return basic credentials as fallback
            return {
                'data_bucket': {
                    'bucket_name': self.data_bucket,
                    'access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
                    'secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
                    'region': self.aws_region
                },
                'region': self.aws_region,
                'expires_at': (datetime.now() + timedelta(hours=12)).isoformat()
            }
        
    def _generate_data_bucket_credentials(self, user: User) -> Dict[str, Any]:
        """Generate temporary credentials for the data bucket."""
        try:
            # First, ensure we have the basic AWS credentials
            if not self.aws_access_key or not self.aws_secret_key:
                logger.error(f"No AWS credentials available for user {user.username}")
                logger.error(f"AWS_ACCESS_KEY_ID: {self.aws_access_key is not None}")
                logger.error(f"AWS_SECRET_ACCESS_KEY: {self.aws_secret_key is not None}")
                raise ValueError("AWS credentials not configured on server")
            
            # If we have a role ARN, try to use STS
            if self.aws_role_arn and self.sts_client:
                logger.info(f"Attempting to assume role {self.aws_role_arn} for user {user.username}")
                
                try:
                    # Create a policy that restricts access to the user's folder
                    user_policy = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:ListBucket"
                                ],
                                "Resource": f"arn:aws:s3:::{self.data_bucket}",
                                "Condition": {
                                    "StringLike": {
                                        "s3:prefix": [
                                            f"users/user_{user.user_id:03d}/*"
                                        ]
                                    }
                                }
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:GetObject",
                                    "s3:PutObject",
                                    "s3:DeleteObject"
                                ],
                                "Resource": f"arn:aws:s3:::{self.data_bucket}/users/user_{user.user_id:03d}/*"
                            }
                        ]
                    }
                    
                    response = self.sts_client.assume_role(
                        RoleArn=self.aws_role_arn,
                        RoleSessionName=f'fibromap-user-{user.user_id}-{user.username}',
                        ExternalId=self.aws_external_id,
                        DurationSeconds=3600 * self.credential_duration_hours,
                        Policy=json.dumps(user_policy)
                    )
                    
                    logger.info(f"Successfully assumed role for user {user.username}")
                    
                    return {
                        'bucket_name': self.data_bucket,
                        'access_key_id': response['Credentials']['AccessKeyId'],
                        'secret_access_key': response['Credentials']['SecretAccessKey'],
                        'session_token': response['Credentials']['SessionToken'],
                        'region': self.aws_region,
                        'user_prefix': f"users/user_{user.user_id:03d}"
                    }
                    
                except Exception as e:
                    logger.error(f"Failed to assume role: {e}")
                    logger.info("Falling back to direct credentials")
            
            # Fallback: Return direct credentials (less secure but works for testing)
            logger.info(f"Using direct credentials for user {user.username}")
            
            return {
                'bucket_name': self.data_bucket,
                'access_key_id': self.aws_access_key,
                'secret_access_key': self.aws_secret_key,
                'region': self.aws_region,
                'user_prefix': f"users/user_{user.user_id:03d}"
            }
            
        except Exception as e:
            logger.error(f"Error generating credentials: {e}")
            # Return empty credentials structure
            return {
                'bucket_name': self.data_bucket,
                'access_key_id': None,
                'secret_access_key': None,
                'region': self.aws_region,
                'error': str(e)
            }
      
    def _generate_images_bucket_credentials(self, user: User, projects: List[Project]) -> Optional[Dict[str, Any]]:
        """
        Generate temporary credentials for company images bucket access.
        
        Args:
            user: User object
            projects: List of user's accessible projects
            
        Returns:
            Dictionary with AWS credentials and bucket info, or None if no image access needed
        """
        # Find all unique image folders the user has access to
        image_folders = set()
        for project in projects:
            if project.s3_images_folder:
                image_folders.add(project.s3_images_folder)
        
        if not image_folders:
            return None
        
        # Create IAM policy for images access (read-only)
        policy_statements = []
        
        for folder in image_folders:
            policy_statements.append({
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    f"arn:aws:s3:::{self.images_bucket}/{folder}/*",
                    f"arn:aws:s3:::{self.images_bucket}"
                ],
                "Condition": {
                    "StringLike": {
                        "s3:prefix": [f"{folder}/*"]
                    }
                }
            })
        
        policy = {
            "Version": "2012-10-17",
            "Statement": policy_statements
        }
        
        # Generate session name
        session_name = f"fibromap-images-{user.user_id}-{int(datetime.now().timestamp())}"
        
        # Assume role with policy
        response = self.sts_client.assume_role_with_web_identity(
            RoleArn=os.getenv('AWS_IMAGES_ROLE_ARN'),
            RoleSessionName=session_name,
            Policy=json.dumps(policy),
            DurationSeconds=self.credential_duration_hours * 3600,
            WebIdentityToken=self._generate_web_identity_token(user)
        )
        
        credentials = response['Credentials']
        
        return {
            'bucket_name': self.images_bucket,
            'access_key_id': credentials['AccessKeyId'],
            'secret_access_key': credentials['SecretAccessKey'],
            'session_token': credentials['SessionToken'],
            'expiration': credentials['Expiration'].isoformat(),
            'accessible_folders': list(image_folders)
        }
    
    def _generate_web_identity_token(self, user: User) -> str:
        """
        Generate a web identity token for STS assume role.
        
        This is a simplified implementation. In production, you might use
        a more sophisticated JWT token with proper signing.
        
        Args:
            user: User object
            
        Returns:
            Web identity token string
        """
        import base64
        
        # Create a simple token with user info
        token_data = {
            'user_id': user.user_id,
            'username': user.username,
            'iat': int(datetime.now().timestamp()),
            'exp': int((datetime.now() + timedelta(hours=self.credential_duration_hours)).timestamp())
        }
        
        # In production, this should be a proper JWT token
        # For now, we'll use a simple base64 encoded JSON
        token_json = json.dumps(token_data)
        return base64.b64encode(token_json.encode()).decode()
    
    def refresh_credentials(self, user: User, ip_address: str = None) -> Dict[str, Any]:
        """
        Refresh S3 credentials for a user.
        
        Args:
            user: User object
            ip_address: Client IP address for audit logging
            
        Returns:
            New credentials dictionary
        """
        logger.info(f"Refreshing S3 credentials for user {user.username}")
        return self.generate_user_credentials(user, ip_address=ip_address)
    
    def validate_bucket_access(self, user: User, bucket_name: str, s3_path: str) -> bool:
        """
        Validate if user should have access to a specific S3 path.
        
        Args:
            user: User object
            bucket_name: S3 bucket name
            s3_path: S3 object path
            
        Returns:
            True if access should be allowed, False otherwise
        """
        try:
            if bucket_name == self.data_bucket:
                # Check data bucket access
                expected_prefix = f"users/user_{user.user_id:03d}/"
                return s3_path.startswith(expected_prefix)
            
            elif bucket_name == self.images_bucket:
                # Check images bucket access
                user_projects = db_manager.get_user_projects(user.user_id)
                accessible_folders = set()
                
                for project in user_projects:
                    if project.s3_images_folder:
                        accessible_folders.add(project.s3_images_folder)
                
                # Check if path matches any accessible folder
                for folder in accessible_folders:
                    if s3_path.startswith(f"{folder}/"):
                        return True
                
                return False
            
            else:
                # Unknown bucket
                return False
                
        except Exception as e:
            logger.error(f"Error validating bucket access: {e}")
            return False
    
    def get_project_s3_paths(self, user_id: int, project_id: int) -> Dict[str, str]:
        """
        Get S3 paths for a specific project.
        
        Args:
            user_id: User ID
            project_id: Project ID
            
        Returns:
            Dictionary with S3 paths for the project
        """
        base_path = f"users/user_{user_id:03d}/project_{project_id:03d}"
        
        return {
            'current_path': f"{base_path}/current",
            'versions_path': f"{base_path}/versions", 
            'thumbnails_path': f"{base_path}/thumbnails",
            'base_path': base_path
        }
    
    def create_version_backup_path(self, user_id: int, project_id: int, 
                                 timestamp: datetime, modified_by_username: str, 
                                 is_overwritten: bool = False) -> str:
        """
        Create S3 path for a version backup.
        
        Args:
            user_id: User ID
            project_id: Project ID
            timestamp: Backup timestamp
            modified_by_username: Username of who made the changes
            is_overwritten: Whether this is an overwritten version
            
        Returns:
            S3 path for the version backup
        """
        base_path = f"users/user_{user_id:03d}/project_{project_id:03d}/versions"
        
        # Format: 2025-01-15_10-30-00_userA or 2025-01-15_10-30-00_userA_overwritten
        timestamp_str = timestamp.strftime("%Y-%m-%d_%H-%M-%S")
        suffix = "_overwritten" if is_overwritten else ""
        
        return f"{base_path}/{timestamp_str}_{modified_by_username}{suffix}"
    
    def _log_credential_generation(self, user_id: int, ip_address: str = None, 
                                 success: bool = True, has_images_access: bool = False,
                                 error: str = None):
        """Log S3 credential generation for audit trail."""
        try:
            details = {
                'has_images_access': has_images_access,
                'credential_duration_hours': self.credential_duration_hours
            }
            
            if error:
                details['error'] = error
            
            audit_log = AuditLog(
                user_id=user_id,
                action="s3_credentials_generated",
                details=details,
                ip_address=ip_address,
                success=success
            )
            db_manager.log_action(audit_log)
        except Exception as e:
            logger.error(f"Error logging credential generation: {e}")


class S3PathHelper:
    """Helper class for S3 path operations."""
    
    @staticmethod
    def get_user_prefix(user_id: int) -> str:
        """Get S3 prefix for a user's data."""
        return f"users/user_{user_id:03d}"
    
    @staticmethod
    def get_project_prefix(user_id: int, project_id: int) -> str:
        """Get S3 prefix for a specific project."""
        return f"users/user_{user_id:03d}/project_{project_id:03d}"
    
    @staticmethod
    def get_current_data_prefix(user_id: int, project_id: int) -> str:
        """Get S3 prefix for current project data."""
        return f"users/user_{user_id:03d}/project_{project_id:03d}/current"
    
    @staticmethod
    def get_thumbnails_prefix(user_id: int, project_id: int) -> str:
        """Get S3 prefix for project thumbnails."""
        return f"users/user_{user_id:03d}/project_{project_id:03d}/thumbnails"
    
    @staticmethod
    def get_versions_prefix(user_id: int, project_id: int) -> str:
        """Get S3 prefix for project versions."""
        return f"users/user_{user_id:03d}/project_{project_id:03d}/versions"
    
    @staticmethod
    def parse_project_path(s3_path: str) -> Optional[Tuple[int, int]]:
        """
        Parse user_id and project_id from S3 path.
        
        Args:
            s3_path: S3 object path
            
        Returns:
            Tuple of (user_id, project_id) or None if invalid
        """
        try:
            # Expected format: users/user_001/project_002/...
            parts = s3_path.split('/')
            if len(parts) < 3 or parts[0] != 'users':
                return None
            
            user_part = parts[1]  # user_001
            project_part = parts[2]  # project_002
            
            if not user_part.startswith('user_') or not project_part.startswith('project_'):
                return None
            
            user_id = int(user_part[5:])  # Remove 'user_' prefix
            project_id = int(project_part[8:])  # Remove 'project_' prefix
            
            return user_id, project_id
            
        except (ValueError, IndexError):
            return None
    
    @staticmethod
    def is_valid_user_path(s3_path: str, user_id: int) -> bool:
        """Check if S3 path is valid for a specific user."""
        expected_prefix = f"users/user_{user_id:03d}/"
        return s3_path.startswith(expected_prefix)
    
    @staticmethod
    def is_current_data_path(s3_path: str) -> bool:
        """Check if S3 path is for current project data."""
        return '/current/' in s3_path
    
    @staticmethod
    def is_version_path(s3_path: str) -> bool:
        """Check if S3 path is for a version backup."""
        return '/versions/' in s3_path
    
    @staticmethod
    def is_thumbnail_path(s3_path: str) -> bool:
        """Check if S3 path is for thumbnails."""
        return '/thumbnails/' in s3_path


# Global S3 credential manager instance
s3_manager = S3CredentialManager()