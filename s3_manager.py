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
        import os
        
        # Debug: Print all environment variables
        print("="*60)
        print("S3Manager Initialization - Environment Check")
        print("="*60)
        
        # Check for AWS variables
        aws_vars = {k: v for k, v in os.environ.items() if 'AWS' in k or 'S3' in k or 'BUCKET' in k}
        print(f"Found {len(aws_vars)} AWS/S3 related variables:")
        for key in sorted(aws_vars.keys()):
            if 'SECRET' in key:
                print(f"  {key}: ***hidden***")
            else:
                print(f"  {key}: {aws_vars[key][:20]}..." if len(aws_vars[key]) > 20 else f"  {key}: {aws_vars[key]}")
        
        # Try to read the variables
        self.data_bucket = os.getenv('S3_BUCKET', 'fibromapdata')
        self.images_bucket = os.getenv('AWS_IMAGES_BUCKET', 'fibromap-images')
        self.aws_region = os.getenv('AWS_REGION', 'us-east-1')
        self.credential_duration_hours = int(os.getenv('CREDENTIAL_DURATION_HOURS', '1'))
        
        # Try multiple possible names for AWS credentials
        self.aws_access_key = (
            os.getenv('AWS_ACCESS_KEY_ID') or 
            os.getenv('AWS_ACCESS_KEY') or
            os.getenv('ACCESS_KEY_ID') or
            os.getenv('ACCESS_KEY')
        )
        
        self.aws_secret_key = (
            os.getenv('AWS_SECRET_ACCESS_KEY') or
            os.getenv('AWS_SECRET_KEY') or
            os.getenv('SECRET_ACCESS_KEY') or
            os.getenv('SECRET_KEY')
        )
        
        self.aws_role_arn = os.getenv('AWS_ROLE_ARN')
        self.aws_external_id = os.getenv('AWS_EXTERNAL_ID', 'fibromap-2024')
        
        print("\nConfiguration loaded:")
        print(f"  Data bucket: {self.data_bucket}")
        print(f"  Region: {self.aws_region}")
        print(f"  Access Key found: {bool(self.aws_access_key)}")
        print(f"  Secret Key found: {bool(self.aws_secret_key)}")
        print(f"  Role ARN: {self.aws_role_arn}")
        print(f"  External ID: {self.aws_external_id}")
        print("="*60)
        
        if not self.aws_access_key:
            logger.error("AWS_ACCESS_KEY_ID not found! Checked: AWS_ACCESS_KEY_ID, AWS_ACCESS_KEY, ACCESS_KEY_ID, ACCESS_KEY")
        
        if not self.aws_secret_key:
            logger.error("AWS_SECRET_ACCESS_KEY not found! Checked: AWS_SECRET_ACCESS_KEY, AWS_SECRET_KEY, SECRET_ACCESS_KEY, SECRET_KEY")
        
        # Initialize AWS clients
        self.sts_client = None
        self.s3_client = None
        
        if self.aws_access_key and self.aws_secret_key:
            try:
                # Always try to create STS client if we have credentials
                logger.info("Attempting to create STS client during initialization...")
                self.sts_client = boto3.client(
                    'sts',
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_secret_key,
                    region_name=self.aws_region
                )
                
                # Test the STS client
                try:
                    identity = self.sts_client.get_caller_identity()
                    logger.info(f"STS client initialized successfully")
                    logger.info(f"  Account: {identity['Account']}")
                    logger.info(f"  ARN: {identity['Arn']}")
                    logger.info(f"  UserID: {identity['UserId']}")
                except Exception as e:
                    logger.error(f"STS client test failed during init: {e}")
                    self.sts_client = None
                
                # Create S3 client
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_secret_key,
                    region_name=self.aws_region
                )
                logger.info("S3 client created successfully")
                
            except Exception as e:
                logger.error(f"Failed to create AWS clients during init: {e}")
                import traceback
                logger.error(traceback.format_exc())
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
            
            # Check if credential generation was successful
            if data_credentials.get('access_key_id'):
                # Log successful credential generation
                self._log_credential_generation(user.user_id, ip_address, success=True)
                
                result = {
                    'data_bucket': data_credentials,
                    'region': self.aws_region,
                    'expires_at': data_credentials.get('expiration', 
                        (datetime.now() + timedelta(hours=self.credential_duration_hours)).isoformat())
                }
                
                # Skip images bucket for now
                # images_credentials = self._generate_images_bucket_credentials(user, user_projects)
                # if images_credentials:
                #     result['images_bucket'] = images_credentials
                
                return result
            else:
                # Credential generation failed
                error_msg = data_credentials.get('error', 'Unknown error')
                logger.error(f"Failed to generate credentials: {error_msg}")
                self._log_credential_generation(user.user_id, ip_address, success=False, 
                                            error=error_msg)
                
                # Return error response (no fallback to raw credentials for security)
                return {
                    'data_bucket': data_credentials,  # This contains the error message
                    'region': self.aws_region,
                    'expires_at': None
                }
                
        except Exception as e:
            logger.error(f"Error generating user credentials: {e}")
            self._log_credential_generation(user.user_id, ip_address, success=False, 
                                        error=str(e))
            
            # Return error response (no raw credentials for security)
            return {
                'data_bucket': {
                    'bucket_name': self.data_bucket,
                    'access_key_id': None,
                    'secret_access_key': None,
                    'region': self.aws_region,
                    'error': f'Failed to generate credentials: {str(e)}'
                },
                'region': self.aws_region,
                'expires_at': None
            }
                
    def _generate_data_bucket_credentials(self, user: User) -> Dict[str, Any]:
        """Generate temporary credentials for the data bucket."""
        try:
            # Read credentials fresh from environment
            aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
            aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
            aws_region = os.getenv('AWS_REGION', 'us-east-1')
            aws_role_arn = os.getenv('AWS_ROLE_ARN')
            aws_external_id = os.getenv('AWS_EXTERNAL_ID', 'fibromap-2024')
            
            # Validate required credentials
            if not aws_access_key or not aws_secret_key:
                logger.error("AWS credentials not configured")
                return self._create_error_response(aws_region, 'AWS credentials not configured on server')
            
            if not aws_role_arn:
                logger.error("AWS_ROLE_ARN not configured - cannot use STS")
                return self._create_error_response(aws_region, 'AWS_ROLE_ARN not configured - STS not available')
            
            # Initialize STS client if needed
            if not self.sts_client:
                sts_client = self._initialize_sts_client(aws_access_key, aws_secret_key, aws_region)
                if not sts_client:
                    return self._create_error_response(aws_region, 'Failed to initialize STS client')
                self.sts_client = sts_client
            
            # Generate credentials based on user role
            if user.role == 'admin':
                return self._generate_admin_credentials(user, aws_role_arn, aws_external_id, aws_region)
            else:
                return self._generate_user_credentials(user, aws_role_arn, aws_external_id, aws_region)
                
        except Exception as e:
            logger.error(f"Error generating credentials: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return self._create_error_response(
                os.getenv('AWS_REGION', 'us-east-1'), 
                f'Unexpected error: {str(e)}'
            )

    def _initialize_sts_client(self, access_key: str, secret_key: str, region: str):
        """Initialize the STS client."""
        try:
            logger.info(f"Initializing STS client...")
            logger.info(f"  Access Key (first 10 chars): {access_key[:10] if access_key else 'None'}")
            logger.info(f"  Secret Key exists: {bool(secret_key)}")
            logger.info(f"  Region: {region}")
            
            client = boto3.client(
                'sts',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            
            # Test the client immediately
            try:
                caller_identity = client.get_caller_identity()
                logger.info(f"STS client created and verified successfully")
                logger.info(f"  Account: {caller_identity['Account']}")
                logger.info(f"  ARN: {caller_identity['Arn']}")
                logger.info(f"  UserID: {caller_identity['UserId']}")
            except Exception as test_error:
                logger.error(f"STS client verification failed: {test_error}")
                logger.error(f"  Error type: {type(test_error).__name__}")
                return None
                
            return client
            
        except Exception as e:
            logger.error(f"Failed to create STS client: {e}")
            logger.error(f"  Error type: {type(e).__name__}")
            import traceback
            logger.error(traceback.format_exc())
            return None
        
    def _create_error_response(self, region: str, error_message: str) -> Dict[str, Any]:
        """Create a standardized error response."""
        return {
            'bucket_name': self.data_bucket,
            'access_key_id': None,
            'secret_access_key': None,
            'region': region,
            'error': error_message
        }

    def _create_admin_policy(self) -> Dict[str, Any]:
        """Create IAM policy for admin users with full bucket access."""
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                        "s3:ListBucketVersions"
                    ],
                    "Resource": f"arn:aws:s3:::{self.data_bucket}"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:GetObjectVersion",
                        "s3:DeleteObjectVersion",
                        "s3:GetObjectAcl",
                        "s3:PutObjectAcl"
                    ],
                    "Resource": f"arn:aws:s3:::{self.data_bucket}/*"
                }
            ]
        }

    def _create_user_policy(self, user_prefix: str, shared_prefixes: List[str] = None) -> Dict[str, Any]:
        """
        Create IAM policy for regular users with restricted access.
        
        Args:
            user_prefix: The user's own folder prefix
            shared_prefixes: List of additional prefixes the user has access to (for shared projects)
        """
        # Start with the user's own folder
        allowed_prefixes = [f"{user_prefix}/*"]
        allowed_resources = [f"arn:aws:s3:::{self.data_bucket}/{user_prefix}/*"]
        
        # Add shared project folders if any
        if shared_prefixes:
            for prefix in shared_prefixes:
                allowed_prefixes.append(f"{prefix}/*")
                allowed_resources.append(f"arn:aws:s3:::{self.data_bucket}/{prefix}/*")
        
        return {
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
                            "s3:prefix": allowed_prefixes
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
                    "Resource": allowed_resources
                }
            ]
        }


    def _assume_role_with_policy(self, role_arn: str, session_name: str, policy: Dict[str, Any], 
                                external_id: str) -> Optional[Dict[str, Any]]:
        """
        Assume an IAM role with a specific policy.
        
        Returns:
            Dictionary with credentials or None if failed
        """
        try:
            logger.info(f"=== Starting Role Assumption ===")
            logger.info(f"  Role ARN: {role_arn}")
            logger.info(f"  Session name: {session_name}")
            logger.info(f"  External ID: {external_id}")
            logger.info(f"  STS client exists: {self.sts_client is not None}")
            
            if not self.sts_client:
                logger.error("STS client is None - cannot assume role")
                return None
            
            # Log the policy being used (first 200 chars)
            policy_str = json.dumps(policy)
            logger.info(f"  Policy (first 200 chars): {policy_str[:200]}...")
            
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                Policy=policy_str,
                DurationSeconds=self.credential_duration_hours * 3600,
                ExternalId=external_id
            )
            
            logger.info("Successfully assumed role - received credentials")
            
            # Validate response structure
            if 'Credentials' not in response:
                logger.error("Response missing 'Credentials' key")
                logger.error(f"Response keys: {response.keys()}")
                return None
                
            credentials = response['Credentials']
            logger.info(f"  Access Key ID (first 10): {credentials['AccessKeyId'][:10]}...")
            logger.info(f"  Has Session Token: {bool(credentials.get('SessionToken'))}")
            logger.info(f"  Expiration: {credentials.get('Expiration')}")
            
            return credentials
            
        except Exception as e:
            logger.error(f"STS assume role failed: {e}")
            logger.error(f"  Error type: {type(e).__name__}")
            logger.error(f"  Error details: {str(e)}")
            
            # Check for specific error types
            error_str = str(e)
            if 'AccessDenied' in error_str:
                logger.error("ACCESS DENIED - Possible issues:")
                logger.error("  1. IAM user doesn't have sts:AssumeRole permission")
                logger.error("  2. Trust policy doesn't allow this user")
                logger.error("  3. External ID mismatch")
            elif 'InvalidParameterValue' in error_str:
                logger.error("INVALID PARAMETER - Check:")
                logger.error("  1. Role ARN format")
                logger.error("  2. External ID format")
                logger.error("  3. Session name format")
            elif 'NoSuchEntity' in error_str:
                logger.error("ROLE NOT FOUND - Check:")
                logger.error("  1. Role ARN is correct")
                logger.error("  2. Role exists in the account")
            elif 'MalformedPolicyDocument' in error_str:
                logger.error("MALFORMED POLICY - Check:")
                logger.error("  1. Policy JSON is valid")
                logger.error("  2. Policy syntax is correct")
                
            import traceback
            logger.error("Full traceback:")
            logger.error(traceback.format_exc())
            
            return None

    def _generate_admin_credentials(self, user: User, role_arn: str, external_id: str, 
                                region: str) -> Dict[str, Any]:
        """Generate STS credentials for admin users with full bucket access."""
        logger.info(f"=== Generating Admin Credentials ===")
        logger.info(f"User: {user.username} (ID: {user.user_id})")
        logger.info(f"Role ARN: {role_arn}")
        logger.info(f"External ID: {external_id}")
        logger.info(f"Region: {region}")
        
        # Validate inputs
        if not role_arn:
            logger.error("Role ARN is None or empty")
            return self._create_error_response(region, 'Role ARN not provided')
        
        if not external_id:
            logger.error("External ID is None or empty")
            return self._create_error_response(region, 'External ID not provided')
        
        # Ensure STS client exists
        if not self.sts_client:
            logger.warning("STS client not initialized, attempting to create...")
            aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
            aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
            
            if aws_access_key and aws_secret_key:
                self.sts_client = self._initialize_sts_client(aws_access_key, aws_secret_key, region)
                if not self.sts_client:
                    logger.error("Failed to initialize STS client")
                    return self._create_error_response(region, 'Failed to initialize STS client')
            else:
                logger.error("Cannot create STS client - missing AWS credentials")
                return self._create_error_response(region, 'AWS credentials not available')
        
        # Create admin policy with full bucket access
        try:
            policy = self._create_admin_policy()
            logger.info(f"Created admin policy for bucket: {self.data_bucket}")
        except Exception as e:
            logger.error(f"Failed to create admin policy: {e}")
            return self._create_error_response(region, f'Failed to create admin policy: {str(e)}')
        
        # Generate unique session name
        timestamp = int(datetime.now().timestamp())
        session_name = f"fibromap-admin-{user.user_id}-{timestamp}"
        logger.info(f"Session name: {session_name}")
        
        # Attempt to assume role
        try:
            logger.info("Calling _assume_role_with_policy...")
            credentials = self._assume_role_with_policy(role_arn, session_name, policy, external_id)
            
            if not credentials:
                logger.error("_assume_role_with_policy returned None")
                error_response = self._create_error_response(region, 'STS assume role returned no credentials')
                error_response['debug_info'] = {
                    'role_arn': role_arn,
                    'external_id': external_id,
                    'session_name': session_name,
                    'user_role': user.role,
                    'user_id': user.user_id,
                    'sts_client_exists': self.sts_client is not None
                }
                return error_response
            
            logger.info("Successfully obtained STS credentials")
            
        except Exception as e:
            logger.error(f"Exception during role assumption: {type(e).__name__}: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            
            error_response = self._create_error_response(region, f'Failed to assume role: {str(e)}')
            error_response['debug_info'] = {
                'role_arn': role_arn,
                'external_id': external_id,
                'session_name': session_name,
                'error_type': type(e).__name__,
                'error_details': str(e)
            }
            return error_response
        
        # Validate credentials structure
        try:
            if not isinstance(credentials, dict):
                logger.error(f"Credentials is not a dict: {type(credentials)}")
                return self._create_error_response(region, 'Invalid credentials format')
            
            required_fields = ['AccessKeyId', 'SecretAccessKey', 'SessionToken', 'Expiration']
            missing_fields = [field for field in required_fields if field not in credentials]
            
            if missing_fields:
                logger.error(f"Missing credential fields: {missing_fields}")
                return self._create_error_response(region, f'Incomplete credentials: missing {missing_fields}')
            
            logger.info("Credentials validation passed")
            
        except Exception as e:
            logger.error(f"Error validating credentials: {e}")
            return self._create_error_response(region, f'Credential validation error: {str(e)}')
        
        # Format successful response
        try:
            user_prefix = f"users/{user.username}"
            
            response = {
                'bucket_name': self.data_bucket,
                'access_key_id': credentials['AccessKeyId'],
                'secret_access_key': credentials['SecretAccessKey'],
                'session_token': credentials['SessionToken'],
                'region': region,
                'user_prefix': user_prefix,
                'expiration': credentials['Expiration'].isoformat() if hasattr(credentials['Expiration'], 'isoformat') else str(credentials['Expiration']),
                'credential_type': 'sts',
                'user_role': 'admin',
                'access_level': 'full_bucket'
            }
            
            logger.info(f"=== Successfully Generated Admin STS Credentials ===")
            logger.info(f"  User: {user.username}")
            logger.info(f"  Expires at: {response['expiration']}")
            logger.info(f"  Access level: full_bucket")
            
            return response
            
        except Exception as e:
            logger.error(f"Error formatting response: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return self._create_error_response(region, f'Failed to format response: {str(e)}')
        
    def _generate_user_credentials(self, user: User, role_arn: str, external_id: str, 
                                region: str) -> Dict[str, Any]:
        """Generate STS credentials for regular users with restricted access."""
        logger.info(f"Generating user credentials for user {user.username}")
        
        user_prefix = f"users/{user.username}"
        
        # TODO: In the future, fetch shared project prefixes from database
        # For now, just give access to user's own folder
        shared_prefixes = None
        
        # Create user policy with restrictions
        policy = self._create_user_policy(user_prefix, shared_prefixes)
        
        # Generate session name
        session_name = f"fibromap-user-{user.user_id}-{int(datetime.now().timestamp())}"
        
        # Assume role with user policy
        credentials = self._assume_role_with_policy(role_arn, session_name, policy, external_id)
        
        if not credentials:
            return self._create_error_response(region, 'Failed to assume role for user')
        
        logger.info(f"Successfully generated restricted STS credentials for {user.username}")
        
        return {
            'bucket_name': self.data_bucket,
            'access_key_id': credentials['AccessKeyId'],
            'secret_access_key': credentials['SecretAccessKey'],
            'session_token': credentials['SessionToken'],
            'region': region,
            'user_prefix': user_prefix,
            'expiration': credentials['Expiration'].isoformat(),
            'credential_type': 'sts',
            'user_role': 'user',
            'access_level': 'restricted',
            'accessible_prefixes': [user_prefix] + (shared_prefixes or [])
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
                expected_prefix = f"users/{user.username}/"
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
        # Get username and project name from database
        from database import db_manager
        user = db_manager.get_user_by_id(user_id)
        project = db_manager.get_project_by_id(project_id)
        if not user or not project:
            logger.error(f"User or project not found")
            return {}
        
        safe_project_name = project.project_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
        base_path = f"users/{user.username}/{safe_project_name}"
        
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
        # Get username and project name from database
        from database import db_manager
        user = db_manager.get_user_by_id(user_id)
        project = db_manager.get_project_by_id(project_id)
        if not user or not project:
            logger.error(f"User or project not found")
            return ""
        
        safe_project_name = project.project_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
        base_path = f"users/{user.username}/{safe_project_name}/versions"
        
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
    def get_user_prefix(user_id: int, username: str = None) -> str:
        """Get S3 prefix for a user's data."""
        if username:
            # New format: username_id (e.g., info_1, john_15)
            return f"users/{username}_{user_id}"
        else:
            # Fallback to old format if username not available
            return f"users/user_{user_id:03d}"
    
    @staticmethod
    def get_project_prefix(user_id: int, project_id: int, username: str, project_name: str) -> str:
        """Generate S3 prefix for a project."""
        user_prefix = f"users/{username}"
        safe_project_name = project_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
        return f"{user_prefix}/{safe_project_name}/"
    
    @staticmethod
    def get_current_data_prefix(user_id: int, project_id: int, username: str = None) -> str:
        """Get S3 prefix for current project data."""
        project_prefix = S3PathHelper.get_project_prefix(user_id, project_id, username)
        return f"{project_prefix}/current"
    
    @staticmethod
    def get_thumbnails_prefix(user_id: int, project_id: int, username: str = None) -> str:
        """Get S3 prefix for project thumbnails."""
        project_prefix = S3PathHelper.get_project_prefix(user_id, project_id, username)
        return f"{project_prefix}/thumbnails"
    
    @staticmethod
    def get_versions_prefix(user_id: int, project_id: int, username: str = None) -> str:
        """Get S3 prefix for project versions."""
        project_prefix = S3PathHelper.get_project_prefix(user_id, project_id, username)
        return f"{project_prefix}/versions"
    
    @staticmethod
    def parse_project_path(s3_path: str) -> Optional[Tuple[int, int, str]]:
        """
        Parse user_id, project_id, and username from S3 path.
        
        Args:
            s3_path: S3 object path
            
        Returns:
            Tuple of (user_id, project_id, username) or None if invalid
        """
        try:
            # Expected formats: 
            # New: users/john_15/project_002/...
            # Old: users/user_001/project_002/...
            parts = s3_path.split('/')
            if len(parts) < 3 or parts[0] != 'users':
                return None
            
            user_part = parts[1]  # john_15 or user_001
            project_part = parts[2]  # project_002
            
            # Project part might be project_XXX or projectname_XXX
            # Extract project ID from the end after last underscore
            last_underscore = project_part.rfind('_')
            if last_underscore == -1:
                return None
            
            # Parse user part
            if user_part.startswith('user_'):
                # Old format: user_001
                user_id = int(user_part[5:])
                username = None
            else:
                # New format: username_id (e.g., john_15)
                last_underscore = user_part.rfind('_')
                if last_underscore == -1:
                    return None
                username = user_part[:last_underscore]
                user_id = int(user_part[last_underscore + 1:])
            
            # Parse project ID from end of project folder name
            try:
                project_id = int(project_part[last_underscore + 1:])
            except ValueError:
                return None
            
            return user_id, project_id, username
            
        except (ValueError, IndexError):
            return None
    
    @staticmethod
    def is_valid_user_path(s3_path: str, user_id: int, username: str = None) -> bool:
        """Check if S3 path is valid for a specific user."""
        if username:
            expected_prefix = f"users/{username}/"
        else:
            expected_prefix = f"users/user_{user_id:03d}/"  # Fallback
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