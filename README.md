# FibroMAP Server

Railway-hosted authentication and API server for the FibroMAP application. Provides user authentication, project management, and AWS S3 credential generation for secure file storage.

## Architecture Overview

This server provides:
- **User Authentication**: Login, registration, session management
- **Project Management**: CRUD operations, version control, conflict resolution  
- **S3 Access Control**: Temporary credential generation for user data and company images
- **Offline Sync**: Conflict detection and resolution for offline editing

## Quick Start

### 1. Local Development Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd fibromap-server

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your actual values (see Configuration section)

# Set up local PostgreSQL database
createdb fibromap
# The database schema will be created automatically on first run

# Run the server
python app.py
```

The server will start on `http://localhost:5000` with the health check at `http://localhost:5000/health`.

### 2. Railway Deployment

```bash
# Connect your GitHub repository to Railway
# 1. Go to railway.app
# 2. Click "New Project" → "Deploy from GitHub repo"
# 3. Select this repository

# Add PostgreSQL database
# 1. In Railway dashboard, click "New" → "Database" → "PostgreSQL"
# 2. Railway will automatically provide DATABASE_URL

# Set environment variables in Railway dashboard
# Go to your service → Variables tab and add all variables from .env.example
```

## Configuration

### Required Environment Variables

Copy `.env.example` to `.env` and configure these variables:

#### Database
- `DATABASE_URL`: PostgreSQL connection string (Railway provides this)

#### Flask  
- `FLASK_SECRET_KEY`: Secret key for sessions (generate random string)
- `FLASK_ENV`: Environment (development/staging/production)

#### AWS
- `AWS_ACCESS_KEY_ID`: AWS access key for permanent IAM user
- `AWS_SECRET_ACCESS_KEY`: AWS secret key
- `AWS_DEFAULT_REGION`: AWS region (e.g., us-east-1)
- `FIBROMAP_S3_BUCKET`: S3 bucket for user data
- `FIBROMAP_IMAGES_BUCKET`: S3 bucket for company images
- `AWS_DATA_ROLE_ARN`: IAM role for data bucket access *(setup required)*
- `AWS_IMAGES_ROLE_ARN`: IAM role for images bucket access *(setup required)*

#### Security
- `INTERNAL_CLEANUP_TOKEN`: Token for cleanup endpoints (generate random string)
- `ALLOWED_ORIGINS`: Comma-separated CORS origins

### AWS Infrastructure Setup (Required)

**⚠️ TODO: AWS infrastructure is not yet set up. You'll need to:**

1. **Create S3 Buckets:**
   ```bash
   # Data bucket for user projects
   aws s3 mb s3://your-fibromap-data
   
   # Images bucket for company microscopy images  
   aws s3 mb s3://company-microscopy-images
   ```

2. **Create IAM User for Railway:**
   - Create permanent IAM user with programmatic access
   - Grant permissions to assume roles and generate temporary credentials
   - Add access keys to Railway environment variables

3. **Create IAM Roles:**
   - `FibroMapDataAccess`: Role for user data bucket access
   - `FibroMapImagesAccess`: Role for company images bucket access
   - Configure trust relationships for the permanent IAM user

4. **Update Environment Variables:**
   - Set the role ARNs in `AWS_DATA_ROLE_ARN` and `AWS_IMAGES_ROLE_ARN`

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration  
- `POST /api/auth/refresh` - Refresh S3 credentials
- `POST /api/auth/logout` - User logout

### Projects
- `GET /api/projects` - List user's projects
- `POST /api/projects` - Create new project
- `GET /api/projects/{id}` - Get project details
- `POST /api/projects/{id}/check-version` - Check for conflicts
- `POST /api/projects/{id}/confirm-save` - Confirm save completion
- `POST /api/projects/{id}/resolve-conflict` - Resolve sync conflicts

### Admin
- `PUT /api/admin/projects/{id}/assign-images` - Assign company images

### System  
- `GET /health` - Health check
- `POST /api/internal/cleanup` - Cleanup expired data

## Database Schema

The server automatically creates these PostgreSQL tables:

- **users**: User accounts and authentication
- **sessions**: User sessions and tokens
- **projects**: Project metadata and S3 paths
- **project_permissions**: Access control for projects
- **audit_log**: Action logging for compliance
- **s3_versions**: Version backup tracking

## Security Features

- **Password Security**: Bcrypt hashing with configurable rounds
- **Session Management**: Secure token generation with expiration
- **Account Lockout**: Protection against brute force attacks
- **Audit Logging**: Comprehensive action logging
- **CORS Protection**: Configurable allowed origins
- **IP Binding**: Optional session IP validation

## Offline Sync & Conflict Resolution

The server handles offline editing conflicts:

1. **Version Checking**: Clients check version before saving
2. **Conflict Detection**: Server compares timestamps
3. **User Choice**: Client presents resolution options
4. **Backup Creation**: Overwritten versions saved for 48 hours
5. **Cleanup**: Automatic deletion of old backups

## File Storage Structure

### S3 Data Bucket Layout:
```
users/
├── user_001/
│   ├── project_001/
│   │   ├── current/
│   │   │   ├── fiber_data.parquet
│   │   │   ├── texture_data.parquet
│   │   │   └── regions.json
│   │   ├── thumbnails/
│   │   │   ├── company_slide_001_thumb.jpg
│   │   │   └── external_img_001_thumb.jpg
│   │   └── versions/
│   │       ├── 2025-01-15_10-30-00_userA/
│   │       └── 2025-01-15_15-00-00_userB_overwritten/
│   └── project_002/
└── user_002/
```

### S3 Images Bucket Layout:
```
liver_study_2025/
├── slide_001.svs
├── slide_002.svs
└── metadata.json

cardiac_study_2024/
├── sample_001.tiff
└── sample_002.tiff
```

## Development

### Running Tests
```bash
# TODO: Add test suite
pytest tests/
```

### Code Structure
```
fibromap-server/
├── app.py              # Main Flask application
├── auth.py             # Authentication logic
├── database.py         # Database operations
├── models.py           # Data models and schema
├── s3_manager.py       # S3 credential management
├── requirements.txt    # Python dependencies
├── .env.example        # Environment template
└── README.md          # This file
```

### Adding New Endpoints

1. Add route handler to `app.py`
2. Add database operations to `database.py`
3. Update models in `models.py` if needed
4. Add authentication/authorization decorators
5. Update this README

## Monitoring & Maintenance

### Health Checks
- Railway monitors `/health` endpoint
- Returns system status and timestamp

### Cleanup Jobs
The server includes automatic cleanup:
- **Expired Sessions**: Cleaned every 6 hours
- **S3 Version Backups**: Cleaned after 48 hours
- **Audit Logs**: Configurable retention

### Logs
- All authentication events logged
- Project actions tracked
- Error logging with stack traces
- Railway provides log aggregation

## Support

### Troubleshooting

**Database Connection Issues:**
- Verify `DATABASE_URL` is set correctly
- Check Railway PostgreSQL service status
- Ensure database exists and schema is created

**AWS Credential Issues:**
- Verify IAM user has correct permissions
- Check role ARNs are properly formatted
- Ensure trust relationships are configured

**CORS Issues:**
- Update `ALLOWED_ORIGINS` environment variable
- Check client is sending proper headers

### Environment-Specific Notes

**Development:**
- Use `FLASK_ENV=development` for debug mode
- Set `ALLOWED_ORIGINS=*` for local testing
- Use local PostgreSQL for faster iteration

**Production:**
- Use strong `FLASK_SECRET_KEY`
- Set specific CORS origins
- Enable IP binding for sessions
- Monitor logs and metrics

## License

[Your License Here]

## Contributing

[Your Contributing Guidelines Here]