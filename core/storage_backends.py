# core/storage_backends.py

"""
Custom storage backend for Cloudflare R2.
Fixes region detection issues that cause infinite retry loops.
"""

import logging
from storages.backends.s3boto3 import S3Boto3Storage
from botocore.config import Config

logger = logging.getLogger(__name__)


class CloudflareR2Storage(S3Boto3Storage):
    """
    Custom S3 storage backend optimized for Cloudflare R2.
    
    Fixes:
    - Disables region detection (R2 doesn't support head_bucket properly)
    - Uses path-style addressing required by R2
    - Disables automatic retries that cause infinite loops
    """
    
    def __init__(self, **settings):
        # Force settings required for R2
        settings['addressing_style'] = 'path'
        settings['signature_version'] = 's3v4'
        settings['region_name'] = 'auto'
        
        super().__init__(**settings)
    
    @property
    def connection(self):
        """
        Override connection to add R2-specific configurations.
        """
        if self._connection is None:
            self._connection = self._create_connection()
        return self._connection
    
    def _create_connection(self):
        """
        Create boto3 connection with R2-optimized settings.
        """
        import boto3
        from django.conf import settings as django_settings
        
        # Custom config that disables problematic features for R2
        config = Config(
            signature_version='s3v4',
            s3={
                'addressing_style': 'path',
            },
            retries={
                'max_attempts': 3,
                'mode': 'standard',
            },
            # Disable region detection
            inject_host_prefix=False,
        )
        
        session = boto3.session.Session()
        
        return session.resource(
            's3',
            aws_access_key_id=django_settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=django_settings.AWS_SECRET_ACCESS_KEY,
            endpoint_url=django_settings.AWS_S3_ENDPOINT_URL,
            region_name='auto',
            config=config,
        )
    
    def _get_write_parameters(self, name, content=None):
        """
        Override to ensure proper content type handling.
        """
        params = super()._get_write_parameters(name, content)
        
        # Ensure we don't pass problematic parameters to R2
        params.pop('ServerSideEncryption', None)
        params.pop('SSEKMSKeyId', None)
        
        return params
    
    def _save(self, name, content):
        """
        Override save to add better error handling for R2.
        """
        try:
            return super()._save(name, content)
        except Exception as e:
            logger.error(f"R2 Storage save error for {name}: {str(e)}")
            raise


class CloudflareR2StaticStorage(CloudflareR2Storage):
    """
    Storage backend for static files on R2 (if needed).
    """
    location = 'static'
    default_acl = None
    file_overwrite = True


class CloudflareR2MediaStorage(CloudflareR2Storage):
    """
    Storage backend for media files on R2.
    """
    location = ''
    default_acl = None
    file_overwrite = False