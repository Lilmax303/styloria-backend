# core/storage_backends.py

"""
Custom storage backend for Cloudflare R2.
Standalone implementation that avoids region detection issues.
"""

import os
import logging
import mimetypes
from io import BytesIO
from datetime import datetime

from django.conf import settings
from django.core.files.base import File, ContentFile
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible

# Import botocore exception properly
try:
    from botocore.exceptions import ClientError
except ImportError:
    ClientError = Exception

logger = logging.getLogger(__name__)


@deconstructible
class CloudflareR2Storage(Storage):
    """
    Standalone storage backend for Cloudflare R2.
    
    This implementation uses boto3 client directly and disables
    the region detection that causes infinite loops with R2.
    """
    
    def __init__(self, **kwargs):
        self._client = None
        self._bucket_name = kwargs.get('bucket_name') or getattr(settings, 'AWS_STORAGE_BUCKET_NAME', '')
        self._endpoint_url = kwargs.get('endpoint_url') or getattr(settings, 'AWS_S3_ENDPOINT_URL', '')
        self._access_key = kwargs.get('access_key') or getattr(settings, 'AWS_ACCESS_KEY_ID', '')
        self._secret_key = kwargs.get('secret_key') or getattr(settings, 'AWS_SECRET_ACCESS_KEY', '')
        self._custom_domain = kwargs.get('custom_domain') or getattr(settings, 'AWS_S3_CUSTOM_DOMAIN', '')
        self._querystring_auth = kwargs.get('querystring_auth', getattr(settings, 'AWS_QUERYSTRING_AUTH', True))
        self._default_acl = kwargs.get('default_acl') or getattr(settings, 'AWS_DEFAULT_ACL', None)
        self._cache_control = None
        
        # Get cache control from settings
        obj_params = getattr(settings, 'AWS_S3_OBJECT_PARAMETERS', {})
        if obj_params:
            self._cache_control = obj_params.get('CacheControl')
        
        logger.info(f"CloudflareR2Storage initialized: bucket={self._bucket_name}")
    
    @property
    def client(self):
        """
        Lazy-load the boto3 client with R2-compatible settings.
        """
        if self._client is None:
            self._client = self._create_client()
        return self._client
    
    def _create_client(self):
        """
        Create a boto3 S3 client configured for Cloudflare R2.
        Disables automatic region detection that causes infinite loops.
        """
        import boto3
        from botocore.config import Config
        
        logger.info(f"Creating boto3 client for R2: endpoint={self._endpoint_url}")
        
        # Configuration that works with R2
        config = Config(
            signature_version='s3v4',
            s3={
                'addressing_style': 'path',
            },
            retries={
                'max_attempts': 3,
                'mode': 'standard',
            },
        )
        
        # Create session and client
        session = boto3.session.Session()
        
        client = session.client(
            's3',
            aws_access_key_id=self._access_key,
            aws_secret_access_key=self._secret_key,
            endpoint_url=self._endpoint_url,
            region_name='auto',
            config=config,
        )
        
        # CRITICAL: Unregister the region redirector that causes infinite loops with R2
        # This handler tries to detect bucket region on errors, which R2 doesn't support
        try:
            client.meta.events.unregister(
                'needs-retry.s3.PutObject',
                handler=self._find_and_remove_redirect_handler(client, 'needs-retry.s3.PutObject')
            )
        except Exception as e:
            logger.debug(f"Could not unregister PutObject retry handler: {e}")
        
        # Also try to unregister for all S3 operations
        self._disable_region_redirector(client)
        
        logger.info("boto3 client created successfully with region redirector disabled")
        return client
    
    def _disable_region_redirector(self, client):
        """
        Disable the S3 region redirector that causes issues with R2.
        """
        try:
            # Get the event system
            events = client.meta.events
            
            # Try to unregister all redirect_from_error handlers
            # These are registered by botocore.utils.S3RegionRedirectorv2
            event_names = [
                'needs-retry.s3.PutObject',
                'needs-retry.s3.GetObject', 
                'needs-retry.s3.HeadObject',
                'needs-retry.s3.DeleteObject',
                'needs-retry.s3.ListObjects',
                'needs-retry.s3.ListObjectsV2',
                'needs-retry.s3.*',
            ]
            
            for event_name in event_names:
                try:
                    # Get all handlers for this event
                    handlers = list(events._emitter._handlers.get(event_name, []))
                    for handler in handlers:
                        # Check if this is the redirect handler
                        handler_func = handler[1] if isinstance(handler, tuple) else handler
                        handler_name = getattr(handler_func, '__name__', str(handler_func))
                        if 'redirect' in handler_name.lower() or 'region' in handler_name.lower():
                            try:
                                events.unregister(event_name, handler=handler_func)
                                logger.debug(f"Unregistered {handler_name} from {event_name}")
                            except Exception:
                                pass
                except Exception:
                    pass
                    
        except Exception as e:
            logger.debug(f"Could not disable region redirector: {e}")
    
    def _find_and_remove_redirect_handler(self, client, event_name):
        """Find the redirect handler for a specific event."""
        try:
            handlers = client.meta.events._emitter._handlers.get(event_name, [])
            for handler in handlers:
                handler_func = handler[1] if isinstance(handler, tuple) else handler
                if 'redirect' in getattr(handler_func, '__name__', '').lower():
                    return handler_func
        except Exception:
            pass
        return None
    
    def _normalize_name(self, name):
        """Normalize the file name."""
        if name is None:
            return name
        name = name.replace('\\', '/')
        while name.startswith('/'):
            name = name[1:]
        return name
    
    def _get_content_type(self, name):
        """Guess the content type from the file name."""
        content_type, _ = mimetypes.guess_type(name)
        return content_type or 'application/octet-stream'
    
    def _save(self, name, content):
        """Save file to R2."""
        name = self._normalize_name(name)
        
        logger.info(f"CloudflareR2Storage._save: name={name}")
        
        # Read the content
        content.seek(0)
        data = content.read()
        
        logger.info(f"CloudflareR2Storage._save: read {len(data)} bytes")
        
        # Prepare upload parameters
        params = {
            'Bucket': self._bucket_name,
            'Key': name,
            'Body': data,
        }
        
        # Add content type
        content_type = getattr(content, 'content_type', None)
        if not content_type:
            content_type = self._get_content_type(name)
        params['ContentType'] = content_type
        
        # Add cache control if configured
        if self._cache_control:
            params['CacheControl'] = self._cache_control
        
        try:
            self.client.put_object(**params)
            logger.info(f"Successfully uploaded '{name}' to R2 bucket '{self._bucket_name}'")
            return name
        except Exception as e:
            logger.error(f"Failed to upload '{name}' to R2: {type(e).__name__}: {str(e)}")
            raise
    
    def _open(self, name, mode='rb'):
        """Open a file from R2."""
        name = self._normalize_name(name)
        
        try:
            response = self.client.get_object(
                Bucket=self._bucket_name,
                Key=name,
            )
            
            data = response['Body'].read()
            file_obj = BytesIO(data)
            file_obj.name = name
            return File(file_obj)
        except Exception as e:
            logger.error(f"Failed to open '{name}' from R2: {type(e).__name__}: {str(e)}")
            raise
    
    def delete(self, name):
        """Delete a file from R2."""
        name = self._normalize_name(name)
        
        try:
            self.client.delete_object(
                Bucket=self._bucket_name,
                Key=name,
            )
            logger.info(f"Successfully deleted '{name}' from R2")
        except Exception as e:
            logger.error(f"Failed to delete '{name}' from R2: {type(e).__name__}: {str(e)}")
            raise
    
    def exists(self, name):
        """Check if a file exists in R2."""
        name = self._normalize_name(name)
        
        try:
            self.client.head_object(
                Bucket=self._bucket_name,
                Key=name,
            )
            return True
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == '404':
                return False
            logger.warning(f"Error checking existence of '{name}': {str(e)}")
            return False
        except Exception:
            return False
    
    def size(self, name):
        """Return the size of a file."""
        name = self._normalize_name(name)
        
        try:
            response = self.client.head_object(
                Bucket=self._bucket_name,
                Key=name,
            )
            return response.get('ContentLength', 0)
        except Exception:
            return 0
    
    def url(self, name):
        """Return the URL of a file."""
        name = self._normalize_name(name)
        
        # If custom domain is set, use it
        if self._custom_domain:
            return f"https://{self._custom_domain}/{name}"
        
        # Generate presigned URL if querystring auth is enabled
        if self._querystring_auth:
            try:
                url = self.client.generate_presigned_url(
                    'get_object',
                    Params={
                        'Bucket': self._bucket_name,
                        'Key': name,
                    },
                    ExpiresIn=3600,  # 1 hour
                )
                return url
            except Exception as e:
                logger.error(f"Failed to generate presigned URL for '{name}': {str(e)}")
        
        # Fallback to direct URL construction
        return f"{self._endpoint_url}/{self._bucket_name}/{name}"
    
    def get_accessed_time(self, name):
        return self.get_modified_time(name)
    
    def get_created_time(self, name):
        return self.get_modified_time(name)
    
    def get_modified_time(self, name):
        name = self._normalize_name(name)
        
        try:
            response = self.client.head_object(
                Bucket=self._bucket_name,
                Key=name,
            )
            return response.get('LastModified', datetime.now())
        except Exception:
            return datetime.now()
    
    def listdir(self, path=''):
        path = self._normalize_name(path) or ''
        if path and not path.endswith('/'):
            path += '/'
        
        directories = set()
        files = []
        
        try:
            paginator = self.client.get_paginator('list_objects_v2')
            
            for page in paginator.paginate(Bucket=self._bucket_name, Prefix=path, Delimiter='/'):
                for prefix in page.get('CommonPrefixes', []):
                    dir_name = prefix['Prefix'][len(path):].rstrip('/')
                    if dir_name:
                        directories.add(dir_name)
                
                for obj in page.get('Contents', []):
                    file_name = obj['Key'][len(path):]
                    if file_name and '/' not in file_name:
                        files.append(file_name)
            
            return list(directories), files
        except Exception as e:
            logger.error(f"Failed to list directory '{path}': {str(e)}")
            return [], []
    
    def get_available_name(self, name, max_length=None):
        name = self._normalize_name(name)
        
        if self.exists(name):
            dir_name, file_name = os.path.split(name)
            file_root, file_ext = os.path.splitext(file_name)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            name = os.path.join(dir_name, f"{file_root}_{timestamp}{file_ext}")
            name = name.replace('\\', '/')
        
        return name


# Alias for backwards compatibility
CloudflareR2MediaStorage = CloudflareR2Storage