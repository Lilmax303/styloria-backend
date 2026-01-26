# core/storage_backends.py

"""
Custom storage backend for Cloudflare R2.
Uses requests library with AWS4Auth to completely bypass boto3's
problematic region detection that causes infinite loops.
"""

import os
import logging
import mimetypes
import hashlib
from io import BytesIO
from datetime import datetime
from urllib.parse import quote

from django.conf import settings
from django.core.files.base import File
from django.core.files.storage import Storage
from django.utils.deconstruct import deconstructible

import requests
from requests_aws4auth import AWS4Auth

logger = logging.getLogger(__name__)


@deconstructible
class CloudflareR2Storage(Storage):
    """
    Storage backend for Cloudflare R2 using requests + AWS4Auth.
    Completely bypasses boto3 to avoid region detection issues.
    """
    
    def __init__(self, **kwargs):
        self._bucket_name = kwargs.get('bucket_name') or getattr(settings, 'AWS_STORAGE_BUCKET_NAME', '')
        self._endpoint_url = kwargs.get('endpoint_url') or getattr(settings, 'AWS_S3_ENDPOINT_URL', '')
        self._access_key = kwargs.get('access_key') or getattr(settings, 'AWS_ACCESS_KEY_ID', '')
        self._secret_key = kwargs.get('secret_key') or getattr(settings, 'AWS_SECRET_ACCESS_KEY', '')
        self._custom_domain = kwargs.get('custom_domain') or getattr(settings, 'AWS_S3_CUSTOM_DOMAIN', '')
        self._querystring_auth = kwargs.get('querystring_auth', getattr(settings, 'AWS_QUERYSTRING_AUTH', True))
        
        # Ensure HTTPS
        if self._endpoint_url.startswith('http://'):
            self._endpoint_url = self._endpoint_url.replace('http://', 'https://')
            logger.warning(f"Changed R2 endpoint from http to https: {self._endpoint_url}")
        
        # Get cache control from settings
        obj_params = getattr(settings, 'AWS_S3_OBJECT_PARAMETERS', {})
        self._cache_control = obj_params.get('CacheControl') if obj_params else None
        
        # Create AWS4Auth for signing requests
        self._auth = AWS4Auth(
            self._access_key,
            self._secret_key,
            'auto',  # region
            's3',    # service
        )
        
        logger.info(f"CloudflareR2Storage initialized: bucket={self._bucket_name}, endpoint={self._endpoint_url}")
    
    def _get_object_url(self, name):
        """Get the full URL for an object."""
        name = self._normalize_name(name)
        return f"{self._endpoint_url}/{self._bucket_name}/{quote(name, safe='/')}"
    
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
        """Save file to R2 using requests."""
        name = self._normalize_name(name)
        url = self._get_object_url(name)
        
        logger.info(f"CloudflareR2Storage._save: name={name}, url={url}")
        
        # Read the content
        content.seek(0)
        data = content.read()
        
        logger.info(f"CloudflareR2Storage._save: read {len(data)} bytes")
        
        # Prepare headers
        content_type = getattr(content, 'content_type', None)
        if not content_type:
            content_type = self._get_content_type(name)
        
        headers = {
            'Content-Type': content_type,
            'Content-Length': str(len(data)),
        }
        
        if self._cache_control:
            headers['Cache-Control'] = self._cache_control
        
        # Calculate content hash for AWS4 signing
        content_hash = hashlib.sha256(data).hexdigest()
        headers['x-amz-content-sha256'] = content_hash
        
        try:
            response = requests.put(
                url,
                data=data,
                headers=headers,
                auth=self._auth,
                timeout=60,
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"Successfully uploaded '{name}' to R2 bucket '{self._bucket_name}'")
                return name
            else:
                logger.error(f"Failed to upload '{name}' to R2: {response.status_code} - {response.text}")
                raise Exception(f"R2 upload failed: {response.status_code} - {response.text}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for '{name}': {type(e).__name__}: {str(e)}")
            raise
    
    def _open(self, name, mode='rb'):
        """Open a file from R2."""
        name = self._normalize_name(name)
        url = self._get_object_url(name)
        
        try:
            response = requests.get(
                url,
                auth=self._auth,
                timeout=60,
            )
            
            if response.status_code == 200:
                file_obj = BytesIO(response.content)
                file_obj.name = name
                return File(file_obj)
            else:
                raise Exception(f"Failed to open file: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to open '{name}' from R2: {type(e).__name__}: {str(e)}")
            raise
    
    def delete(self, name):
        """Delete a file from R2."""
        name = self._normalize_name(name)
        url = self._get_object_url(name)
        
        try:
            response = requests.delete(
                url,
                auth=self._auth,
                timeout=30,
            )
            
            if response.status_code in [200, 204]:
                logger.info(f"Successfully deleted '{name}' from R2")
            else:
                logger.error(f"Failed to delete '{name}': {response.status_code} - {response.text}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to delete '{name}' from R2: {type(e).__name__}: {str(e)}")
            raise
    
    def exists(self, name):
        """Check if a file exists in R2."""
        name = self._normalize_name(name)
        url = self._get_object_url(name)
        
        try:
            response = requests.head(
                url,
                auth=self._auth,
                timeout=10,
            )
            return response.status_code == 200
        except Exception:
            return False
    
    def size(self, name):
        """Return the size of a file."""
        name = self._normalize_name(name)
        url = self._get_object_url(name)
        
        try:
            response = requests.head(
                url,
                auth=self._auth,
                timeout=10,
            )
            if response.status_code == 200:
                return int(response.headers.get('Content-Length', 0))
        except Exception:
            pass
        return 0
    
    def url(self, name):
        """Return the URL of a file."""
        name = self._normalize_name(name)
        
        # If custom domain is set, use it (public URL)
        if self._custom_domain:
            return f"https://{self._custom_domain}/{name}"
        
        # For R2, we need to use the public bucket URL or generate a signed URL
        # Since R2 doesn't support pre-signed URLs the same way, use public URL
        public_domain = getattr(settings, 'R2_PUBLIC_DOMAIN', None)
        if public_domain:
            return f"https://{public_domain}/{name}"
        
        # Fallback - this won't work publicly without proper R2 public access setup
        return f"{self._endpoint_url}/{self._bucket_name}/{name}"
    
    def get_accessed_time(self, name):
        return self.get_modified_time(name)
    
    def get_created_time(self, name):
        return self.get_modified_time(name)
    
    def get_modified_time(self, name):
        name = self._normalize_name(name)
        url = self._get_object_url(name)
        
        try:
            response = requests.head(
                url,
                auth=self._auth,
                timeout=10,
            )
            if response.status_code == 200:
                from email.utils import parsedate_to_datetime
                last_modified = response.headers.get('Last-Modified')
                if last_modified:
                    return parsedate_to_datetime(last_modified)
        except Exception:
            pass
        return datetime.now()
    
    def listdir(self, path=''):
        """List directory contents - simplified implementation."""
        # R2 list operations would require XML parsing
        # For now, return empty
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