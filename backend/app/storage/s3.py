import os
import hashlib
from typing import Tuple
from fastapi import UploadFile
from app.storage.base import BaseStorage

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


class S3Storage(BaseStorage):
    def __init__(
        self,
        bucket_name: str,
        endpoint_url: str = None,
        access_key_id: str = None,
        secret_access_key: str = None,
        region_name: str = "us-east-1",
        cache_dir: str = "./storage_data/s3_cache"
    ):
        if not BOTO3_AVAILABLE:
            raise ImportError("boto3 is required for S3Storage backend.")
        self.bucket_name = bucket_name
        self.cache_dir = os.path.abspath(cache_dir)
        os.makedirs(self.cache_dir, exist_ok=True)

        session = boto3.session.Session()
        self.s3_client = session.client(
            service_name="s3",
            endpoint_url=endpoint_url or None,
            aws_access_key_id=access_key_id or None,
            aws_secret_access_key=secret_access_key or None,
            region_name=region_name
        )

    async def save_stream(self, file: UploadFile, key: str, max_bytes: int) -> Tuple[int, str]:
        # Stage locally first to compute hash and enforce limits safely
        temp_path = os.path.join(self.cache_dir, f"temp_{os.path.basename(key)}")
        sha256 = hashlib.sha256()
        total_bytes = 0
        chunk_size = 64 * 1024

        try:
            with open(temp_path, "wb") as f:
                while True:
                    chunk = await file.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > max_bytes:
                        raise ValueError(f"Uploaded file exceeds maximum allowed limit of {max_bytes} bytes.")
                    sha256.update(chunk)
                    f.write(chunk)

            if total_bytes == 0:
                raise ValueError("Uploaded file is empty (0 bytes).")

            # Upload to S3
            with open(temp_path, "rb") as f:
                self.s3_client.upload_fileobj(f, self.bucket_name, key)

            # Move temp file to persistent cache key path
            cached_path = os.path.join(self.cache_dir, key)
            os.makedirs(os.path.dirname(cached_path), exist_ok=True)
            if os.path.exists(cached_path):
                os.remove(cached_path)
            os.rename(temp_path, cached_path)

            return total_bytes, sha256.hexdigest()

        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    def get_local_path(self, key: str) -> str:
        cached_path = os.path.join(self.cache_dir, key)
        if os.path.exists(cached_path):
            return cached_path
        os.makedirs(os.path.dirname(cached_path), exist_ok=True)
        self.s3_client.download_file(self.bucket_name, key, cached_path)
        return cached_path

    async def delete(self, key: str) -> bool:
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=key)
            cached_path = os.path.join(self.cache_dir, key)
            if os.path.exists(cached_path):
                os.remove(cached_path)
            return True
        except Exception:
            return False

    def check_ready(self) -> bool:
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            return True
        except Exception:
            return False
