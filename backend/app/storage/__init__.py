from app.config import settings
from app.storage.base import BaseStorage
from app.storage.local import LocalStorage

_storage_instance = None


def get_storage() -> BaseStorage:
    global _storage_instance
    if _storage_instance is None:
        if settings.STORAGE_BACKEND == "s3" and settings.S3_BUCKET_NAME:
            from app.storage.s3 import S3Storage
            _storage_instance = S3Storage(
                bucket_name=settings.S3_BUCKET_NAME,
                endpoint_url=settings.S3_ENDPOINT_URL,
                access_key_id=settings.S3_ACCESS_KEY_ID,
                secret_access_key=settings.S3_SECRET_ACCESS_KEY,
                region_name=settings.S3_REGION_NAME
            )
        else:
            _storage_instance = LocalStorage(base_dir=settings.LOCAL_STORAGE_PATH)
    return _storage_instance
