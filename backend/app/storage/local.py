import os
import hashlib
from typing import Tuple
from fastapi import UploadFile
from app.storage.base import BaseStorage


class LocalStorage(BaseStorage):
    def __init__(self, base_dir: str):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def _resolve_path(self, key: str) -> str:
        # Sanitize and ensure path stays within base_dir
        clean_key = os.path.normpath(key).lstrip("/\\")
        full_path = os.path.abspath(os.path.join(self.base_dir, clean_key))
        if not full_path.startswith(self.base_dir):
            raise ValueError(f"Illegal storage key access outside base directory: {key}")
        return full_path

    async def save_stream(self, file: UploadFile, key: str, max_bytes: int) -> Tuple[int, str]:
        target_path = self._resolve_path(key)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        sha256 = hashlib.sha256()
        total_bytes = 0
        chunk_size = 64 * 1024  # 64 KB streaming chunks

        try:
            with open(target_path, "wb") as f:
                while True:
                    chunk = await file.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > max_bytes:
                        raise ValueError(f"Uploaded file exceeds maximum allowed limit of {max_bytes} bytes.")
                    sha256.update(chunk)
                    f.write(chunk)
        except Exception:
            # Clean up partial file on failure
            if os.path.exists(target_path):
                try:
                    os.remove(target_path)
                except OSError:
                    pass
            raise

        if total_bytes == 0:
            if os.path.exists(target_path):
                os.remove(target_path)
            raise ValueError("Uploaded file is empty (0 bytes).")

        return total_bytes, sha256.hexdigest()

    def get_local_path(self, key: str) -> str:
        path = self._resolve_path(key)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Stored file does not exist: {key}")
        return path

    async def delete(self, key: str) -> bool:
        try:
            path = self._resolve_path(key)
            if os.path.exists(path):
                os.remove(path)
                return True
            return False
        except Exception:
            return False

    def check_ready(self) -> bool:
        try:
            os.makedirs(self.base_dir, exist_ok=True)
            test_file = os.path.join(self.base_dir, ".health_check")
            with open(test_file, "w") as f:
                f.write("ok")
            os.remove(test_file)
            return True
        except Exception:
            return False
