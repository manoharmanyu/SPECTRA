from abc import ABC, abstractmethod
from typing import Tuple
from fastapi import UploadFile


class BaseStorage(ABC):
    @abstractmethod
    async def save_stream(self, file: UploadFile, key: str, max_bytes: int) -> Tuple[int, str]:
        """
        Stream uploaded file into storage without loading entire file into memory.
        Returns: (size_bytes, sha256_hex)
        Raises ValueError if file exceeds max_bytes or is empty.
        """
        pass

    @abstractmethod
    def get_local_path(self, key: str) -> str:
        """
        Return a local accessible filesystem path for inspection tools (exiftool, ffprobe).
        """
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """
        Delete stored file by key.
        """
        pass

    @abstractmethod
    def check_ready(self) -> bool:
        """
        Check if storage backend is accessible and writable.
        """
        pass
