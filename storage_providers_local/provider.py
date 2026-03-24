import logging
import os

from django.core.files.storage import FileSystemStorage
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from storage_providers.base import BaseStorageProvider
from storage_providers.exceptions import (StorageConnectionError,
                                          StorageDeleteError,
                                          StorageDownloadError,
                                          StorageFileNotFoundError,
                                          StoragePermissionError,
                                          StorageProviderError,
                                          StorageUploadError)

logger = logging.getLogger(__name__)


class LocalStorageProvider(BaseStorageProvider):
    """Local filesystem storage provider.

    Delegates all operations to Django's built-in FileSystemStorage,
    using the location and base_url from StorageConfig.

    self._client is None — no external connection needed.
    """

    def _connect(self):
        try:
            self._fs = FileSystemStorage(
                location=self.config.local_root,
                base_url=self.config.local_base_url,
            )
            logger.debug(
                'LocalStorageProvider ready | root=%s base_url=%s',
                self.config.local_root,
                self.config.local_base_url,
            )
            return None
        except Exception as exc:
            logger.error(
                'LocalStorageProvider failed to initialise | root=%s | %s: %s',
                self.config.local_root, type(exc).__name__, exc,
            )
            raise StorageConnectionError(
                f"Failed to initialise local storage at '{self.config.local_root}': {exc}"
            ) from exc

    def _save(self, name: str, content) -> str:
        try:
            saved_name = self._fs._save(name, content)
            logger.debug("Saved '%s' → '%s' | local storage", name, saved_name)
            return saved_name
        except PermissionError as exc:
            logger.error("Permission denied saving '%s' | local storage | %s", name, exc)
            raise StoragePermissionError(
                f"Permission denied writing '{name}' to local storage."
            ) from exc
        except OSError as exc:
            logger.error("OSError saving '%s' | local storage | %s: %s", name, type(exc).__name__, exc)
            raise StorageUploadError(
                f"Failed to write '{name}' to local storage: {exc}"
            ) from exc

    def download_file(self, name: str, mode: str = 'rb'):
        try:
            result = self._fs._open(name, mode)
            logger.debug("Opened '%s' (mode=%s) | local storage", name, mode)
            return result
        except FileNotFoundError as exc:
            logger.warning("File not found '%s' | local storage", name)
            raise StorageFileNotFoundError(
                f"File '{name}' not found in local storage."
            ) from exc
        except PermissionError as exc:
            logger.error("Permission denied reading '%s' | local storage | %s", name, exc)
            raise StoragePermissionError(
                f"Permission denied reading '{name}' from local storage."
            ) from exc
        except OSError as exc:
            logger.error("OSError reading '%s' | local storage | %s: %s", name, type(exc).__name__, exc)
            raise StorageDownloadError(
                f"Failed to open '{name}' from local storage: {exc}"
            ) from exc

    def delete(self, name: str) -> None:
        try:
            self._fs.delete(name)
            logger.debug("Deleted '%s' | local storage", name)
        except PermissionError as exc:
            logger.error("Permission denied deleting '%s' | local storage | %s", name, exc)
            raise StoragePermissionError(
                f"Permission denied deleting '{name}' from local storage."
            ) from exc
        except OSError as exc:
            logger.error("OSError deleting '%s' | local storage | %s: %s", name, type(exc).__name__, exc)
            raise StorageDeleteError(
                f"Failed to delete '{name}' from local storage: {exc}"
            ) from exc

    def exists(self, name: str) -> bool:
        try:
            return self._fs.exists(name)
        except OSError as exc:
            raise StorageProviderError(
                f"Failed to check existence of '{name}' in local storage: {exc}"
            ) from exc

    def url(self, name: str) -> str:
        try:
            return self._fs.url(name)
        except Exception as exc:
            raise StorageProviderError(
                f"Failed to resolve URL for '{name}' in local storage: {exc}"
            ) from exc

    def size(self, name: str) -> int:
        try:
            return self._fs.size(name)
        except FileNotFoundError as exc:
            raise StorageFileNotFoundError(
                f"File '{name}' not found in local storage."
            ) from exc
        except OSError as exc:
            raise StorageProviderError(
                f"Failed to get size of '{name}' in local storage: {exc}"
            ) from exc

    def generate_download_url(self, name: str, expires_in: int = 300) -> dict:
        signer = TimestampSigner()
        token = signer.sign(name)
        base_url = self._fs.url(name)
        url = f'{base_url}?token={token}'
        logger.debug("Generated signed download URL for '%s' | expires_in=%s", name, expires_in)
        return {'url': url, 'expires_in': expires_in}

    def verify_download_token(self, token: str, max_age: int = 300) -> str:
        signer = TimestampSigner()
        try:
            file_path = signer.unsign(token, max_age=max_age)
            logger.debug("Verified download token | file_path='%s'", file_path)
            return file_path
        except SignatureExpired:
            logger.warning('Download token expired | token=%s...', token[:20])
            raise StorageProviderError('Download token has expired.')
        except BadSignature:
            logger.warning('Invalid download token | token=%s...', token[:20])
            raise StorageProviderError('Invalid download token.')

    def upload_in_chunks(
        self,
        name: str,
        file_obj,
        chunk_size: int = 5 * 1024 * 1024,
        progress_callback=None,
    ) -> str:
        try:
            full_path = self._fs.path(name)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            total_size = getattr(file_obj, 'size', None)
            bytes_done = 0
            chunk_count = 0
            logger.debug(
                'Chunked upload started | name=%s size=%s chunk_size=%s path=%s',
                name, total_size, chunk_size, full_path,
            )
            with open(full_path, 'wb') as dest:
                while True:
                    chunk = file_obj.read(chunk_size)
                    if not chunk:
                        break
                    dest.write(chunk)
                    chunk_count += 1
                    bytes_done += len(chunk)
                    logger.debug(
                        'Wrote chunk %s | name=%s bytes_done=%s/%s',
                        chunk_count, name, bytes_done, total_size,
                    )
                    if progress_callback and total_size:
                        try:
                            progress_callback(bytes_done, total_size)
                        except Exception as cb_exc:
                            logger.debug(
                                'progress_callback error (ignored) | name=%s bytes_done=%s | %s: %s',
                                name, bytes_done, type(cb_exc).__name__, cb_exc,
                            )
            logger.debug(
                'Chunked upload complete | name=%s total_bytes=%s chunks=%s',
                name, bytes_done, chunk_count,
            )
            return name
        except PermissionError as exc:
            logger.error('Permission denied during chunked upload | name=%s | %s', name, exc)
            raise StoragePermissionError(
                f"Permission denied writing '{name}' to local storage."
            ) from exc
        except OSError as exc:
            logger.error(
                'OSError during chunked upload | name=%s | %s: %s', name, type(exc).__name__, exc,
            )
            raise StorageUploadError(
                f"Failed to write '{name}' to local storage during chunked upload: {exc}"
            ) from exc
