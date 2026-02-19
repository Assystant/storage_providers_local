from storage_providers.registry import register_provider

from .provider import LocalStorageProvider

register_provider('local', LocalStorageProvider)
