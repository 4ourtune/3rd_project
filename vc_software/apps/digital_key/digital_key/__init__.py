"""Core package for Raspberry Pi digital key prototype."""

from importlib import import_module
from typing import Any

_EXPORT_MAP = {
    "VehicleBleServer": (".vehicle_ble", "VehicleBleServer"),
    "detect_adapter": (".vehicle_ble", "detect_adapter"),
    "main": (".vehicle_ble", "main"),
    "PairingManager": (".pairing", "PairingManager"),
    "PairingApiClient": (".pairing_client", "PairingApiClient"),
    "PairingApiError": (".pairing_client", "PairingApiError"),
    "PairingSession": (".pairing_client", "PairingSession"),
    "build_client": (".pairing_client", "build_client"),
    "load_identity": (".identity", "load_identity"),
    "get_identity_value": (".identity", "get_identity_value"),
    "refresh_identity": (".identity", "refresh_identity"),
    "load_env_defaults": (".identity", "load_env_defaults"),
    "CertificateProvider": (".certificates", "CertificateProvider"),
    "StaticPemProvider": (".certificates", "StaticPemProvider"),
    "CertificatePayload": (".certificates", "CertificatePayload"),
    "build_static_provider_from_env": (".certificates", "build_static_provider_from_env"),
}

__all__ = list(_EXPORT_MAP.keys())


def __getattr__(name: str) -> Any:
    try:
        module_name, attr_name = _EXPORT_MAP[name]
    except KeyError as exc:  # pragma: no cover - mirrors default behaviour
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    module = import_module(module_name, __name__)
    return getattr(module, attr_name)


def __dir__() -> list[str]:  # pragma: no cover - minimal helper
    return sorted(set(globals().keys()) | set(__all__))
