"""Utilities for extracting MAC data and applying them to HA devices."""

from __future__ import annotations

from typing import Any, Iterable

from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC

from .const import LOGGER


def _normalize_mac(raw: str | None) -> str | None:
    """Return a normalized colon-delimited lower-case MAC address."""
    if not raw:
        return None
    candidate = raw.strip().lower()
    if not candidate:
        return None
    if ":" in candidate:
        parts = candidate.split(":")
        if len(parts) == 6 and all(len(part) == 2 for part in parts):
            return ":".join(parts)
        return None
    if len(candidate) == 12 and all(ch in "0123456789abcdef" for ch in candidate):
        return ":".join(candidate[i : i + 2] for i in range(0, 12, 2))
    return None


def _is_wireless(iface: dict[str, Any]) -> bool:
    """Best effort wireless interface detection."""
    name = str(iface.get("iface") or iface.get("name") or "").lower()
    iface_type = str(iface.get("type") or "").lower()
    prefixes = ("wl", "wi", "ath", "air", "wlan")
    return name.startswith(prefixes) or iface_type in {"wireless", "wifi", "wlan"}


def _candidate_mac_values(iface: dict[str, Any]) -> Iterable[str | None]:
    """Yield potential MAC values from an interface entry."""
    yield iface.get("mac")
    yield iface.get("hwaddr")
    options = iface.get("options")
    if isinstance(options, (list, tuple)):
        for option in options:
            if not isinstance(option, str):
                continue
            lower = option.lower()
            if lower.startswith("hwaddr") or lower.startswith("hwaddress"):
                if "=" in option:
                    _, value = option.split("=", 1)
                    yield value.strip()
                else:
                    segments = option.split()
                    if segments:
                        yield segments[-1]


def extract_qemu_mac_data(config: dict[str, Any]) -> tuple[dict[str, str], str | None]:
    """Extract interface->MAC mapping from a QEMU config payload."""
    macs: dict[str, str] = {}
    for key, value in config.items():
        if not key.startswith("net") or not isinstance(value, str):
            continue
        entries = [segment.strip() for segment in value.split(",") if segment.strip()]
        mac = None
        name = None
        for segment in entries:
            if segment.startswith("hwaddr="):
                mac = segment.split("=", 1)[1]
            elif segment.startswith("name="):
                name = segment.split("=", 1)[1]
            elif "=" not in segment and mac is None:
                mac = segment
        normalized = _normalize_mac(mac)
        if not normalized:
            continue
        iface_name = name or key
        macs[iface_name] = normalized
    primary = next(iter(macs.values()), None)
    return (macs, primary)


def extract_lxc_mac_data(config: dict[str, Any]) -> tuple[dict[str, str], str | None]:
    """Extract interface->MAC mapping from an LXC config payload."""
    macs: dict[str, str] = {}
    for key, value in config.items():
        if not key.startswith("net") or not isinstance(value, str):
            continue
        entries = [segment.strip() for segment in value.split(",") if segment.strip()]
        mac = None
        name = None
        for segment in entries:
            if segment.startswith("hwaddr="):
                mac = segment.split("=", 1)[1]
            elif segment.startswith("name="):
                name = segment.split("=", 1)[1]
        normalized = _normalize_mac(mac)
        if not normalized:
            continue
        iface_name = name or key
        macs[iface_name] = normalized
    primary = next(iter(macs.values()), None)
    return (macs, primary)


def extract_node_mac_data(payload: Any) -> tuple[dict[str, str], str | None]:
    """Extract MAC information from node network payload."""
    if not isinstance(payload, list):
        LOGGER.debug("Node network payload unexpected: %s", payload)
        return ({}, None)

    candidates: list[tuple[int, str, str]] = []
    for iface in payload:
        if not isinstance(iface, dict):
            continue
        iface_name = str(iface.get("iface") or iface.get("name") or "").strip()
        if not iface_name:
            continue
        mac = next(
            (_normalize_mac(value) for value in _candidate_mac_values(iface)
             if _normalize_mac(value)),
            None,
        )
        if not mac:
            continue
        is_bridge = iface_name.lower().startswith("vmbr") or str(iface.get("type") or "").lower() == "bridge"
        score = 0 if is_bridge else (2 if _is_wireless(iface) else 1)
        candidates.append((score, iface_name, mac))

    if not candidates:
        return ({}, None)

    candidates.sort(key=lambda item: (item[0], item[1].lower()))
    macs = {name: mac for _, name, mac in candidates}
    primary = candidates[0][2]
    return (macs, primary)


def connections_from_mac_data(
    mac_map: dict[str, str] | None,
    primary_mac: str | None,
) -> set[tuple[str, str]] | None:
    """Build Home Assistant connection tuples for the provided MAC data."""
    connections: set[tuple[str, str]] = set()
    for mac in (mac_map or {}).values():
        normalized = _normalize_mac(mac)
        if normalized:
            connections.add((CONNECTION_NETWORK_MAC, normalized))
    if not connections and primary_mac:
        normalized_primary = _normalize_mac(primary_mac)
        if normalized_primary:
            connections.add((CONNECTION_NETWORK_MAC, normalized_primary))
    return connections or None


def update_device_connections(
    dev_reg: dr.DeviceRegistry,
    config_entry_id: str,
    identifier: tuple[str, str],
    via_identifier: tuple[str, str] | None,
    connections: set[tuple[str, str]] | None,
) -> None:
    """Ensure the device registry entry carries the provided connections."""
    device = dev_reg.async_get_device(identifiers={identifier})
    original_device = device
    adopted_existing = False

    normalized_connections: set[tuple[str, str]] = set()
    if connections:
        for connection in connections:
            normalized_connections.add(connection)
            existing = dev_reg.async_get_device(connections={connection})
            if existing and (device is None or existing.id != device.id):
                if not existing.identifiers and not existing.config_entries:
                    LOGGER.debug(
                        "Ignoring connection %s due to orphan device %s",
                        connection,
                        existing.id,
                    )
                    continue
                LOGGER.debug(
                    "Adopting existing device %s for identifier %s via connection %s",
                    existing.id,
                    identifier,
                    connection,
                )
                device = existing
                adopted_existing = True

    if device is None:
        device = dev_reg.async_get_or_create(
            config_entry_id=config_entry_id,
            identifiers={identifier},
            entry_type=dr.DeviceEntryType.SERVICE,
        )
    elif identifier not in device.identifiers:
        dev_reg.async_update_device(
            device.id,
            new_identifiers=device.identifiers | {identifier},
            add_config_entry_id=config_entry_id,
        )
    elif config_entry_id not in device.config_entries:
        dev_reg.async_update_device(
            device.id,
            add_config_entry_id=config_entry_id,
        )

    if (
        adopted_existing
        and original_device
        and original_device.id != device.id
        and original_device.config_entries == {config_entry_id}
    ):
        LOGGER.debug(
            "Removing duplicate device %s after adopting %s",
            original_device.id,
            device.id,
        )
        dev_reg.async_remove_device(original_device.id)

    via_device_id = None
    if via_identifier is not None:
        via_device = dev_reg.async_get_device(identifiers={via_identifier})
        if via_device is None:
            via_device = dev_reg.async_get_or_create(
                config_entry_id=config_entry_id,
                identifiers={via_identifier},
                entry_type=dr.DeviceEntryType.SERVICE,
            )
        via_device_id = via_device.id

    update_kwargs: dict[str, Any] = {}

    if via_device_id is not None and device.via_device_id != via_device_id:
        update_kwargs["via_device_id"] = via_device_id

    if normalized_connections:
        current = set(device.connections or set())
        combined = current.union(normalized_connections)
        if combined != current:
            update_kwargs["new_connections"] = combined

    if update_kwargs:
        update_kwargs["entry_type"] = dr.DeviceEntryType.SERVICE
        LOGGER.debug(
            "Updating device %s connections=%s via=%s",
            identifier,
            normalized_connections or connections,
            via_device_id,
        )
        dev_reg.async_update_device(device.id, **update_kwargs)
