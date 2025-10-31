"""Helpers for managing Proxmox device connection metadata."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Callable, Iterable, Set
from urllib.parse import urlparse

from homeassistant.const import CONF_HOST
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from homeassistant.helpers.typing import UNDEFINED, UndefinedType
from homeassistant.helpers.update_coordinator import UpdateFailed

from .const import CONF_IGNORE_WIFI, DOMAIN, LOGGER, ProxmoxType


def _normalize_mac(mac: str | None) -> str | None:
    """Normalize MAC string to lowercase colon-delimited form."""
    if not mac:
        return None
    mac = mac.strip().lower()
    parts = mac.split(":")
    if len(parts) == 6 and all(len(part) == 2 for part in parts):
        return mac
    return None


def _extract_qemu_mac(net_value: Any) -> tuple[str | None, str | None]:
    """Extract interface name and MAC from a QEMU net string."""
    if not isinstance(net_value, str):
        return (None, None)
    mac = None
    iface_name = None
    parts = [segment.strip() for segment in net_value.split(",")]
    if parts:
        first = parts[0]
        if "=" in first:
            _, potential_mac = first.split("=", 1)
            mac = potential_mac.strip()
    for part in parts[1:]:
        if part.startswith("name="):
            iface_name = part.split("=", 1)[1].strip()
            break
    return (iface_name, mac)


def _extract_lxc_mac(net_value: Any) -> tuple[str | None, str | None]:
    """Extract interface name and MAC from an LXC net string."""
    if not isinstance(net_value, str):
        return (None, None)
    mac = None
    iface_name = None
    for part in (segment.strip() for segment in net_value.split(",") if segment.strip()):
        if part.startswith("hwaddr="):
            mac = part.split("=", 1)[1].strip()
        elif part.startswith("name="):
            iface_name = part.split("=", 1)[1].strip()
    return (iface_name, mac)


def extract_qemu_mac_data(config: dict[str, Any]) -> tuple[dict[str, str], str | None]:
    """Return MAC mapping and primary MAC for a QEMU config payload."""
    mac_addresses: dict[str, str] = {}
    primary_mac: str | None = None

    for key in sorted(config):
        if not key.startswith("net"):
            continue
        iface_name, raw_mac = _extract_qemu_mac(config[key])
        mac = _normalize_mac(raw_mac)
        if not mac:
            continue
        if iface_name is None:
            iface_name = key
        mac_addresses[iface_name] = mac

    if mac_addresses:
        primary_mac = next(iter(mac_addresses.values()))
    return (mac_addresses, primary_mac)


def extract_lxc_mac_data(config: dict[str, Any]) -> tuple[dict[str, str], str | None]:
    """Return MAC mapping and primary MAC for an LXC config payload."""
    mac_addresses: dict[str, str] = {}
    primary_mac: str | None = None

    for key in sorted(config):
        if not key.startswith("net"):
            continue
        iface_name, raw_mac = _extract_lxc_mac(config[key])
        mac = _normalize_mac(raw_mac)
        if not mac:
            continue
        if iface_name is None:
            iface_name = key
        mac_addresses[iface_name] = mac

    if mac_addresses:
        primary_mac = next(iter(mac_addresses.values()))
    return (mac_addresses, primary_mac)


def _extract_node_mac(
    iface: dict[str, Any], iface_lookup: dict[str | None, dict[str, Any]] | None = None
) -> str | None:
    """Extract a MAC for a node interface, following bridge memberships."""
    candidates: list[str | None] = [
        iface.get("mac"),
        iface.get("hwaddr"),
        iface.get("address"),
    ]
    for alt in iface.get("altnames", []) or []:
        if isinstance(alt, str):
            normalized = _normalize_mac(alt)
            if normalized:
                candidates.append(normalized)
                continue
            if len(alt) == 15 and alt[:3] in {"wlx", "enx"}:
                raw = alt[3:]
                if all(ch in "0123456789abcdefABCDEF" for ch in raw):
                    formatted = ":".join(raw[i : i + 2] for i in range(0, 12, 2))
                    candidates.append(formatted.lower())
            elif len(alt) == 17 and alt[:3] in {"wlx", "enx"} and ":" in alt:
                candidates.append(alt[3:])

    if (
        iface_lookup
        and isinstance(iface.get("bridge_ports"), str)
        and (
            (iface.get("type") or "").lower() == "bridge"
            or (iface.get("iface") or "").startswith("vmbr")
        )
    ):
        for port in iface["bridge_ports"].split():
            port_iface = iface_lookup.get(port)
            if port_iface:
                port_mac = _extract_node_mac(port_iface, iface_lookup)
                if port_mac:
                    candidates.insert(0, port_mac)

    for candidate in candidates:
        normalized = _normalize_mac(candidate) if candidate else None
        if normalized:
            return normalized
    return None


def _interface_priority(iface: dict[str, Any]) -> int:
    """Return selection priority for interfaces (lower is better)."""
    iface_name = (iface.get("iface") or iface.get("name") or "").lower()
    iface_type = (iface.get("type") or "").lower()

    if iface_name.startswith(("en", "eth")) or iface_type in {"eth", "bond"}:
        return 0
    if iface_type == "bridge" or iface_name.startswith("vmbr"):
        return 3
    if iface_name.startswith(("wl", "wi")):
        return 4
    return 5


def _iface_is_wireless(iface: dict[str, Any]) -> bool:
    """Return True if interface appears to be wireless."""
    iface_name = (iface.get("iface") or iface.get("name") or "").lower()
    iface_type = (iface.get("type") or "").lower()
    if iface_name.startswith(("wl", "wi", "ath", "air", "wlan")):
        return True
    if iface_type in {"wireless", "wifi", "wlan"}:
        return True
    return False


def _iface_addresses(iface: dict[str, Any]) -> set[str]:
    """Return lowercase string addresses found on an interface entry."""
    addresses: set[str] = set()
    for key in ("address", "address6", "ip", "ip6"):
        value = iface.get(key)
        if isinstance(value, str):
            addr = value.strip().lower()
            if addr:
                addresses.add(addr)
    for key in ("cidr", "cidr6"):
        value = iface.get(key)
        if isinstance(value, str) and "/" in value:
            addr = value.split("/", 1)[0].strip().lower()
            if addr:
                addresses.add(addr)
    return addresses


def _iface_is_active(iface: dict[str, Any]) -> bool:
    """Return True if interface appears to be administratively up."""
    state = str(iface.get("state") or iface.get("status") or "").lower()
    if state in {"up", "active", "connected", "running"}:
        return True
    active_flag = iface.get("active")
    if isinstance(active_flag, bool):
        return active_flag
    if isinstance(active_flag, (int, float)):
        return active_flag != 0
    if isinstance(active_flag, str):
        return active_flag.strip().lower() in {"1", "true", "yes", "on"}
    return False


async def _async_host_addresses(hass, host: str) -> Set[str]:
    """Resolve host string into a set of lowercase addresses."""
    if not host:
        return set()

    host = host.strip()
    if not host:
        return set()

    parsed = urlparse(host)
    if parsed.scheme:
        hostname = parsed.hostname or host
    else:
        hostname = host

    hostname = hostname.strip("[]").strip()
    addresses: set[str] = set()

    try:
        ip_obj = ipaddress.ip_address(hostname)
        addresses.add(ip_obj.compressed.lower())
        return addresses
    except ValueError:
        pass

    # Host might be IPv6 with zone id (e.g. fe80::1%eth0)
    if "%" in hostname:
        without_zone = hostname.split("%", 1)[0]
        try:
            ip_obj = ipaddress.ip_address(without_zone)
            addresses.add(ip_obj.compressed.lower())
            return addresses
        except ValueError:
            hostname = without_zone

    try:
        infos = await hass.async_add_executor_job(
            socket.getaddrinfo,
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return set()

    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        addr = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(addr)
            addresses.add(ip_obj.compressed.lower())
        except ValueError:
            addresses.add(addr.lower())

    return addresses


def _host_matches_interface(host_addresses: Iterable[str], iface: dict[str, Any]) -> bool:
    """Return True if interface carries any of the configured host addresses."""
    normalized_host_addresses = {addr.lower() for addr in host_addresses if addr}
    if not normalized_host_addresses:
        return False
    iface_addresses = _iface_addresses(iface)
    return any(address in iface_addresses for address in normalized_host_addresses)


def _iface_category(host_addresses: Iterable[str], iface: dict[str, Any]) -> int:
    """Return category ranking (lower is better) for an interface."""
    is_wireless = _iface_is_wireless(iface)
    has_host = _host_matches_interface(host_addresses, iface)
    iface_name = (iface.get("iface") or iface.get("name") or "").lower()
    iface_type = (iface.get("type") or "").lower()
    has_ip = bool(_iface_addresses(iface))
    is_bridge = iface_type == "bridge" or iface_name.startswith("vmbr")
    is_physical = iface_name.startswith(("en", "eth")) or iface_type in {"eth", "bond"}

    if has_host and not is_wireless:
        base = 0
    elif is_bridge and has_ip:
        base = 1
    elif is_physical and has_ip:
        base = 2
    elif is_bridge:
        base = 3
    elif is_physical:
        base = 4
    elif has_ip:
        base = 5
    else:
        base = 6

    if is_wireless:
        # Strongly penalize wireless interfaces regardless of other traits.
        base += 10
        if has_host:
            base += 2

    return base


async def async_get_node_mac_data(
    hass,
    config_entry,
    proxmox,
    node_name: str,
    poller: Callable[..., Any],
) -> tuple[dict[str, str], str | None]:
    """Fetch node network data and return MAC mapping + primary."""
    network_status = await hass.async_add_executor_job(
        poller,
        hass,
        config_entry,
        proxmox,
        f"nodes/{node_name}/network",
        ProxmoxType.Node,
        node_name,
    )

    mac_addresses: dict[str, str] = {}
    primary_mac: str | None = None

    host_addresses = await _async_host_addresses(
        hass,
        str(config_entry.data.get(CONF_HOST, "")).strip(),
    )
    ignore_wifi = bool(
        config_entry.options.get(
            CONF_IGNORE_WIFI,
            config_entry.data.get(CONF_IGNORE_WIFI, True),
        )
    )

    if isinstance(network_status, list):
        iface_lookup = {
            (entry.get("iface") or entry.get("name")): entry
            for entry in network_status
            if isinstance(entry, dict)
        }
        iface_details_cache: dict[str, dict[str, Any] | None] = {}
        candidate_entries: list[dict[str, Any]] = []

        for iface in network_status:
            LOGGER.debug("Node %s network iface %s", node_name, iface)
            mac = _extract_node_mac(iface, iface_lookup)
            if not mac:
                iface_id = iface.get("iface") or iface.get("name")
                detail = None
                if iface_id and iface_id not in iface_details_cache:
                    detail_path = f"nodes/{node_name}/network/{iface_id}?current=1"
                    try:
                        detail = await hass.async_add_executor_job(
                            poller,
                            hass,
                            config_entry,
                            proxmox,
                            detail_path,
                            ProxmoxType.Node,
                            f"{node_name}_{iface_id}",
                            False,
                        )
                    except UpdateFailed:
                        detail = None
                    iface_details_cache[iface_id] = (
                        detail if isinstance(detail, dict) else None
                    )
                elif iface_id:
                    detail = iface_details_cache.get(iface_id)

                if detail:
                    LOGGER.debug(
                        "Node %s network iface detail %s: %s",
                        node_name,
                        iface_id,
                        detail,
                    )
                    iface.update(detail)
                    iface_lookup[iface_id] = iface
                    mac = _extract_node_mac(iface, iface_lookup)

            if not mac:
                continue
            iface_name = iface.get("iface") or iface.get("name") or mac
            iface_name_lower = iface_name.lower()
            iface_type = (iface.get("type") or "").lower()
            candidate_entries.append(
                {
                    "iface": iface.copy(),
                    "name": iface_name,
                    "name_lower": iface_name_lower,
                    "mac": mac,
                    "is_wireless": _iface_is_wireless(iface),
                    "has_host": _host_matches_interface(host_addresses, iface),
                    "is_active": _iface_is_active(iface),
                    "is_bridge": iface_type == "bridge" or iface_name_lower.startswith("vmbr"),
                    "is_physical": iface_name_lower.startswith(("en", "eth"))
                    or iface_type in {"eth", "bond"},
                    "priority": _interface_priority(iface),
                }
            )

        if candidate_entries:
            prioritized_set = candidate_entries
            if ignore_wifi:
                non_wifi = [entry for entry in candidate_entries if not entry["is_wireless"]]
                if non_wifi:
                    prioritized_set = non_wifi

            prioritized_set.sort(
                key=lambda entry: (
                    0 if entry["is_bridge"] else (1 if entry["is_physical"] else 2),
                    0 if entry["has_host"] else 1,
                    0 if entry["is_active"] else 1,
                    0 if not entry["is_wireless"] else 1,
                    entry["priority"],
                    entry["name_lower"],
                )
            )

            for entry in prioritized_set:
                LOGGER.debug(
                    "Node %s candidate iface %s (wireless=%s host=%s active=%s) -> %s",
                    node_name,
                    entry["name"],
                    entry["is_wireless"],
                    entry["has_host"],
                    entry["is_active"],
                    entry["mac"],
                )
                mac_addresses[entry["name"]] = entry["mac"]

            if prioritized_set:
                LOGGER.debug(
                    "Node %s primary selected MAC %s from %s",
                    node_name,
                    prioritized_set[0]["mac"],
                    prioritized_set[0]["name"],
                )
                primary_mac = prioritized_set[0]["mac"]
        elif mac_addresses:
            primary_mac = next(iter(mac_addresses.values()))
    else:
        LOGGER.debug(
            "Node %s network config unavailable or malformed: %s",
            node_name,
            network_status,
        )

    return (mac_addresses, primary_mac)


def connections_from_mac_data(
    mac_map: dict[str, str] | None, primary_mac: str | None
) -> set[tuple[str, str]] | None:
    """Build connection tuples from MAC mapping."""
    connections: set[tuple[str, str]] = set()
    if mac_map:
        for mac in mac_map.values():
            normalized = _normalize_mac(mac)
            if normalized:
                connections.add((CONNECTION_NETWORK_MAC, normalized))
    if not connections and primary_mac:
        normalized_primary = _normalize_mac(primary_mac)
        if normalized_primary:
            connections.add((CONNECTION_NETWORK_MAC, normalized_primary))
    return connections or None


def update_device_via(
    coordinator,
    api_category: ProxmoxType,
    node_name: str,
    connections: set[tuple[str, str]] | None = None,
) -> None:
    """Update HA device registry with connection information."""
    dev_reg = dr.async_get(coordinator.hass)
    identifier = (
        DOMAIN,
        f"{coordinator.config_entry.entry_id}_{api_category.upper()}_{coordinator.resource_id}",
    )

    device = dev_reg.async_get_device(identifiers={identifier})
    adopted_existing = False
    filtered_connections: set[tuple[str, str]] = set()
    original_device = device

    if connections:
        for connection in connections:
            existing = dev_reg.async_get_device(connections={connection})
            if existing and (device is None or existing.id != device.id):
                if not existing.identifiers:
                    LOGGER.debug(
                        "Skipping connection %s for %s due to existing device %s without identifiers",
                        connection,
                        coordinator.resource_id,
                        existing.id,
                    )
                    continue
                LOGGER.debug(
                    "Adopting existing device %s for %s via connection %s",
                    existing.id,
                    coordinator.resource_id,
                    connection,
                )
                device = existing
                adopted_existing = True
            filtered_connections.add(connection)

    if (
        adopted_existing
        and original_device
        and device
        and original_device.id != device.id
        and original_device.config_entries == {coordinator.config_entry.entry_id}
    ):
        LOGGER.debug(
            "Removing duplicate device %s after adopting %s for %s",
            original_device.id,
            device.id,
            coordinator.resource_id,
        )
        dev_reg.async_remove_device(original_device.id)

    if device is None:
        device = dev_reg.async_get_or_create(
            config_entry_id=coordinator.config_entry.entry_id,
            identifiers={identifier},
            entry_type=dr.DeviceEntryType.SERVICE,
        )
    elif identifier not in device.identifiers:
        dev_reg.async_update_device(
            device.id,
            new_identifiers=device.identifiers | {identifier},
            add_config_entry_id=coordinator.config_entry.entry_id,
        )

    via_identifier = (
        DOMAIN,
        f"{coordinator.config_entry.entry_id}_{ProxmoxType.Node.upper()}_{node_name}",
    )
    via_device = dev_reg.async_get_device(identifiers={via_identifier})
    if via_device is None and node_name is not None:
        via_device = dev_reg.async_get_or_create(
            config_entry_id=coordinator.config_entry.entry_id,
            identifiers={via_identifier},
            entry_type=dr.DeviceEntryType.SERVICE,
        )

    via_device_id: str | UndefinedType = via_device.id if via_device else UNDEFINED

    update_kwargs: dict[str, Any] = {
        "via_device_id": via_device_id,
        "entry_type": dr.DeviceEntryType.SERVICE,
    }

    current_connections = set(device.connections or set())
    new_connections_set: set[tuple[str, str]] | None = None

    if filtered_connections:
        new_connections_set = filtered_connections | current_connections
        update_kwargs["new_connections"] = new_connections_set

    if (
        device.via_device_id != via_device_id
        or (new_connections_set is not None and current_connections != new_connections_set)
        or adopted_existing
    ):
        LOGGER.debug(
            "Update device %s - via: old=%s new=%s, connections=%s",
            coordinator.resource_id,
            device.via_device_id,
            via_device_id,
            new_connections_set,
        )
        dev_reg.async_update_device(device.id, **update_kwargs)
