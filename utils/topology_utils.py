import ipaddress
from typing import List, Dict, Any

def build_device_map(subnets: List[Dict[str, Any]], devices: List[Dict[str, Any]]):
    """
    Returns a mapping: subnet_id -> list of devices in that subnet.
    Handles both TCP/IP and non-TCP/IP interfaces.
    """
    device_map = {subnet["_id"]: [] for subnet in subnets}
    device_lookup = {d["_id"]: d for d in devices}
    for device in devices:
        added_to_subnet = set()
        for iface in device.get("interfaces", []):
            if iface.get("interface_type") == "TCP/IP":
                subnet_id = iface.get("subnet")
                if subnet_id in device_map and subnet_id not in added_to_subnet:
                    device_map[subnet_id].append(device)
                    added_to_subnet.add(subnet_id)
            else:
                connected_id = iface.get("connected_to")
                if connected_id and connected_id in device_lookup:
                    connected_dev = device_lookup[connected_id]
                    for conn_iface in connected_dev.get("interfaces", []):
                        if conn_iface.get("subnet") and conn_iface.get("interface_type") == "TCP/IP":
                            subnet_id = conn_iface["subnet"]
                            if subnet_id in device_map and subnet_id not in added_to_subnet:
                                device_map[subnet_id].append(device)
                                added_to_subnet.add(subnet_id)
                                if "slave_of" not in device:
                                    device["slave_of"] = connected_id
    return device_map

def assign_subnets_to_interfaces(interfaces: List[Dict[str, Any]], subnets: List[Dict[str, Any]]):
    """
    Assigns subnet IDs to TCP/IP interfaces based on IP address and subnet CIDR.
    Modifies the interfaces list in place.
    """
    for iface in interfaces:
        if iface.get("interface_type") == "TCP/IP":
            if not iface.get("subnet") and iface.get("ip_address"):
                try:
                    ip_obj = ipaddress.ip_address(iface["ip_address"])
                    for subnet in subnets:
                        if "cidr" in subnet and ip_obj in ipaddress.ip_network(subnet["cidr"]):
                            iface["subnet"] = subnet["_id"]
                            break
                except Exception:
                    continue

def build_device_lookup(devices: List[Dict[str, Any]]):
    """
    Returns a mapping: device_id -> device dict
    """
    return {d["_id"]: d for d in devices} 