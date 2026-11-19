import socket
import sys
from typing import List, Dict, Any
from config import Config
from database.models import DatabaseManager

def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Detect available network interfaces across Windows, Linux, and macOS.
    Uses Scapy interface configuration and standard socket libraries.
    """
    interfaces = []
    
    try:
        from scapy.all import conf
        
        # Determine whether native pcap driver (wpcap.dll / libpcap) is present
        pcap_available = getattr(conf, 'use_pcap', False) and (
            hasattr(conf, 'L2listen') and 'NotAvailableSocket' not in str(conf.L2listen)
        )

        for iface_id, iface in conf.ifaces.items():
            name = getattr(iface, 'name', str(iface_id))
            desc = getattr(iface, 'description', name)
            ip = getattr(iface, 'ip', None) or '0.0.0.0'
            mac = getattr(iface, 'mac', None) or '00:00:00:00:00:00'
            guid = getattr(iface, 'guid', '')
            
            # Check loopback
            is_loopback = (
                'loopback' in name.lower() or 
                'loopback' in desc.lower() or 
                ip.startswith('127.')
            )
            
            # Determine if interface appears active (has valid non-apipa IPv4 or loopback)
            is_up = bool(ip and ip != '0.0.0.0' and not ip.startswith('169.254.')) or is_loopback
            
            interfaces.append({
                'id': str(iface_id),
                'name': name,
                'description': desc,
                'ip_address': ip,
                'mac_address': mac,
                'guid': guid,
                'is_up': is_up,
                'is_loopback': is_loopback,
                'pcap_available': pcap_available
            })
            
    except Exception as e:
        # Fallback to standard Python socket lookup if Scapy ifaces fails
        hostname = socket.gethostname()
        try:
            _, _, ip_list = socket.gethostbyname_ex(hostname)
        except Exception:
            ip_list = ['127.0.0.1']

        interfaces.append({
            'id': 'default',
            'name': 'Primary Network Interface',
            'description': f'Host {hostname} Default Interface',
            'ip_address': ip_list[0] if ip_list else '127.0.0.1',
            'mac_address': '00:00:00:00:00:00',
            'guid': '',
            'is_up': True,
            'is_loopback': False,
            'pcap_available': False
        })
        interfaces.append({
            'id': 'loopback',
            'name': 'Loopback Adapter',
            'description': 'Software Loopback Interface',
            'ip_address': '127.0.0.1',
            'mac_address': '00:00:00:00:00:00',
            'guid': '',
            'is_up': True,
            'is_loopback': True,
            'pcap_available': False
        })

    # Sort so active/up interfaces appear at the top
    interfaces.sort(key=lambda x: (not x['is_up'], x['is_loopback'], x['name']))

    # Cache into database
    try:
        DatabaseManager.save_interfaces(interfaces)
    except Exception:
        pass

    return interfaces

def get_system_capture_capabilities() -> Dict[str, Any]:
    """Inspect and return current host OS capture environment capabilities."""
    from scapy.all import conf
    
    pcap_available = getattr(conf, 'use_pcap', False) and (
        hasattr(conf, 'L2listen') and 'NotAvailableSocket' not in str(conf.L2listen)
    )
    
    return {
        'os': sys.platform,
        'pcap_driver_installed': pcap_available,
        'scapy_l3_socket': str(getattr(conf, 'L3socket', 'Unknown')),
        'offline_pcap_supported': True,
        'safe_mode': Config.CAPTURE_SAFE_MODE,
        'message': "Full Npcap driver ready" if pcap_available else "Npcap/WinPcap not detected. Raw socket / PCAP analysis mode active."
    }
