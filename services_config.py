"""Local service registry: 113 variants, 32 mutation profiles and 31 identification services. MQTT versions use separate mutation profiles and a shared identification label. Ports match Docker/.env. Each payload is tested against the complete available same-transport fleet."""

from typing import Dict, List

# Leave empty [] to fuzz all spec'd protocols.
# SERVICES_TO_FUZZ matches PROTOCOL SPEC names, not these config keys.
SERVICES_TO_FUZZ: List[str] = [
]

# Transport defaults
_TCP = "tcp"
_UDP = "udp"
_BOTH = "both"

SERVICES = {'memcached': {'host': '127.0.0.1', 'port': 24043},
 'redis': {'host': '127.0.0.1', 'port': 24078},
 'irc': {'host': '127.0.0.1', 'port': 24037},
 'mqttv311': {'host': '127.0.0.1', 'port': 24053},
 'mqttv50': {'host': '127.0.0.1', 'port': 24056},
 'dns': {'host': '127.0.0.1', 'port': 24014, 'protocol': 'both'},
 'ldap': {'host': '127.0.0.1', 'port': 24040},
 'http2': {'host': '127.0.0.1', 'port': 24022},
 'amqp': {'host': '127.0.0.1', 'port': 24000},
 'smb': {'host': '127.0.0.1', 'port': 24092},
 'rdp': {'host': '127.0.0.1', 'port': 24070},
 'modbus': {'host': '127.0.0.1', 'port': 24045},
 'rtsp': {'host': '127.0.0.1', 'port': 24085},
 'x11': {'host': '127.0.0.1', 'port': 24111},
 'bittorrentv10': {'host': '127.0.0.1', 'port': 24007},
 'mongodb': {'host': '127.0.0.1', 'port': 24049},
 'bolt': {'host': '127.0.0.1', 'port': 24004},
 'rethinkdb': {'host': '127.0.0.1', 'port': 24082},
 'ssh': {'host': '127.0.0.1', 'port': 24105},
 'ftp': {'host': '127.0.0.1', 'port': 24016},
 'telnet': {'host': '127.0.0.1', 'port': 24108},
 'http': {'host': '127.0.0.1', 'port': 24026},
 'pop3': {'host': '127.0.0.1', 'port': 24064},
 'imapv4': {'host': '127.0.0.1', 'port': 24033},
 'portmapv2': {'host': '127.0.0.1', 'port': 24066, 'protocol': 'both'},
 'ntpv4': {'host': '127.0.0.1', 'port': 24062, 'protocol': 'udp'},
 'snmp': {'host': '127.0.0.1', 'port': 24095, 'protocol': 'udp'},
 'ikev2': {'host': '127.0.0.1', 'port': 24030, 'protocol': 'both'},
 'socks5': {'host': '127.0.0.1', 'port': 24100},
 'l2tp': {'host': '127.0.0.1', 'port': 24039, 'protocol': 'udp'},
 'sip': {'host': '127.0.0.1', 'port': 24089, 'protocol': 'both'},
 'cwmp': {'host': '127.0.0.1', 'port': 24010},
 'ssh-dropbear': {'host': '127.0.0.1', 'port': 24102},
 'ssh-asyncssh': {'host': '127.0.0.1', 'port': 24101},
 'ssh-lsh': {'host': '127.0.0.1', 'port': 24103},
 'ssh-openssh-cfg': {'host': '127.0.0.1', 'port': 24104},
 'ftp-proftpd': {'host': '127.0.0.1', 'port': 24017},
 'ftp-pure-ftpd': {'host': '127.0.0.1', 'port': 24018},
 'ftp-pyftpd-cfg': {'host': '127.0.0.1', 'port': 24019},
 'http-apache': {'host': '127.0.0.1', 'port': 24023},
 'http-lighttpd': {'host': '127.0.0.1', 'port': 24025},
 'http-caddy': {'host': '127.0.0.1', 'port': 24024},
 'http-tengine': {'host': '127.0.0.1', 'port': 24027},
 'http2-caddy': {'host': '127.0.0.1', 'port': 24020},
 'http2-nghttpd': {'host': '127.0.0.1', 'port': 24021},
 'telnet-pytelnetd': {'host': '127.0.0.1', 'port': 24106},
 'telnet-inetd-telnetd': {'host': '127.0.0.1', 'port': 24107},
 'telnet-socat-telnetd': {'host': '127.0.0.1', 'port': 24109},
 'telnet-telnetlib3-cfg': {'host': '127.0.0.1', 'port': 24110},
 'dns-dnsmasq': {'host': '127.0.0.1', 'port': 24012, 'protocol': 'both'},
 'dns-unbound': {'host': '127.0.0.1', 'port': 24015, 'protocol': 'both'},
 'dns-knot': {'host': '127.0.0.1', 'port': 24013, 'protocol': 'both'},
 'dns-bind-auth': {'host': '127.0.0.1', 'port': 24011, 'protocol': 'both'},
 'irc-inspircd': {'host': '127.0.0.1', 'port': 24035},
 'irc-ircd-hybrid': {'host': '127.0.0.1', 'port': 24034},
 'irc-ngircd-cfg': {'host': '127.0.0.1', 'port': 24036},
 'mqtt-amqtt': {'host': '127.0.0.1', 'port': 24050},
 'mqtt-emqx-v311': {'host': '127.0.0.1', 'port': 24051},
 'mqtt-mosquitto-v311-cfg': {'host': '127.0.0.1', 'port': 24052},
 'mqtt-emqx-v50': {'host': '127.0.0.1', 'port': 24054},
 'mqtt-vernemq': {'host': '127.0.0.1', 'port': 24057},
 'mqtt-mosquitto-v50-cfg': {'host': '127.0.0.1', 'port': 24055},
 'redis-redis5': {'host': '127.0.0.1', 'port': 24072},
 'redis-redis6': {'host': '127.0.0.1', 'port': 24073},
 'redis-valkey': {'host': '127.0.0.1', 'port': 24079},
 'redis-keydb': {'host': '127.0.0.1', 'port': 24076},
 'redis-dragonfly': {'host': '127.0.0.1', 'port': 24075},
 'redis-redis-nopersist': {'host': '127.0.0.1', 'port': 24077},
 'redis-redis-config': {'host': '127.0.0.1', 'port': 24074},
 'memcached-memcached-nocas': {'host': '127.0.0.1', 'port': 24042},
 'memcached-memcached-binary': {'host': '127.0.0.1', 'port': 24041},
 'memcached-memcached-slab': {'host': '127.0.0.1', 'port': 24044},
 'modbus-pymodbus-cfg': {'host': '127.0.0.1', 'port': 24046},
 'smb-smb3-only': {'host': '127.0.0.1', 'port': 24093},
 'smb-smb-nosign': {'host': '127.0.0.1', 'port': 24091},
 'smb-smb-classic': {'host': '127.0.0.1', 'port': 24090},
 'rdp-xrdp-tls': {'host': '127.0.0.1', 'port': 24071},
 'rdp-xrdp-basic': {'host': '127.0.0.1', 'port': 24068},
 'rdp-xrdp-nla': {'host': '127.0.0.1', 'port': 24069},
 'amqp-rabbitmq-cfg': {'host': '127.0.0.1', 'port': 24001},
 'bolt-neo4j4': {'host': '127.0.0.1', 'port': 24003},
 'bolt-memgraph': {'host': '127.0.0.1', 'port': 24002},
 'rtsp-gstreamer': {'host': '127.0.0.1', 'port': 24083},
 'rtsp-mediamtx-cfg': {'host': '127.0.0.1', 'port': 24084},
 'x11-xorg': {'host': '127.0.0.1', 'port': 24112},
 'x11-xvnc': {'host': '127.0.0.1', 'port': 24113},
 'bittorrent-qbittorrent': {'host': '127.0.0.1', 'port': 24008},
 'bittorrent-deluge': {'host': '127.0.0.1', 'port': 24005},
 'mongodb-mongo5': {'host': '127.0.0.1', 'port': 24047},
 'mongodb-mongo6': {'host': '127.0.0.1', 'port': 24048},
 'rethinkdb-rethinkdb-23': {'host': '127.0.0.1', 'port': 24080},
 'rethinkdb-rethinkdb-config': {'host': '127.0.0.1', 'port': 24081},
 'pop3-dovecot-cfg': {'host': '127.0.0.1', 'port': 24063},
 'imap-dovecot-cfg': {'host': '127.0.0.1', 'port': 24032},
 'portmap-rpcbind-insecure': {'host': '127.0.0.1', 'port': 24065, 'protocol': 'both'},
 'portmap-rpcbind-warm': {'host': '127.0.0.1', 'port': 24067, 'protocol': 'both'},
 'socks-microsocks': {'host': '127.0.0.1', 'port': 24099},
 'socks-dante-cfg': {'host': '127.0.0.1', 'port': 24098},
 'cwmp-genieacs-cfg': {'host': '127.0.0.1', 'port': 24009},
 'ntp-ntpsec': {'host': '127.0.0.1', 'port': 24060, 'protocol': 'udp'},
 'ntp-openntpd': {'host': '127.0.0.1', 'port': 24061, 'protocol': 'udp'},
 'ntp-ntp-classic': {'host': '127.0.0.1', 'port': 24059, 'protocol': 'udp'},
 'ntp-chrony-cfg': {'host': '127.0.0.1', 'port': 24058, 'protocol': 'udp'},
 'snmp-pysnmp': {'host': '127.0.0.1', 'port': 24096, 'protocol': 'udp'},
 'snmp-netsnmp-cfg': {'host': '127.0.0.1', 'port': 24094, 'protocol': 'udp'},
 'snmp-netsnmp-v3': {'host': '127.0.0.1', 'port': 24097, 'protocol': 'udp'},
 'ike-libreswan': {'host': '127.0.0.1', 'port': 24028, 'protocol': 'both'},
 'ike-openiked': {'host': '127.0.0.1', 'port': 24029, 'protocol': 'both'},
 'ike-strongswan-v2only': {'host': '127.0.0.1', 'port': 24031, 'protocol': 'both'},
 'sip-asterisk': {'host': '127.0.0.1', 'port': 24086, 'protocol': 'both'},
 'sip-opensips': {'host': '127.0.0.1', 'port': 24088, 'protocol': 'both'},
 'sip-kamailio-cfg': {'host': '127.0.0.1', 'port': 24087, 'protocol': 'both'},
 'l2tp-xl2tpd-cfg': {'host': '127.0.0.1', 'port': 24038, 'protocol': 'udp'}}

# ============================================================================

# ============================================================================

#

#   ike-       → ikev2          ntp-     → ntpv4
#   portmap-   → portmapv2      bittorrent- → bittorrentv10
#   socks-     → socks5         imap-    → imapv4
import logging as _sc_logging
_sc_logger = _sc_logging.getLogger(__name__)

SERVICE_CLUSTERS = {'ssh': ['ssh', 'ssh-dropbear', 'ssh-lsh', 'ssh-openssh-cfg', 'ssh-asyncssh'],
 'telnet': ['telnet',
            'telnet-inetd-telnetd',
            'telnet-socat-telnetd',
            'telnet-pytelnetd',
            'telnet-telnetlib3-cfg'],
 'ftp': ['ftp', 'ftp-proftpd', 'ftp-pure-ftpd', 'ftp-pyftpd-cfg'],
 'http': ['http', 'http-apache', 'http-lighttpd', 'http-caddy', 'http-tengine'],
 'http2': ['http2', 'http2-caddy', 'http2-nghttpd'],
 'cwmp': ['cwmp', 'cwmp-genieacs-cfg'],
 'dns': ['dns', 'dns-dnsmasq', 'dns-unbound', 'dns-knot', 'dns-bind-auth'],
 'ldap': ['ldap'],
 'mqttv311': ['mqttv311', 'mqtt-amqtt', 'mqtt-emqx-v311', 'mqtt-mosquitto-v311-cfg'],
 'mqttv50': ['mqttv50', 'mqtt-emqx-v50', 'mqtt-vernemq', 'mqtt-mosquitto-v50-cfg'],
 'irc': ['irc', 'irc-inspircd', 'irc-ircd-hybrid', 'irc-ngircd-cfg'],
 'amqp': ['amqp', 'amqp-rabbitmq-cfg'],
 'redis': ['redis',
           'redis-redis5',
           'redis-redis6',
           'redis-valkey',
           'redis-keydb',
           'redis-dragonfly',
           'redis-redis-nopersist',
           'redis-redis-config'],
 'memcached': ['memcached',
               'memcached-memcached-nocas',
               'memcached-memcached-binary',
               'memcached-memcached-slab'],
 'mongodb': ['mongodb', 'mongodb-mongo5', 'mongodb-mongo6'],
 'rethinkdb': ['rethinkdb', 'rethinkdb-rethinkdb-23', 'rethinkdb-rethinkdb-config'],
 'bolt': ['bolt', 'bolt-neo4j4', 'bolt-memgraph'],
 'pop3': ['pop3', 'pop3-dovecot-cfg'],
 'imapv4': ['imapv4', 'imap-dovecot-cfg'],
 'modbus': ['modbus', 'modbus-pymodbus-cfg'],
 'smb': ['smb', 'smb-smb3-only', 'smb-smb-nosign', 'smb-smb-classic'],
 'rdp': ['rdp', 'rdp-xrdp-tls', 'rdp-xrdp-basic', 'rdp-xrdp-nla'],
 'x11': ['x11', 'x11-xorg', 'x11-xvnc'],
 'rtsp': ['rtsp', 'rtsp-gstreamer', 'rtsp-mediamtx-cfg'],
 'bittorrentv10': ['bittorrentv10', 'bittorrent-qbittorrent', 'bittorrent-deluge'],
 'portmapv2': ['portmapv2', 'portmap-rpcbind-insecure', 'portmap-rpcbind-warm'],
 'socks5': ['socks5', 'socks-microsocks', 'socks-dante-cfg'],
 'ntpv4': ['ntpv4', 'ntp-ntpsec', 'ntp-openntpd', 'ntp-ntp-classic', 'ntp-chrony-cfg'],
 'snmp': ['snmp', 'snmp-netsnmp-cfg', 'snmp-netsnmp-v3', 'snmp-pysnmp'],
 'ikev2': ['ikev2', 'ike-libreswan', 'ike-openiked', 'ike-strongswan-v2only'],
 'l2tp': ['l2tp', 'l2tp-xl2tpd-cfg'],
 'sip': ['sip', 'sip-asterisk', 'sip-opensips', 'sip-kamailio-cfg']}

_CLUSTER_OF: Dict[str, str] = {
    member: cluster
    for cluster, members in SERVICE_CLUSTERS.items()
    for member in members
}

def cluster_of(service_key: str) -> str:
    """Map an implementation key to its service, falling back to a singleton."""
    return _CLUSTER_OF.get(service_key, service_key)

# ---------------------------------------------------------------------------

#

# ---------------------------------------------------------------------------
IDENTIFICATION_CLUSTER_MERGE: Dict[str, str] = {
    "mqttv311": "mqtt",
    "mqttv50": "mqtt",
}

def identification_cluster_of(cluster: str) -> str:
    """Map a probe service to its canonical identification service."""
    return IDENTIFICATION_CLUSTER_MERGE.get(str(cluster), str(cluster))

def _build_identification_cluster_members() -> Dict[str, List[str]]:
    """Build candidate groups and reject dangling or cyclic identification mappings."""
    probe_clusters = set(SERVICE_CLUSTERS)
    for source, target in IDENTIFICATION_CLUSTER_MERGE.items():
        if source not in probe_clusters:
            raise ValueError(
                f"identification merge source {source!r} is not a probe cluster")
        if not target or target == source:
            raise ValueError(
                f"identification merge {source!r}->{target!r} is not a rename")
        if target in IDENTIFICATION_CLUSTER_MERGE:
            raise ValueError(
                f"identification merge target {target!r} is itself remapped; "
                "chains/cycles are forbidden")
    groups: Dict[str, List[str]] = {}
    for probe_cluster in sorted(probe_clusters):
        groups.setdefault(
            identification_cluster_of(probe_cluster), []).append(probe_cluster)
    return {cluster: members for cluster, members in sorted(groups.items())}

IDENTIFICATION_CLUSTER_MEMBERS: Dict[str, List[str]] = (
    _build_identification_cluster_members())

def identification_candidates(cluster: str) -> List[str]:
    """Return a deterministically sorted set of probe-service candidates."""
    canonical = identification_cluster_of(str(cluster))
    return list(IDENTIFICATION_CLUSTER_MEMBERS.get(canonical, [canonical]))

for _svc_key in SERVICES:
    if _svc_key not in _CLUSTER_OF:
        _sc_logger.warning(
            "services_config: %r is not declared in SERVICE_CLUSTERS; using a singleton; "
            "register it under its service.", _svc_key,
        )
