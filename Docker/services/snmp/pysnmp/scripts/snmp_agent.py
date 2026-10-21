#!/usr/bin/env python3
"""SNMP command responder built on PySNMP's standard engine API.

PySNMP is a mature SNMP implementation; this only wires up its standard
command-responder classes (the engine ID format and default sysDescr differ
from Net-SNMP, which is the point of this variant).
"""

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncore.dgram import udp

snmpEngine = engine.SnmpEngine()

config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode(("0.0.0.0", 161)),
)

# SNMPv1 + v2c community "public".
config.addV1System(snmpEngine, "my-area", "public")

# Allow read access to the whole tree for v1 and v2c.
config.addVacmUser(snmpEngine, 1, "my-area", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))
config.addVacmUser(snmpEngine, 2, "my-area", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))

snmpContext = context.SnmpContext(snmpEngine)

cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

snmpEngine.transportDispatcher.jobStarted(1)
print("PySNMP agent listening on 0.0.0.0:161/udp", flush=True)
try:
    snmpEngine.transportDispatcher.runDispatcher()
except Exception:
    snmpEngine.transportDispatcher.closeDispatcher()
    raise
