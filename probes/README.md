# Released probe sequences

`selected_tcp.json` / `selected_udp.json` contain the original ranked eight TCP
and three UDP payloads. The `.hex` files contain the same bytes in the same order.
`local_responses_*.json` retain distinct local observations for those payloads,
including banner/post-send phase and implementation labels. Repeated original
records may contribute different responses; this is not a new measurement.

Out-of-scope service responses, endpoint metadata and experiment provenance
paths are omitted. Embedded private IPv4 addresses and container identifiers
were masked in place with equal-length bytes. Every change is listed by field,
offset and length in `redactions`; original values are not included. Protocol
lengths and offsets are preserved. Sanitized samples must not be presented as
byte-for-byte original measurements or an independent accuracy dataset.
