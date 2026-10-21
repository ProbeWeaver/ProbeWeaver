# Bounded profile contract

A `UnifiedProtocolSpec` describes one bounded request or initial exchange,
not a full protocol parser. Required metadata: `name`, `default_port`,
`transport`, `profile_version`, `source_refs`, `profile_scope`, and `fields`.
Public class names are compatibility names, not protocol-version evidence.
The source catalog establishes identity and checks document hashes. Candidate
admission interprets a restricted AST rather than executing candidate code.
Only allowed constructors and bounded byte expressions are accepted.

`expected_values[0]` is the baseline. Other positive values must remain valid
within the same fixed layout. `negative_values` are deliberate invalid test
inputs. F/I helpers add same-width zero/FF negatives excluding positive overlap;
these are generic fuzz inputs, not values claimed by a source document.
Every value must exactly match its field width. A short write is not a dynamic
string; a long write overwrites later fields. Counts are not inferred from byte
length. Use a separate profile when flags, versions or list sizes change layout.
State-changing commands require explicit authorization in a controlled setting.

Combine bitfields sharing a byte. Specify binary endianness per field and use
`binary`, `ascii_decimal`, `ber` or `mqtt_varint` length codecs as appropriate.
`length_mask` preserves flags such as the RPC final-fragment bit. BER and MQTT
encodings have a fixed width in these profiles; overflow fails instead of moving
field anchors. Blocks have unique names, explicit boundaries and correct nesting.
Do not manually supply LENGTH/CHECKSUM candidates. Selected lengths receive
incorrect same-width values; unselected lengths are repaired. Checksums are
always repaired and never enter the bandit. Empty blocks may exist; ordinary
zero-length fields may not. Nominal block lengths do not imply arbitrary dynamic
mutation repair.

Choose TCP/UDP framing once with `spec.for_transport()`, at generation time.
Never customize the same payload for each receiving service. Both-transport
profiles default to UDP: DNS/TCP adds a two-byte length excluding itself;
Portmap/TCP adds a four-byte record marker; IKE/TCP adds IKETCP, a two-byte
inclusive length and a non-ESP marker. SIP Via reflects the transport. Verify
IKE/TCP server support and port separately; do not assume TCP/500.

SSH, Telnet and Bolt cover initial exchanges. CWMP requires session context;
AMQP 1.0 does not mean AMQP 0-9-1; cleartext HTTP/2 is not a TLS handshake.
BitTorrent needs the test swarm's info_hash. Deterministic IKE nonce/DH fixtures
are for format testing, not secure sessions.

The independent wire parser does not derive its expected headers from the field
table. It detects many self-consistent layout mistakes, but is not a formal
standards proof. Inspect original sources and counterexamples. Single-field
passes do not establish all multi-field combinations. These tests send no network
traffic. Changed profile digests invalidate old posterior/calibration assumptions;
use fresh state and output paths rather than changing frozen historical results.
