# Local experimental services

Run `bash Docker/start.sh` from the repository root; stop with
`bash Docker/stop.sh`. Docker Engine with the Compose plugin is required.
To start a subset, pass Compose service names to `start.sh`.

The configuration contains the paper's 113 implementation/configuration
variants (31 identification services, 32 mutation profiles). Memgraph and
PySNMP were unavailable during construction and require the explicit
`unavailable` profile; the default starts the other 111 configurations.
Ports bind only to loopback and are listed in `.env`; `services_config.py`
uses the same ports. Container credentials and domains are synthetic fixtures.
Image builds require network access. Service documents and deployment records
are not distributed. These build recipes preserve the selected configurations;
upstream package repositories may change their resolved versions.
