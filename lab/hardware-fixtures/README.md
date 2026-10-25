# Hardware / switch fixtures (synthetic)

All data is synthetic and safe to publish: no real GPU/BMC/switch serial numbers,
no real credentials, no vendor-private configuration. The firmware signature uses
an HMAC fixture key to exercise the verification path only; production must use a
vendor asymmetric signature / PKI trust chain.

Regenerate with: `python lab/hardware-fixtures/build_fixtures.py`.
