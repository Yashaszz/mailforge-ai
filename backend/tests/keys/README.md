# Test keys

A throwaway 2048-bit RSA keypair used **only** by the DKIM unit tests.

`conftest.py` signs a message with `dkim_test_private.pem` and serves
`dkim_test_public.b64` through a stub resolver, so `dkimpy` performs a real
signature verification without any DNS access.

This key signs nothing real and is published nowhere. Do not reuse it.
