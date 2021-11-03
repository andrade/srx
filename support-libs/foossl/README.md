`foossl` provides support for setting up a TLS communication channel between a client and a server.

There is a test client/server example at `test`. Running make generates the binaries at `bin/test` with the temporary TLS certificates placed at `tls`.

The static libraries to link against are in `static` and the public headers in `include`.

The library right now is using hard-coded paths for the key and certificate, this needs to be updated.

## Requirements

- OpenSSL 1.1.0+
