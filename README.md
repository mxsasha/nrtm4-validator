# nrtm4-validator

This is a validator for [draft-ietf-grow-nrtm-v4](https://datatracker.ietf.org/doc/html/draft-ietf-grow-nrtm-v4) written in Rust.
It can be useful in monitoring or supporting development.

## Usage

```
Validate an NRTMv4 server

Usage: nrtmv4-validator <UPDATE_NOTIFICATION_URL> <SOURCE> <PUBLIC_KEY>

Arguments:
  <UPDATE_NOTIFICATION_URL>  URL to the update notification file
  <SOURCE>                   Name of the IRR source
  <PUBLIC_KEY>               Public key in PEM

Options:
  -h, --help  Print help
```

For example:
```
nrtmv4-validator https://example.net/nrtmv4/EXAMPLE/update-notification-file.jose \
 EXAMPLE "-----BEGIN PUBLIC KEY-----
<repository public key>
-----END PUBLIC KEY-----"
```

Exit code: 0 for valid, 1 for invalid.
