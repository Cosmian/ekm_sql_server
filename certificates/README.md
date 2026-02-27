# Certificates

This directory holds PEM-encoded client certificates and keys used for
mTLS authentication with the Cosmian KMS.

## Generating test certificates

Run the helper script from the repository root:

```powershell
.\scripts\generate_certificates.ps1
```

This creates:

| File              | Description                                      |
|-------------------|--------------------------------------------------|
| `ca.key.pem`      | CA private key (RSA 4096)                        |
| `ca.cert.pem`     | Self-signed CA certificate (10-year validity)    |
| `admin.key.pem`   | Client private key for username `admin` (RSA 2048)|
| `admin.cert.pem`  | Client certificate signed by the CA (CN=admin)   |

To generate a certificate for a different username:

```powershell
.\scripts\generate_certificates.ps1 -Username alice
```

## Configuration

Reference the certificate paths in `%PROGRAMDATA%\Cosmian\EKM\config.toml`:

```toml
[kms]
server_url = "https://kms.example.com:9998"

[[kms.certificates]]
username    = "admin"
client_cert = "C:\\ProgramData\\Cosmian\\EKM\\certificates\\admin.cert.pem"
client_key  = "C:\\ProgramData\\Cosmian\\EKM\\certificates\\admin.key.pem"
```
