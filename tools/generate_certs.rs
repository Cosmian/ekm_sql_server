//! Certificate generator for Cosmian EKM mTLS testing.
//!
//! Generates a self-signed CA and a client certificate (signed by the CA)
//! using the `openssl` crate (backed by openssl-sys / vcpkg OpenSSL).
//!
//! Usage:
//!   cargo run --bin generate-certs
//!   cargo run --bin generate-certs -- --username alice --out-dir certificates

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
    SubjectAlternativeName, SubjectKeyIdentifier,
};
use openssl::x509::{X509Name, X509};
use std::fs;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let username = arg_value(&args, "--username").unwrap_or_else(|| "admin".to_string());
    let out_dir = PathBuf::from(
        arg_value(&args, "--out-dir").unwrap_or_else(|| "certificates".to_string()),
    );

    fs::create_dir_all(&out_dir).expect("failed to create output directory");

    let ca_key_path = out_dir.join("ca.key.pem");
    let ca_cert_path = out_dir.join("ca.cert.pem");
    let client_key_path = out_dir.join(format!("{username}.key.pem"));
    let client_cert_path = out_dir.join(format!("{username}.cert.pem"));

    // ── 1. CA key + self-signed certificate ───────────────────────────────

    let (ca_cert, ca_key) = if ca_cert_path.exists() && ca_key_path.exists() {
        println!("CA certificate already exists, loading...");
        let key_pem = fs::read(&ca_key_path).expect("read ca.key.pem");
        let cert_pem = fs::read(&ca_cert_path).expect("read ca.cert.pem");
        let ca_key = PKey::private_key_from_pem(&key_pem).expect("parse CA key");
        let ca_cert = X509::from_pem(&cert_pem).expect("parse CA cert");
        (ca_cert, ca_key)
    } else {
        println!("Generating CA private key (RSA 4096)...");
        let rsa = Rsa::generate(4096).expect("generate RSA 4096");
        let ca_key = PKey::from_rsa(rsa).expect("PKey from RSA");
        fs::write(&ca_key_path, ca_key.private_key_to_pem_pkcs8().expect("CA key PEM"))
            .expect("write ca.key.pem");
        println!("  -> {}", ca_key_path.display());

        println!("Generating self-signed CA certificate (10 years)...");
        let ca_cert = build_ca_cert(&ca_key);
        fs::write(&ca_cert_path, ca_cert.to_pem().expect("CA cert PEM"))
            .expect("write ca.cert.pem");
        println!("  -> {}", ca_cert_path.display());

        (ca_cert, ca_key)
    };

    // ── 2. Client key + certificate signed by CA ──────────────────────────

    if client_cert_path.exists() {
        println!(
            "Client certificate for '{}' already exists, skipping.",
            username
        );
    } else {
        println!("Generating client private key for '{username}' (RSA 2048)...");
        let rsa = Rsa::generate(2048).expect("generate RSA 2048");
        let client_key = PKey::from_rsa(rsa).expect("PKey from RSA");
        fs::write(
            &client_key_path,
            client_key.private_key_to_pem_pkcs8().expect("client key PEM"),
        )
        .expect("write client key");
        println!("  -> {}", client_key_path.display());

        println!("Generating client certificate signed by CA (1 year)...");
        let client_cert = build_client_cert(&client_key, &ca_cert, &ca_key, &username);
        fs::write(
            &client_cert_path,
            client_cert.to_pem().expect("client cert PEM"),
        )
        .expect("write client cert");
        println!("  -> {}", client_cert_path.display());
    }

    // ── 3. Summary ────────────────────────────────────────────────────────

    println!("\nDone.  Files in {}:", out_dir.display());
    for entry in fs::read_dir(&out_dir).expect("read output dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(".pem") {
            println!("  {}", name.to_string_lossy());
        }
    }
}

/// Build a self-signed CA certificate valid for 10 years.
fn build_ca_cert(ca_key: &PKey<openssl::pkey::Private>) -> X509 {
    let mut name = X509Name::builder().expect("X509Name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, "Cosmian EKM Test CA")
        .unwrap();
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Cosmian")
        .unwrap();
    name.append_entry_by_nid(Nid::COUNTRYNAME, "FR").unwrap();
    let name = name.build();

    let mut builder = X509::builder().expect("X509 builder");
    builder.set_version(2).unwrap(); // X.509 v3
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(ca_key).unwrap();

    // Serial number
    let serial = {
        let mut bn = BigNum::new().unwrap();
        bn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .unwrap();
        bn.to_asn1_integer().unwrap()
    };
    builder.set_serial_number(&serial).unwrap();

    // Validity: now → +10 years (3650 days)
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(3650).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    // Extensions
    builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();

    let ctx = builder.x509v3_context(None, None);
    builder
        .append_extension(SubjectKeyIdentifier::new().build(&ctx).unwrap())
        .unwrap();

    builder.sign(ca_key, MessageDigest::sha256()).unwrap();
    builder.build()
}

/// Build a client certificate signed by the CA, valid for 1 year.
/// The `username` is set as Subject CN and as a DNS SAN.
fn build_client_cert(
    client_key: &PKey<openssl::pkey::Private>,
    ca_cert: &X509,
    ca_key: &PKey<openssl::pkey::Private>,
    username: &str,
) -> X509 {
    // Subject
    let mut subj = X509Name::builder().expect("X509Name builder");
    subj.append_entry_by_nid(Nid::COMMONNAME, username)
        .unwrap();
    subj.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Cosmian")
        .unwrap();
    let subj = subj.build();

    let mut builder = X509::builder().expect("X509 builder");
    builder.set_version(2).unwrap();
    builder.set_subject_name(&subj).unwrap();
    builder
        .set_issuer_name(ca_cert.subject_name())
        .unwrap();
    builder.set_pubkey(client_key).unwrap();

    // Serial
    let serial = {
        let mut bn = BigNum::new().unwrap();
        bn.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .unwrap();
        bn.to_asn1_integer().unwrap()
    };
    builder.set_serial_number(&serial).unwrap();

    // Validity: 1 year
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    // Extensions
    builder
        .append_extension(BasicConstraints::new().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()
                .unwrap(),
        )
        .unwrap();
    builder
        .append_extension(
            ExtendedKeyUsage::new().client_auth().build().unwrap(),
        )
        .unwrap();

    // SAN: DNS:<username>
    let ctx = builder.x509v3_context(Some(ca_cert), None);
    builder
        .append_extension(
            SubjectAlternativeName::new()
                .dns(username)
                .build(&ctx)
                .unwrap(),
        )
        .unwrap();

    // Authority Key Identifier
    let ctx = builder.x509v3_context(Some(ca_cert), None);
    builder
        .append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(false)
                .issuer(false)
                .build(&ctx)
                .unwrap(),
        )
        .unwrap();

    builder.sign(ca_key, MessageDigest::sha256()).unwrap();
    builder.build()
}

/// Simple CLI arg parser: returns the value after `--flag`.
fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}
