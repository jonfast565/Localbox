use std::fs;
use utilities::{test_temp_path, write_str_atomic};

#[test]
fn export_ca_from_chain_and_import_dedupes() {
    let tmp = test_temp_path("localbox-tls");
    fs::create_dir_all(&tmp).unwrap();

    let materials = tls::generate_tls_materials("pc-test").unwrap();

    let chain_path = tmp.join("cert-chain.pem");
    let trust_path = tmp.join("trust.pem");
    let exported_ca = tmp.join("ca-export.pem");

    write_str_atomic(&chain_path, &materials.cert_chain_pem).unwrap();
    write_str_atomic(&trust_path, "").unwrap();

    tls::workflow::export_ca_from_chain_pem(&chain_path, &exported_ca).unwrap();
    let exported_text = fs::read_to_string(&exported_ca).unwrap();
    assert!(exported_text.contains("BEGIN CERTIFICATE"));

    // Import the exported CA twice; second import should add 0.
    let added1 = tls::workflow::import_ca_into_trust_store(&trust_path, &exported_ca).unwrap();
    let added2 = tls::workflow::import_ca_into_trust_store(&trust_path, &exported_ca).unwrap();
    assert_eq!(added1, 1);
    assert_eq!(added2, 0);

    let fps = tls::workflow::read_trust_store_fingerprints(&trust_path).unwrap();
    assert_eq!(fps.len(), 1);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn normalize_fingerprint_ignores_separators() {
    let a = tls::normalize_fingerprint("aa:bb:cc");
    let b = tls::normalize_fingerprint("AABBCC");
    assert_eq!(a, b);
}
