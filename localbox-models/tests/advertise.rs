use localbox_models::{
    decode_discovery_shares, encode_discovery_shares, escape_discovery_value,
    unescape_discovery_value, AdvertisedShare, TransferMode,
};

#[test]
fn discovery_share_tokens_round_trip() {
    let shares = vec![
        AdvertisedShare {
            name: "docs".into(),
            recursive: true,
            sync: TransferMode::Auto,
            pull: TransferMode::Manual,
        },
        AdvertisedShare::new("photos"),
    ];
    let encoded = encode_discovery_shares(&shares);
    assert_eq!(encoded, "docs:true:auto:manual,photos:true:manual:manual");
    let decoded = decode_discovery_shares(&encoded);
    assert_eq!(decoded, shares);
    // Plain names still parse.
    let plain = decode_discovery_shares("a,b");
    assert_eq!(plain.len(), 2);
    assert_eq!(plain[0].name, "a");
}

#[test]
fn discovery_value_escape_round_trip() {
    let s = "Living Room = Main";
    assert_eq!(unescape_discovery_value(&escape_discovery_value(s)), s);
}
