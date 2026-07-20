//! Layout-pinning tests for [`crate::wire_stamp`].
//!
//! These live in their own file, NOT inside `wire_stamp.rs`, on purpose: `wire_stamp.rs` is hashed
//! byte-for-byte by `tools/wire-version-guard.sh`, so adding a test there would demand a
//! `BUNDLE_VERSION` bump for a change that moves no wire byte. This file is outside the manifest,
//! so test coverage can grow freely.
//!
//! The deterministic corpus (`vectors/bundle-v10.json`) pins the stamped envelope end to end via
//! `wire_vectors::deterministic_stamp`. What it does NOT do is separate the pieces, so a reader
//! cannot tell from the corpus alone which constant moved when it drifts. These pin each input
//! independently: the signed preimage, the hint derivation, and the struct encoding.

use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const TENANT: TenantId = [0x91u8; 16];

#[test]
fn the_signed_preimage_layout_is_pinned() {
    // STAMP_CONTEXT || bundle_id (32 raw bytes) || epoch (u64 little-endian). No length prefixes:
    // every component is fixed width, so the concatenation is unambiguous.
    let msg = stamp_message(&[0xabu8; 32], 0x0102_0304_0506_0708);
    assert_eq!(
        hex(&msg),
        concat!(
            "686f70206361727269616765207374616d70207631",
            "abababababababababababababababababababababababababababababababab",
            "0807060504030201"
        )
    );
    // The domain separator is the literal ASCII, unterminated and unlengthed.
    assert_eq!(&msg[..21], b"hop carriage stamp v1");
    assert_eq!(msg.len(), 21 + 32 + 8);
}

#[test]
fn the_hint_derivation_is_pinned() {
    // blake3::derive_key(HINT_CONTEXT, tenant_id || epoch_le)[..HINT_BYTES]. Pinning the output
    // catches a change to the context string, the preimage order, or the truncation width, none of
    // which the type system would notice.
    assert_eq!(HINT_BYTES, 4);
    assert_eq!(hex(&carriage_hint(&TENANT, 0)), "647e87b8");
    assert_eq!(hex(&carriage_hint(&TENANT, 1)), "15d56315");
}

#[test]
fn the_stamp_struct_encoding_is_pinned() {
    // Postcard: the 4 hint bytes raw (fixed-size array, no length prefix), then a varint length +
    // raw bytes for the signature, then a varint epoch. Field ORDER is the encoding.
    let stamp = CarriageStamp {
        hint: [0x01, 0x02, 0x03, 0x04],
        sig: vec![0xffu8; 64],
        epoch: 300,
    };
    let bytes = postcard::to_allocvec(&stamp).expect("encodes");
    assert_eq!(
        hex(&bytes),
        concat!(
            "01020304",
            "40",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ac02"
        )
    );
}

#[test]
fn the_epoch_period_is_pinned() {
    // CARRIAGE_EPOCH_MS decides the epoch VALUE emitted for a given clock, so it is wire, not
    // policy: change it and every stamp a node emits carries a different number.
    assert_eq!(CARRIAGE_EPOCH_MS, 3_600_000);
    assert_eq!(epoch_of(0), 0);
    assert_eq!(epoch_of(3_599_999), 0);
    assert_eq!(epoch_of(3_600_000), 1);
    assert_eq!(epoch_of(7_200_001), 2);
}

#[test]
fn a_stamper_emits_exactly_the_pinned_fields() {
    // The stamp a Stamper produces must be reproducible from the pinned primitives alone. This is
    // what makes Stamper's presence in the watched file meaningful: if `stamp` ever put something
    // else in a field, this fails even though `stamp_message` was untouched.
    let key = Identity::from_secret_bytes(&[0xb1u8; 32]);
    let stamper = Stamper::new(TENANT, key);
    let id = [0x77u8; 32];
    let now = 4242 * CARRIAGE_EPOCH_MS + 999;
    let stamp = stamper.stamp(&id, now);

    assert_eq!(stamp.epoch, 4242);
    assert_eq!(stamp.hint, carriage_hint(&TENANT, 4242));
    let expected = Identity::from_secret_bytes(&[0xb1u8; 32]).sign(&stamp_message(&id, 4242));
    assert_eq!(stamp.sig, expected.to_vec());
    assert_eq!(stamper.tenant(), TENANT);
}
