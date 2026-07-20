//! Layout-pinning tests for [`crate::wire_emit`].
//!
//! These live in their own file, NOT inside `wire_emit.rs`, on purpose: `wire_emit.rs` is hashed
//! byte-for-byte by `tools/wire-version-guard.sh`, so adding a test there would demand a
//! `BUNDLE_VERSION` bump for a change that moves no wire byte. This file is outside the manifest,
//! so test coverage can grow freely.
//!
//! The deterministic corpus (`vectors/bundle-v10.json`) already pins `LinkPacket`, `LinkAuth`, and
//! `Wire`. It does NOT construct `SessionInner`, `IdentityRecord`, the carrier chunk split, or the
//! stream-id derivation, so those are pinned here with explicit expected bytes.

use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn session_inner_layout_is_pinned() {
    // Postcard: varint len + utf8 for the string, then varint len + raw bytes for the body.
    let inner = SessionInner {
        content_type: "text/plain".into(),
        body: vec![0xde, 0xad, 0xbe, 0xef],
    };
    let bytes = postcard::to_allocvec(&inner).expect("encodes");
    assert_eq!(hex(&bytes), "0a746578742f706c61696e04deadbeef");
}

#[test]
fn session_establish_content_type_is_pinned() {
    // The receiver matches on this exact string to heal a desynced ratchet; changing it makes
    // healing pings surface as user messages on an older peer.
    assert_eq!(SESSION_ESTABLISH_CT, "hop.session.establish");
}

#[test]
fn identity_record_layout_is_pinned() {
    // The `hop.identify` reply body. Option tag, then the NodeKind discriminant, then 32 raw bytes.
    let record = IdentityRecord {
        name: Some("relay-iad".into()),
        kind: NodeKind::Relay,
        address: [0x11; 32],
    };
    let bytes = postcard::to_allocvec(&record).expect("encodes");
    assert_eq!(
        hex(&bytes),
        "010972656c61792d69616401\
         1111111111111111111111111111111111111111111111111111111111111111"
            .replace(char::is_whitespace, "")
    );

    let anonymous = IdentityRecord {
        name: None,
        kind: NodeKind::Device,
        address: [0x00; 32],
    };
    let bytes = postcard::to_allocvec(&anonymous).expect("encodes");
    assert_eq!(&hex(&bytes)[..4], "0000");
}

#[test]
fn node_kind_discriminants_are_append_only() {
    // Postcard encodes by index. Reordering renumbers every later variant and silently
    // mislabels nodes across versions.
    for (kind, expected) in [
        (NodeKind::Device, 0u8),
        (NodeKind::Relay, 1),
        (NodeKind::Gateway, 2),
        (NodeKind::Endpoint, 3),
    ] {
        let bytes = postcard::to_allocvec(&kind).expect("encodes");
        assert_eq!(bytes, vec![expected], "{kind:?} discriminant moved");
    }
}

#[test]
fn service_names_are_pinned() {
    assert_eq!(SERVICE_IDENTIFY, "hop.identify");
    assert_eq!(SERVICE_TELEMETRY, "hop.telemetry");
}

#[test]
fn link_packet_discriminants_are_append_only() {
    // `advert_record_exceeds_limit` depends on `Wire::Advert == 1`; `decode_link_packet`
    // depends on these three being 0/1/2.
    assert_eq!(
        postcard::to_allocvec(&LinkPacket::Handshake(vec![])).expect("encodes")[0],
        0
    );
    assert_eq!(
        postcard::to_allocvec(&LinkPacket::Data(vec![])).expect("encodes")[0],
        1
    );
    assert_eq!(
        postcard::to_allocvec(&LinkPacket::DataFrag {
            idx: 0,
            cnt: 1,
            ct: vec![]
        })
        .expect("encodes")[0],
        2
    );
}

#[test]
fn stream_id_derivation_is_pinned() {
    // High 8 bytes big-endian sequence, low 8 bytes our short address.
    let address = [0xab; 32];
    let id = derive_stream_id(0x0102030405060708, &address);
    assert_eq!(&id[..8], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(&id[8..], &short_addr(&address)[..]);
}

#[test]
fn carrier_chunk_split_is_pinned() {
    let encoded: Vec<u8> = (0..10u8).collect();
    let payloads = carrier_chunk_payloads(&encoded, [0x77; 16], 4);
    assert_eq!(payloads.len(), 3, "10 bytes at 4 per chunk is 3 chunks");
    let expected: [(u64, &[u8], bool); 3] = [
        (0, &[0, 1, 2, 3], false),
        (1, &[4, 5, 6, 7], false),
        (2, &[8, 9], true),
    ];
    for (payload, (seq, bytes, fin)) in payloads.iter().zip(expected) {
        let Payload::Carrier {
            stream_id,
            seq: got_seq,
            bytes: got_bytes,
            fin: got_fin,
        } = payload
        else {
            panic!("expected a Carrier payload");
        };
        assert_eq!(*stream_id, [0x77; 16]);
        assert_eq!(*got_seq, seq);
        assert_eq!(got_bytes.as_slice(), bytes);
        assert_eq!(*got_fin, fin);
    }
}

#[test]
fn carrier_chunk_split_marks_fin_on_an_exact_multiple() {
    let encoded: Vec<u8> = (0..8u8).collect();
    let payloads = carrier_chunk_payloads(&encoded, [0; 16], 4);
    assert_eq!(payloads.len(), 2);
    let Payload::Carrier { fin, seq, .. } = &payloads[1] else {
        panic!("expected a Carrier payload");
    };
    assert!(
        *fin,
        "the last chunk of an exact multiple still carries fin"
    );
    assert_eq!(*seq, 1);
}

#[test]
fn framing_thresholds_are_pinned() {
    // A receiver on an older build rejects anything outside this envelope, so these are wire.
    assert_eq!(MAX_RECORD_PLAINTEXT, 60_000);
    assert_eq!(MAX_REASSEMBLED_RECORD, 1 << 20);
    assert_eq!(MAX_RECORD_FRAGMENTS, 18);
    assert_eq!(MAX_LINK_PACKET_BYTES, 64 * 1024);
    assert_eq!(MAX_HANDSHAKE_MESSAGE_BYTES, 1024);
    assert_eq!(STREAM_CHUNK, 48 * 1024);
}

#[test]
fn frame_record_emits_one_data_packet_below_the_threshold() {
    let record = Wire::Have(crate::store::HaveSet { ids: Vec::new() });
    let framed = frame_record(&record, |piece| Some(piece.to_vec()));
    assert_eq!(framed.len(), 1);
    let packet = decode_link_packet(&framed[0]).expect("decodes");
    assert!(matches!(packet, LinkPacket::Data(_)));
}

#[test]
fn frame_record_fragments_in_order_above_the_threshold() {
    // A HaveSet large enough to exceed one Noise message: each id is 32 bytes.
    let ids = vec![[0x5au8; 32]; 3_000];
    let record = Wire::Have(crate::store::HaveSet { ids });
    let framed = frame_record(&record, |piece| Some(piece.to_vec()));
    assert!(framed.len() > 1, "expected fragmentation");
    let cnt = framed.len() as u16;
    for (expected_idx, bytes) in framed.iter().enumerate() {
        let packet = decode_link_packet(bytes).expect("fragment decodes");
        let LinkPacket::DataFrag { idx, cnt: got, .. } = packet else {
            panic!("expected DataFrag");
        };
        assert_eq!(idx, expected_idx as u16);
        assert_eq!(got, cnt, "every fragment carries the same total count");
    }
}

#[test]
fn frame_record_abandons_the_remainder_when_the_ratchet_fails() {
    let ids = vec![[0x5au8; 32]; 3_000];
    let record = Wire::Have(crate::store::HaveSet { ids });
    let mut calls = 0;
    let framed = frame_record(&record, |piece| {
        calls += 1;
        (calls < 2).then(|| piece.to_vec())
    });
    assert_eq!(framed.len(), 1, "stops at the first encrypt failure");
}

#[test]
fn frame_record_emits_nothing_when_the_first_encrypt_fails() {
    let record = Wire::Have(crate::store::HaveSet { ids: Vec::new() });
    let framed = frame_record(&record, |_| None);
    assert!(framed.is_empty());
}

#[test]
fn link_auth_encoding_is_the_bare_address() {
    let address = [0x2c; 32];
    let bytes = encode_link_auth(address);
    assert_eq!(bytes, address.to_vec(), "a newtype struct adds no framing");
}

#[test]
fn decode_link_packet_rejects_outside_the_envelope() {
    assert!(decode_link_packet(&vec![0u8; MAX_LINK_PACKET_BYTES + 1]).is_none());
    // cnt == 0 is not a valid fragment count.
    let bad = postcard::to_allocvec(&LinkPacket::DataFrag {
        idx: 0,
        cnt: 0,
        ct: vec![1, 2, 3],
    })
    .expect("encodes");
    assert!(decode_link_packet(&bad).is_none());
    // idx must be inside cnt.
    let bad = postcard::to_allocvec(&LinkPacket::DataFrag {
        idx: 3,
        cnt: 2,
        ct: vec![1, 2, 3],
    })
    .expect("encodes");
    assert!(decode_link_packet(&bad).is_none());
    // An oversized handshake message is rejected before it reaches the Noise state machine.
    let bad = postcard::to_allocvec(&LinkPacket::Handshake(vec![
        0u8;
        MAX_HANDSHAKE_MESSAGE_BYTES + 1
    ]))
    .expect("encodes");
    assert!(decode_link_packet(&bad).is_none());
}

#[test]
fn fragment_bounds_reject_an_oversized_reassembly() {
    assert!(fragment_bounds_ok(2, 1_000, 0));
    assert!(!fragment_bounds_ok(
        (MAX_RECORD_FRAGMENTS + 1) as u16,
        1_000,
        0
    ));
    assert!(!fragment_bounds_ok(2, MAX_RECORD_PLAINTEXT + 1, 0));
    assert!(!fragment_bounds_ok(2, 1_000, MAX_REASSEMBLED_RECORD));
}

#[test]
fn advert_record_limit_keys_off_the_wire_discriminant() {
    // Wire::Advert == 1, so a long record whose first byte is 1 is an oversized advert.
    let mut oversized = vec![1u8];
    oversized.extend(std::iter::repeat_n(0u8, MAX_ADVERT_LINK_BYTES + 1));
    assert!(advert_record_exceeds_limit(&oversized));

    // The same length under the Bundle discriminant is legitimate and must pass.
    let mut bundle = vec![0u8];
    bundle.extend(std::iter::repeat_n(0u8, MAX_ADVERT_LINK_BYTES + 1));
    assert!(!advert_record_exceeds_limit(&bundle));
    assert!(!advert_record_exceeds_limit(&[]));
}
