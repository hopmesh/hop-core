//! Deterministic v9 wire-vector construction.
//!
//! This module is compiled only by tests and the explicit `wire-vectors` feature. It uses fixed
//! secrets and nonces solely to make a reviewable corpus. Production constructors continue to use
//! the operating system CSPRNG.

use std::collections::BTreeMap;

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::Serialize;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use super::*;
use crate::access::{CarriageStamp, Stamper};
use crate::discover::{Advert, AdvertKind};
use crate::hps::{self, AccessMode, ServiceKind, TopicMeta, Visibility};
use crate::link::Frame;
use crate::node::{LinkAuth, LinkPacket, Wire};
use crate::reach::ReachRecord;
use crate::session::{Header, RatchetMessage};
use crate::store::HaveSet;

pub const CORPUS_SCHEMA: u32 = 1;
pub const CORPUS_FILE: &str = "vectors/bundle-v10.json";

const CREATED_AT: u64 = 1_725_000_123_456;
const LIFETIME_MS: u32 = 604_800_000;
const HOP_LIMIT: u8 = 11;
const COPIES: u16 = 13;
const HOPS: u8 = 2;

#[derive(Serialize)]
pub struct Corpus {
    pub schema: u32,
    pub bundle_version: u8,
    pub description: &'static str,
    pub fixed_inputs: BTreeMap<&'static str, String>,
    pub destinations: Vec<EncodingVector>,
    pub bundles: Vec<BundleVector>,
    pub supplemental_payload_layouts: Vec<EncodingVector>,
    pub nested_layouts: Vec<EncodingVector>,
    pub link_packets: Vec<EncodingVector>,
    pub link_auth: EncodingVector,
    pub wire_records: Vec<EncodingVector>,
    pub have_sets: Vec<EncodingVector>,
    pub adverts: Vec<EncodingVector>,
    pub reach_records: Vec<EncodingVector>,
    pub id_derivations: Vec<EncodingVector>,
}

#[derive(Serialize)]
pub struct EncodingVector {
    pub name: String,
    pub family: String,
    pub variant: String,
    pub bytes_hex: String,
}

#[derive(Serialize)]
pub struct BundleVector {
    pub name: String,
    pub family: String,
    pub payload_variant: Option<String>,
    pub private_inner_variant: Option<String>,
    pub primary_payload: bool,
    pub destination_variant: String,
    pub destination_code: u8,
    pub bytes_hex: String,
    pub payload_hex: String,
    pub id_hex: String,
    pub version: u8,
    pub private: bool,
    pub is_ack: bool,
    pub created_at: u64,
    pub lifetime_ms: u32,
    pub hop_limit: u8,
    pub copies: u16,
    pub hops: u8,
    pub trace_len: usize,
    pub trace_hex: String,
    pub access_present: bool,
    pub access_hex: String,
    pub integrity_kind: String,
    pub private_content_id_hex: String,
    pub recognition_tag_hex: String,
    pub recognition_ephemeral_hex: String,
    pub private_mailbox_present: bool,
    pub private_mailbox_hex: String,
    pub seal_ephemeral_secret_hex: String,
    pub sealed_ephemeral_pub_hex: String,
    pub seal_nonce_hex: String,
    pub ciphertext_hex: String,
    pub signature_hex: String,
}

struct PayloadSpec {
    name: &'static str,
    family: &'static str,
    payload: Payload,
    destination: Destination,
}

struct SealFixture {
    sealed: Sealed,
    secret: [u8; 32],
}

struct PrivateSpec {
    name: &'static str,
    inner: Payload,
    mailbox: Option<[u8; 2]>,
    flags: BundleFlags,
    fixture_index: u8,
}

pub fn corpus() -> Corpus {
    let sender = Identity::from_secret_bytes(&bytes32(0x11));
    let recipient = Identity::from_secret_bytes(&bytes32(0x51));
    let recipient_addr = recipient.address();
    let fixed_id = bytes32(0xa0);

    let mut fixed_inputs = BTreeMap::new();
    fixed_inputs.insert("sender_ed25519_seed_hex", hex(&sender.to_secret_bytes()));
    fixed_inputs.insert(
        "recipient_ed25519_seed_hex",
        hex(&recipient.to_secret_bytes()),
    );
    fixed_inputs.insert("sender_address_hex", hex(&sender.address()));
    fixed_inputs.insert("recipient_address_hex", hex(&recipient_addr));
    fixed_inputs.insert("reference_bundle_id_hex", hex(&fixed_id));
    fixed_inputs.insert("created_at_ms", CREATED_AT.to_string());
    fixed_inputs.insert("lifetime_ms", LIFETIME_MS.to_string());
    fixed_inputs.insert("hop_limit", HOP_LIMIT.to_string());
    fixed_inputs.insert("copy_budget", COPIES.to_string());
    fixed_inputs.insert("hps_content_key_hex", hex(&bytes32(0xd1)));
    fixed_inputs.insert("carriage_tenant_id_hex", hex(&bytes16(0x91)));
    fixed_inputs.insert("carriage_signing_seed_hex", hex(&bytes32(0xb1)));
    fixed_inputs.insert("carriage_stamp_time_ms", CREATED_AT.to_string());
    fixed_inputs.insert(
        "seal_rule",
        "vector index selects a fixed 32-byte X25519 secret and 12-byte nonce".into(),
    );

    let destinations = destination_values(&recipient_addr, &fixed_id)
        .into_iter()
        .map(|destination| EncodingVector {
            name: format!("destination-{}", destination_name(&destination)),
            family: "destination".into(),
            variant: destination_name(&destination).into(),
            bytes_hex: hex(&postcard::to_allocvec(&destination).expect("destination encodes")),
        })
        .collect();

    let mut bundles = Vec::new();
    for (index, spec) in payload_specs(&sender, recipient_addr, fixed_id)
        .into_iter()
        .enumerate()
    {
        let payload_variant = payload_name(&spec.payload);
        let payload_bytes = postcard::to_allocvec(&spec.payload).expect("payload encodes");
        let seal = deterministic_seal(&recipient_addr, &payload_bytes, index as u8);
        let bundle = signed_bundle(&sender, spec.destination, seal.sealed.clone(), index as u64);
        bundle
            .verify()
            .expect("deterministic signed bundle verifies");
        bundles.push(bundle_vector(
            spec.name,
            spec.family,
            Some(payload_variant),
            true,
            &bundle,
            &payload_bytes,
            Some(&seal),
        ));
    }

    let mut reference_private_content_id = None;
    let mut reference_private_wire_id = None;
    for (index, spec) in private_specs(fixed_id).into_iter().enumerate() {
        let name = spec.name;
        let private = private_bundle(&recipient, spec, index as u64);
        private
            .0
            .verify()
            .expect("deterministic private bundle verifies");
        if name == "private-envelope-session-message" {
            reference_private_content_id = private.0.private_content_id();
            reference_private_wire_id = Some(private.0.id());
        }
        bundles.push(bundle_vector(
            name,
            "private",
            Some(payload_name(&private.1)),
            false,
            &private.0,
            &postcard::to_allocvec(&private.1).expect("private payload encodes"),
            Some(&private.2),
        ));
    }

    let minimal_payload = Payload::SessionReset;
    let minimal_payload_bytes =
        postcard::to_allocvec(&minimal_payload).expect("minimal traced payload encodes");
    let minimal_seal = deterministic_seal(&recipient_addr, &minimal_payload_bytes, 0xe8);
    let mut minimal_traced = signed_bundle(
        &sender,
        Destination::Device(recipient_addr),
        minimal_seal.sealed.clone(),
        450,
    );
    minimal_traced.env.custody = None;
    minimal_traced.env.copies = 1;
    minimal_traced.env.hops = 0;
    minimal_traced.env.trace.clear();
    minimal_traced
        .verify()
        .expect("minimal traced bundle verifies");
    bundles.push(bundle_vector(
        "traced-envelope-empty-forwarding",
        "traced-envelope",
        Some(payload_name(&minimal_payload)),
        false,
        &minimal_traced,
        &minimal_payload_bytes,
        Some(&minimal_seal),
    ));

    let mut stamped_traced = minimal_traced.clone();
    let stamp = deterministic_stamp(&stamped_traced.id());
    stamped_traced.env.access = Some(Box::new(stamp));
    stamped_traced
        .verify()
        .expect("deterministic stamped bundle verifies");
    bundles.push(bundle_vector(
        "traced-envelope-carriage-stamped",
        "traced-envelope",
        Some(payload_name(&minimal_payload)),
        false,
        &stamped_traced,
        &minimal_payload_bytes,
        Some(&minimal_seal),
    ));

    let vaccine = Bundle::create_vaccine(
        bytes32(0xe0),
        BundleOpts {
            app: bytes16(0x81),
            created_at: CREATED_AT + 500,
            lifetime_ms: LIFETIME_MS,
            hop_limit: HOP_LIMIT,
            copies: COPIES,
            priority: 9,
            flags: BundleFlags {
                request_ack: false,
                is_ack: false,
                custody_requested: false,
            },
        },
    );
    vaccine.verify().expect("deterministic vaccine verifies");
    bundles.push(bundle_vector(
        "vaccine-envelope",
        "vaccine",
        None,
        false,
        &vaccine,
        &[],
        None,
    ));

    let supplemental_payload_layouts = supplemental_payloads()
        .into_iter()
        .map(|(name, payload)| EncodingVector {
            name: name.into(),
            family: "payload-supplemental".into(),
            variant: payload_name(&payload).into(),
            bytes_hex: hex(&postcard::to_allocvec(&payload).expect("payload encodes")),
        })
        .collect();

    let adverts = advert_vectors(&sender);
    let wire_bundle = Bundle::from_bytes(&decode_hex(&bundles[0].bytes_hex))
        .expect("reference wire bundle decodes");
    let wire_advert: Advert = postcard::from_bytes(&decode_hex(&adverts[0].bytes_hex))
        .expect("reference wire advert decodes");
    let link_packets = link_packet_vectors();
    let link_auth = encoded(
        "link-auth",
        "LinkAuth",
        &LinkAuth {
            address: sender.address(),
        },
    );
    let have_sets = have_set_vectors(&fixed_id, &wire_bundle.id());
    let wire_records = wire_record_vectors(wire_bundle, wire_advert, &fixed_id);
    let nested_layouts = nested_layouts(&fixed_id);
    let reach_records = vec![EncodingVector {
        name: "hns-self-certifying-reach-record".into(),
        family: "hns-reach".into(),
        variant: "ReachRecord".into(),
        bytes_hex: hex(&ReachRecord::sign(
            &sender,
            "wss://vector.example/_hop",
            3600,
            CREATED_AT / 1000,
        )
        .to_bytes()),
    }];

    let private_content_id =
        reference_private_content_id.expect("reference private content id was recorded");
    let private_wire_id =
        reference_private_wire_id.expect("reference private wire id was recorded");
    let id_derivations = vec![
        EncodingVector {
            name: "traced-bundle-id".into(),
            family: "id".into(),
            variant: "BLAKE3(src, sealed)".into(),
            bytes_hex: hex(&bundles[0].id_hex_bytes()),
        },
        EncodingVector {
            name: "private-content-id".into(),
            family: "id".into(),
            variant: "PrivateContentId".into(),
            bytes_hex: hex(&private_content_id),
        },
        EncodingVector {
            name: "private-wire-id".into(),
            family: "id".into(),
            variant: "PrivateWireId".into(),
            bytes_hex: hex(&private_wire_id),
        },
        EncodingVector {
            name: "vaccine-id".into(),
            family: "id".into(),
            variant: "VaccineId".into(),
            bytes_hex: hex(&vaccine.id()),
        },
    ];

    Corpus {
        schema: CORPUS_SCHEMA,
        bundle_version: BUNDLE_VERSION,
        description:
            "Complete deterministic Hop versioned wire corpus. Fixed secrets are test data only.",
        fixed_inputs,
        destinations,
        bundles,
        supplemental_payload_layouts,
        nested_layouts,
        link_packets,
        link_auth,
        wire_records,
        have_sets,
        adverts,
        reach_records,
        id_derivations,
    }
}

fn link_packet_vectors() -> Vec<EncodingVector> {
    vec![
        LinkPacket::Handshake(vec![0x00, 0x7f, 0x80, 0xff]),
        LinkPacket::Data(vec![0x10, 0x20, 0x30, 0x40]),
        LinkPacket::DataFrag {
            idx: 0x0102,
            cnt: 0x0304,
            ct: vec![0x00, 0x80, 0xfe, 0xff],
        },
    ]
    .into_iter()
    .map(|packet| encoded("link-packet", link_packet_name(&packet), &packet))
    .collect()
}

fn link_packet_name(packet: &LinkPacket) -> &'static str {
    match packet {
        LinkPacket::Handshake(_) => "Handshake",
        LinkPacket::Data(_) => "Data",
        LinkPacket::DataFrag { .. } => "DataFrag",
    }
}

fn wire_record_vectors(
    bundle: Bundle,
    advert: Advert,
    reference_id: &BundleId,
) -> Vec<EncodingVector> {
    vec![
        Wire::Bundle(bundle),
        Wire::Advert(advert),
        Wire::Have(HaveSet {
            ids: vec![*reference_id, bytes32(0xc0)],
        }),
    ]
    .into_iter()
    .map(|wire| encoded("wire", wire_record_name(&wire), &wire))
    .collect()
}

fn wire_record_name(wire: &Wire) -> &'static str {
    match wire {
        Wire::Bundle(_) => "Bundle",
        Wire::Advert(_) => "Advert",
        Wire::Have(_) => "Have",
    }
}

fn have_set_vectors(reference_id: &BundleId, second_id: &BundleId) -> Vec<EncodingVector> {
    [
        ("Empty", HaveSet::default()),
        (
            "NonEmpty",
            HaveSet {
                ids: vec![*reference_id, *second_id],
            },
        ),
    ]
    .into_iter()
    .map(|(variant, have)| encoded("have-set", variant, &have))
    .collect()
}

impl BundleVector {
    fn id_hex_bytes(&self) -> Vec<u8> {
        decode_hex(&self.id_hex)
    }
}

fn destination_values(recipient: &PubKeyBytes, fixed_id: &BundleId) -> Vec<Destination> {
    vec![
        Destination::Device(*recipient),
        Destination::AckTo(*recipient, *fixed_id),
        Destination::Broadcast,
        Destination::Vaccine(bytes32(0xe0)),
    ]
}

pub fn destination_name(destination: &Destination) -> &'static str {
    match destination {
        Destination::Device(_) => "Device",
        Destination::AckTo(_, _) => "AckTo",
        Destination::Broadcast => "Broadcast",
        Destination::Vaccine(_) => "Vaccine",
    }
}

pub fn destination_code(destination: &Destination) -> u8 {
    match destination {
        Destination::Device(_) => 0,
        Destination::AckTo(_, _) => 1,
        Destination::Broadcast => 2,
        Destination::Vaccine(_) => 3,
    }
}

pub fn payload_name(payload: &Payload) -> &'static str {
    match payload {
        Payload::HttpRequest { .. } => "HttpRequest",
        Payload::HttpResponse { .. } => "HttpResponse",
        Payload::PeerMessage { .. } => "PeerMessage",
        Payload::SessionInit { .. } => "SessionInit",
        Payload::SessionMessage { .. } => "SessionMessage",
        Payload::Private { .. } => "Private",
        Payload::Ack { .. } => "Ack",
        Payload::StreamOpen { .. } => "StreamOpen",
        Payload::StreamData { .. } => "StreamData",
        Payload::StreamAck { .. } => "StreamAck",
        Payload::StreamClose { .. } => "StreamClose",
        Payload::ServiceRequest { .. } => "ServiceRequest",
        Payload::ServiceResponse { .. } => "ServiceResponse",
        Payload::Carrier { .. } => "Carrier",
        Payload::HpsJoinRequest { .. } => "HpsJoinRequest",
        Payload::HpsKeys { .. } => "HpsKeys",
        Payload::HpsInvite { .. } => "HpsInvite",
        Payload::HpsInviteAccept { .. } => "HpsInviteAccept",
        Payload::HpsLeave { .. } => "HpsLeave",
        Payload::HpsRekey { .. } => "HpsRekey",
        Payload::HpsReachAck { .. } => "HpsReachAck",
        Payload::HpsPublish { .. } => "HpsPublish",
        Payload::SessionReset => "SessionReset",
    }
}

fn payload_specs(
    sender: &Identity,
    recipient: PubKeyBytes,
    fixed_id: BundleId,
) -> Vec<PayloadSpec> {
    let ratchet = RatchetMessage {
        header: Header {
            dh: bytes32(0x31),
            pn: 17,
            n: 19,
        },
        ciphertext: vec![0x90, 0x91, 0x92, 0x93, 0x94],
    };
    let stream_id = bytes16(0x61);
    let app = bytes16(0x81);
    let sender_addr = sender.address();
    let reach_tag = bytes16(0xab);
    let reach_epoch = 0x2122_2324;
    let reach_mac = hps::reach_ack_mac(&bytes32(0xd1), &app, &sender_addr, &reach_tag, reach_epoch);
    let publish_tag = bytes16(0xcd);
    let publish_epoch = 0x3132_3334;
    let publish_nonce = bytes12(0xde);
    let publish_ciphertext = vec![0x00, 0x80, 0xfe, 0xff];
    let publish_sig = hps::sign_publish(
        &sender.to_secret_bytes(),
        &app,
        &sender_addr,
        &publish_tag,
        publish_epoch,
        &publish_nonce,
        &publish_ciphertext,
    );
    vec![
        PayloadSpec {
            name: "payload-http-request",
            family: "egress",
            payload: Payload::HttpRequest {
                host: "vector.example".into(),
                method: "POST".into(),
                url: "/v1/check?q=wire".into(),
                headers: vec![("accept".into(), "application/cbor".into())],
                body: vec![0x01, 0x80, 0xff],
                max_resp_bytes: 65_535,
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-http-response",
            family: "egress",
            payload: Payload::HttpResponse {
                status: 207,
                headers: vec![("content-type".into(), "application/octet-stream".into())],
                body: vec![0xde, 0xad, 0xbe, 0xef],
                for_bundle_id: fixed_id,
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-peer-message",
            family: "messaging",
            payload: Payload::PeerMessage {
                content_type: "text/plain; charset=utf-8".into(),
                body: b"deterministic peer message".to_vec(),
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-session-init",
            family: "ratchet",
            payload: Payload::SessionInit {
                ek_pub: bytes32(0x21),
                spk_pub: bytes32(0x41),
                msg: ratchet.clone(),
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-session-message",
            family: "ratchet",
            payload: Payload::SessionMessage {
                msg: ratchet.clone(),
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-private-wrapper",
            family: "private",
            payload: Payload::Private {
                sender: bytes32(0x71),
                inner: Box::new(Payload::SessionInit {
                    ek_pub: bytes32(0x22),
                    spk_pub: bytes32(0x42),
                    msg: ratchet.clone(),
                }),
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-ack",
            family: "ack",
            payload: Payload::Ack {
                for_bundle_id: fixed_id,
                status: 3,
                delivery_hops: 7,
                delivery_ms: 42_424,
                proof: Some(bytes32(0x83)),
            },
            destination: Destination::AckTo(recipient, fixed_id),
        },
        PayloadSpec {
            name: "payload-stream-open",
            family: "stream",
            payload: Payload::StreamOpen {
                stream_id,
                kind: StreamKind::WebSocket,
                method: "GET".into(),
                url: "/events".into(),
                headers: vec![("x-vector".into(), "open".into())],
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-stream-data",
            family: "stream",
            payload: Payload::StreamData {
                stream_id,
                seq: 0x0102_0304_0506_0708,
                bytes: vec![0x00, 0x7f, 0x80, 0xff],
                fin: true,
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-stream-ack",
            family: "stream",
            payload: Payload::StreamAck {
                stream_id,
                ack: 0xfedc_ba98_7654_3210,
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-stream-close",
            family: "stream",
            payload: Payload::StreamClose {
                stream_id,
                reason: 4001,
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-service-request",
            family: "service-rpc",
            payload: Payload::ServiceRequest {
                service: "hop.identify".into(),
                method: "describe".into(),
                args: vec![0x10, 0x20, 0x30],
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-service-response",
            family: "service-rpc",
            payload: Payload::ServiceResponse {
                for_bundle_id: fixed_id,
                status: 299,
                body: b"rpc-response".to_vec(),
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-carrier",
            family: "carrier",
            payload: Payload::Carrier {
                stream_id,
                seq: 9,
                bytes: vec![0x81, 0x82, 0x83, 0x84],
                fin: false,
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-hps-join-request",
            family: "hps",
            payload: Payload::HpsJoinRequest {
                path: "/vector/topic".into(),
                proof: bytes32(0x12),
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-hps-keys",
            family: "hps",
            payload: Payload::HpsKeys {
                path: "/vector/topic".into(),
                content_key: bytes32(0x23),
                service_pubkey: Some(bytes32(0x34)),
                epoch: 0x0102_0304,
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-hps-invite",
            family: "hps",
            payload: Payload::HpsInvite {
                path: "/vector/topic".into(),
                kind: ServiceKind::Service,
                proof: bytes32(0x45),
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-hps-invite-accept",
            family: "hps",
            payload: Payload::HpsInviteAccept {
                path: "/vector/topic".into(),
                proof: bytes32(0x56),
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-hps-leave",
            family: "hps",
            payload: Payload::HpsLeave {
                path: "/vector/topic".into(),
                proof: bytes32(0x67),
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-hps-rekey",
            family: "hps",
            payload: Payload::HpsRekey {
                old_path: "/vector/old".into(),
                new_path: "/vector/new".into(),
                epoch: 0x1112_1314,
                content_key: bytes32(0x78),
                service_pubkey: Some(bytes32(0x89)),
                proof: bytes32(0x9a),
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-hps-reach-ack",
            family: "hps",
            payload: Payload::HpsReachAck {
                topic_tag: reach_tag,
                epoch: reach_epoch,
                mac: reach_mac,
            },
            destination: Destination::Device(recipient),
        },
        PayloadSpec {
            name: "payload-hps-publish",
            family: "hps",
            payload: Payload::HpsPublish {
                topic_tag: publish_tag,
                epoch: publish_epoch,
                nonce: publish_nonce.to_vec(),
                ciphertext: publish_ciphertext,
                sig: publish_sig.to_vec(),
            },
            destination: Destination::Broadcast,
        },
        PayloadSpec {
            name: "payload-session-reset",
            family: "control",
            payload: Payload::SessionReset,
            destination: Destination::Device(recipient),
        },
    ]
}

fn supplemental_payloads() -> Vec<(&'static str, Payload)> {
    vec![
        (
            "payload-ack-without-private-proof",
            Payload::Ack {
                for_bundle_id: bytes32(0xa0),
                status: 0,
                delivery_hops: 0,
                delivery_ms: 0,
                proof: None,
            },
        ),
        (
            "payload-stream-open-sse",
            Payload::StreamOpen {
                stream_id: bytes16(0x61),
                kind: StreamKind::Sse,
                method: "GET".into(),
                url: "/sse".into(),
                headers: Vec::new(),
            },
        ),
        (
            "payload-hps-keys-channel",
            Payload::HpsKeys {
                path: "/vector/channel".into(),
                content_key: bytes32(0x23),
                service_pubkey: None,
                epoch: 0,
            },
        ),
        (
            "payload-hps-invite-channel",
            Payload::HpsInvite {
                path: "/vector/channel".into(),
                kind: ServiceKind::Channel,
                proof: bytes32(0x45),
            },
        ),
        (
            "payload-hps-rekey-channel",
            Payload::HpsRekey {
                old_path: "/vector/channel".into(),
                new_path: "/vector/channel".into(),
                epoch: 1,
                content_key: bytes32(0x78),
                service_pubkey: None,
                proof: bytes32(0x9a),
            },
        ),
    ]
}

fn private_specs(fixed_id: BundleId) -> Vec<PrivateSpec> {
    let session_message = |dh, pn, n, ciphertext| RatchetMessage {
        header: Header {
            dh: bytes32(dh),
            pn,
            n,
        },
        ciphertext,
    };
    vec![
        PrivateSpec {
            name: "private-envelope-session-init",
            inner: Payload::SessionInit {
                ek_pub: bytes32(0x24),
                spk_pub: bytes32(0x44),
                msg: session_message(0x34, 31, 37, vec![0xb1, 0xb2, 0xb3]),
            },
            mailbox: Some([0xa5, 0x5a]),
            flags: BundleFlags {
                request_ack: true,
                ..Default::default()
            },
            fixture_index: 0xef,
        },
        PrivateSpec {
            name: "private-envelope-session-message",
            inner: Payload::SessionMessage {
                msg: session_message(0x31, 23, 29, vec![0xa1, 0xa2, 0xa3, 0xa4]),
            },
            mailbox: Some([0xa5, 0x5a]),
            flags: BundleFlags {
                request_ack: true,
                ..Default::default()
            },
            fixture_index: 0xf0,
        },
        PrivateSpec {
            name: "private-envelope-delivery-ack",
            inner: Payload::Ack {
                for_bundle_id: fixed_id,
                status: 0,
                delivery_hops: 5,
                delivery_ms: 12_345,
                proof: Some(bytes32(0xe1)),
            },
            mailbox: Some([0x5a, 0xa5]),
            flags: BundleFlags::default(),
            fixture_index: 0xf1,
        },
        PrivateSpec {
            name: "private-envelope-session-message-no-mailbox",
            inner: Payload::SessionMessage {
                msg: session_message(0x38, 41, 43, vec![0xc1, 0xc2, 0xc3, 0xc4, 0xc5]),
            },
            mailbox: None,
            flags: BundleFlags::default(),
            fixture_index: 0xf2,
        },
    ]
}

fn signed_bundle(
    sender: &Identity,
    destination: Destination,
    sealed: Sealed,
    index: u64,
) -> Bundle {
    let src = sender.address();
    let id = compute_id(&src, &sealed);
    let inner = SignedInner {
        version: BUNDLE_VERSION,
        app: bytes16(0x81),
        id,
        src,
        dst: destination,
        private: None,
        created_at: CREATED_AT + index,
        lifetime_ms: LIFETIME_MS,
        flags: BundleFlags {
            request_ack: true,
            is_ack: index == 6,
            custody_requested: true,
        },
        priority: 9,
        payload: sealed,
    };
    let sig = sender
        .sign(&postcard::to_allocvec(&inner).expect("inner encodes"))
        .to_vec();
    Bundle {
        inner,
        env: Envelope {
            hop_limit: HOP_LIMIT,
            custody: Some(src),
            copies: COPIES,
            hops: HOPS,
            trace: vec![
                TraceHop {
                    node: bytes8(0x10),
                    app: bytes8(0x20),
                },
                TraceHop {
                    node: bytes8(0x30),
                    app: bytes8(0x40),
                },
            ],
            access: None,
        },
        sig,
    }
}

fn private_bundle(
    recipient: &Identity,
    spec: PrivateSpec,
    ordinal: u64,
) -> (Bundle, Payload, SealFixture) {
    let payload = Payload::Private {
        sender: bytes32(0x71),
        inner: Box::new(spec.inner),
    };
    let plaintext = postcard::to_allocvec(&payload).expect("private payload encodes");
    let seal = deterministic_seal(&recipient.address(), &plaintext, spec.fixture_index);
    let content_id = compute_private_content_id(&seal.sealed);
    let spk = recipient.derive_prekey_epoch(7);
    let recognition_secret = StaticSecret::from(bytes32(0xd1u8.wrapping_add(ordinal as u8)));
    let recognition_public = XPublicKey::from(&recognition_secret).to_bytes();
    let shared = recognition_secret.diffie_hellman(&XPublicKey::from(spk.public));
    let tag = crypto::recognition_tag_from_shared(shared.as_bytes(), &content_id);
    let mut inner = SignedInner {
        version: BUNDLE_VERSION,
        app: bytes16(0x81),
        id: [0u8; 32],
        src: [0u8; 32],
        dst: Destination::Broadcast,
        private: Some(PrivateHeader {
            tag,
            ephemeral: recognition_public,
            mailbox: spec.mailbox,
        }),
        created_at: CREATED_AT + 400 + ordinal,
        lifetime_ms: LIFETIME_MS,
        flags: spec.flags,
        priority: 9,
        payload: seal.sealed.clone(),
    };
    inner.id = compute_private_wire_id(&inner);
    (
        Bundle {
            inner,
            env: Envelope {
                hop_limit: HOP_LIMIT,
                custody: None,
                copies: COPIES,
                hops: 0,
                trace: Vec::new(),
                access: None,
            },
            sig: Vec::new(),
        },
        payload,
        seal,
    )
}

fn deterministic_stamp(bundle_id: &BundleId) -> CarriageStamp {
    Stamper::new(bytes16(0x91), Identity::from_secret_bytes(&bytes32(0xb1)))
        .stamp(bundle_id, CREATED_AT)
}

fn deterministic_seal(recipient: &PubKeyBytes, plaintext: &[u8], index: u8) -> SealFixture {
    let recipient = crypto::address_to_x(recipient).expect("fixed recipient address is valid");
    let secret = bytes32(index.wrapping_add(0x40));
    let ephemeral = StaticSecret::from(secret);
    let ephemeral_pub = XPublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&XPublicKey::from(recipient));
    let key = blake3::hash(shared.as_bytes());
    let nonce = bytes12(index.wrapping_add(0x20));
    let ciphertext = ChaCha20Poly1305::new(&Key::from(*key.as_bytes()))
        .encrypt(&Nonce::from(nonce), plaintext)
        .expect("fixed deterministic seal encrypts");
    SealFixture {
        sealed: Sealed {
            ephemeral_pub,
            nonce,
            ciphertext,
        },
        secret,
    }
}

fn bundle_vector(
    name: &str,
    family: &str,
    payload_variant: Option<&str>,
    primary_payload: bool,
    bundle: &Bundle,
    payload_bytes: &[u8],
    seal: Option<&SealFixture>,
) -> BundleVector {
    let private_header = bundle.inner.private.as_ref();
    let integrity_kind = if bundle.is_private() {
        "PrivateWireId"
    } else if matches!(&bundle.inner.dst, Destination::Vaccine(_)) {
        "VaccineId"
    } else {
        "Ed25519Signature"
    };
    BundleVector {
        name: name.into(),
        family: family.into(),
        payload_variant: payload_variant.map(str::to_string),
        private_inner_variant: if bundle.is_private() {
            private_inner_name(payload_bytes)
        } else {
            None
        },
        primary_payload,
        destination_variant: destination_name(&bundle.inner.dst).into(),
        destination_code: destination_code(&bundle.inner.dst),
        bytes_hex: hex(&bundle.to_bytes().expect("bundle encodes")),
        payload_hex: hex(payload_bytes),
        id_hex: hex(&bundle.id()),
        version: bundle.inner.version,
        private: bundle.is_private(),
        is_ack: bundle.inner.flags.is_ack,
        created_at: bundle.inner.created_at,
        lifetime_ms: bundle.inner.lifetime_ms,
        hop_limit: bundle.env.hop_limit,
        copies: bundle.env.copies,
        hops: bundle.env.hops,
        trace_len: bundle.trace().len(),
        trace_hex: hex(&postcard::to_allocvec(&bundle.env.trace).expect("trace encodes")),
        access_present: bundle.env.access.is_some(),
        access_hex: hex(&postcard::to_allocvec(&bundle.env.access).expect("access encodes")),
        integrity_kind: integrity_kind.into(),
        private_content_id_hex: bundle
            .private_content_id()
            .map_or_else(String::new, |id| hex(&id)),
        recognition_tag_hex: private_header.map_or_else(String::new, |header| hex(&header.tag)),
        recognition_ephemeral_hex: private_header
            .map_or_else(String::new, |header| hex(&header.ephemeral)),
        private_mailbox_present: private_header.is_some_and(|header| header.mailbox.is_some()),
        private_mailbox_hex: private_header
            .and_then(|header| header.mailbox)
            .map_or_else(String::new, |mailbox| hex(&mailbox)),
        seal_ephemeral_secret_hex: seal.map_or_else(String::new, |value| hex(&value.secret)),
        sealed_ephemeral_pub_hex: hex(&bundle.inner.payload.ephemeral_pub),
        seal_nonce_hex: hex(&bundle.inner.payload.nonce),
        ciphertext_hex: hex(&bundle.inner.payload.ciphertext),
        signature_hex: hex(&bundle.sig),
    }
}

fn private_inner_name(payload_bytes: &[u8]) -> Option<String> {
    let payload: Payload = postcard::from_bytes(payload_bytes).expect("vector payload decodes");
    match payload {
        Payload::Private { inner, .. } => Some(payload_name(&inner).into()),
        _ => None,
    }
}

fn nested_layouts(reference_id: &BundleId) -> Vec<EncodingVector> {
    let mut out = Vec::new();
    for kind in [StreamKind::Sse, StreamKind::WebSocket] {
        out.push(encoded("stream-kind", stream_kind_name(kind), &kind));
    }
    for kind in [ServiceKind::Channel, ServiceKind::Service] {
        out.push(encoded("service-kind", service_kind_name(kind), &kind));
    }
    for mode in [
        AccessMode::Open,
        AccessMode::RequestToJoin,
        AccessMode::Invite,
    ] {
        out.push(encoded("access-mode", access_mode_name(mode), &mode));
    }
    for visibility in [Visibility::Private, Visibility::Discoverable] {
        out.push(encoded(
            "visibility",
            visibility_name(visibility),
            &visibility,
        ));
    }
    out.push(encoded(
        "layout",
        "BundleFlags",
        &BundleFlags {
            request_ack: true,
            is_ack: false,
            custody_requested: true,
        },
    ));
    out.push(encoded(
        "layout",
        "RatchetHeader",
        &Header {
            dh: bytes32(0x31),
            pn: u32::MAX - 1,
            n: u32::MAX,
        },
    ));
    out.push(encoded(
        "layout",
        "RatchetMessage",
        &RatchetMessage {
            header: Header {
                dh: bytes32(0x31),
                pn: 1,
                n: 2,
            },
            ciphertext: vec![0x00, 0x80, 0xff],
        },
    ));
    out.push(encoded(
        "layout",
        "PrivateHeaderMailboxSome",
        &PrivateHeader {
            tag: bytes16(0x41),
            ephemeral: bytes32(0x51),
            mailbox: Some([0xa5, 0x5a]),
        },
    ));
    out.push(encoded(
        "layout",
        "PrivateHeaderMailboxNone",
        &PrivateHeader {
            tag: bytes16(0x41),
            ephemeral: bytes32(0x51),
            mailbox: None,
        },
    ));
    let envelope = Envelope {
        hop_limit: HOP_LIMIT,
        custody: Some(bytes32(0x61)),
        copies: COPIES,
        hops: HOPS,
        trace: vec![TraceHop {
            node: bytes8(0x10),
            app: bytes8(0x20),
        }],
        access: None,
    };
    out.push(encoded("layout", "EnvelopeAccessNone", &envelope));
    let mut stamped_envelope = envelope;
    stamped_envelope.access = Some(Box::new(deterministic_stamp(reference_id)));
    out.push(encoded("layout", "EnvelopeAccessSome", &stamped_envelope));
    out.push(encoded(
        "layout",
        "TopicMetaChannelPrivate",
        &TopicMeta {
            path: "/vector/channel".into(),
            kind: ServiceKind::Channel,
            title: "Vector channel".into(),
            summary: "Private deterministic topic".into(),
            tags: vec!["wire".into(), "v9".into()],
            access: AccessMode::RequestToJoin,
            service_pubkey: None,
        },
    ));
    out.push(encoded(
        "layout",
        "TopicMetaServiceDiscoverable",
        &TopicMeta {
            path: "/vector/service".into(),
            kind: ServiceKind::Service,
            title: "Vector service".into(),
            summary: "Discoverable deterministic topic".into(),
            tags: vec!["rpc".into()],
            access: AccessMode::Invite,
            service_pubkey: Some(bytes32(0x34)),
        },
    ));
    out.push(encoded(
        "layout",
        "Frame",
        &Frame {
            bundle_id: bytes32(0xa0),
            frag_index: 1,
            frag_count: 3,
            bytes: vec![0x00, 0x7f, 0x80, 0xff],
        },
    ));
    out
}

fn advert_vectors(sender: &Identity) -> Vec<EncodingVector> {
    let spk = sender.derive_prekey_epoch(7);
    let kinds = vec![
        AdvertKind::Service {
            service: "vector.service".into(),
            title: "Wire vectors".into(),
            summary: "Deterministic public advert".into(),
            tags: vec!["v9".into(), "audit".into()],
        },
        AdvertKind::PreKey {
            spk_pub: spk.public,
            spk_sig: spk.sig.to_vec(),
        },
        AdvertKind::Tombstone {
            revokes: bytes32(0xa0),
        },
        AdvertKind::HpsTopic {
            nonce: bytes12(0x22),
            ct: vec![0x00, 0x80, 0xfe, 0xff],
        },
        AdvertKind::RecvBeacon {
            mailbox: bytes16(0x33),
        },
    ];
    kinds
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            let variant = advert_kind_name(&kind);
            let advert = Advert::publish_in(
                bytes16(0x81),
                sender,
                kind,
                CREATED_AT + index as u64,
                60_000,
                100 + index as u64,
            )
            .expect("fixed advert publishes");
            advert.verify().expect("fixed advert verifies");
            EncodingVector {
                name: format!("advert-{variant}"),
                family: "advert".into(),
                variant: variant.into(),
                bytes_hex: hex(&postcard::to_allocvec(&advert).expect("advert encodes")),
            }
        })
        .collect()
}

fn advert_kind_name(kind: &AdvertKind) -> &'static str {
    match kind {
        AdvertKind::Service { .. } => "Service",
        AdvertKind::PreKey { .. } => "PreKey",
        AdvertKind::Tombstone { .. } => "Tombstone",
        AdvertKind::HpsTopic { .. } => "HpsTopic",
        AdvertKind::RecvBeacon { .. } => "RecvBeacon",
    }
}

fn stream_kind_name(kind: StreamKind) -> &'static str {
    match kind {
        StreamKind::Sse => "Sse",
        StreamKind::WebSocket => "WebSocket",
    }
}

fn service_kind_name(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Channel => "Channel",
        ServiceKind::Service => "Service",
    }
}

fn access_mode_name(mode: AccessMode) -> &'static str {
    match mode {
        AccessMode::Open => "Open",
        AccessMode::RequestToJoin => "RequestToJoin",
        AccessMode::Invite => "Invite",
    }
}

fn visibility_name(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Private => "Private",
        Visibility::Discoverable => "Discoverable",
    }
}

fn encoded<T: Serialize>(family: &str, variant: &str, value: &T) -> EncodingVector {
    EncodingVector {
        name: format!("{}-{}", family, variant).to_ascii_lowercase(),
        family: family.into(),
        variant: variant.into(),
        bytes_hex: hex(&postcard::to_allocvec(value).expect("layout encodes")),
    }
}

fn bytes8(start: u8) -> [u8; 8] {
    sequence(start)
}

fn bytes12(start: u8) -> [u8; 12] {
    sequence(start)
}

fn bytes16(start: u8) -> [u8; 16] {
    sequence(start)
}

fn bytes32(start: u8) -> [u8; 32] {
    sequence(start)
}

fn sequence<const N: usize>(start: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = start.wrapping_add(index as u8);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("generated hex contains an invalid digit"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn corpus_covers_every_current_wire_enum_variant() {
        let corpus = corpus();
        assert_eq!(corpus.bundle_version, 10);
        let destinations: BTreeSet<_> = corpus
            .destinations
            .iter()
            .map(|vector| vector.variant.as_str())
            .collect();
        assert_eq!(
            destinations,
            BTreeSet::from(["Device", "AckTo", "Broadcast", "Vaccine"]),
            "destination_name is exhaustive, and every named variant needs a vector"
        );
        assert_eq!(corpus.adverts.len(), 5);
        assert_eq!(
            corpus
                .link_packets
                .iter()
                .map(|vector| vector.variant.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["Handshake", "Data", "DataFrag"]),
            "link_packet_name is exhaustive, and every named variant needs a vector"
        );
        assert_eq!(
            corpus
                .wire_records
                .iter()
                .map(|vector| vector.variant.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["Bundle", "Advert", "Have"]),
            "wire_record_name is exhaustive, and every named variant needs a vector"
        );
        assert_eq!(
            corpus
                .have_sets
                .iter()
                .map(|vector| vector.variant.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["Empty", "NonEmpty"])
        );
        let payloads: BTreeSet<_> = corpus
            .bundles
            .iter()
            .filter(|vector| vector.primary_payload)
            .filter_map(|vector| vector.payload_variant.as_deref())
            .collect();
        assert_eq!(
            payloads,
            BTreeSet::from([
                "HttpRequest",
                "HttpResponse",
                "PeerMessage",
                "SessionInit",
                "SessionMessage",
                "Private",
                "Ack",
                "StreamOpen",
                "StreamData",
                "StreamAck",
                "StreamClose",
                "ServiceRequest",
                "ServiceResponse",
                "Carrier",
                "HpsJoinRequest",
                "HpsKeys",
                "HpsInvite",
                "HpsInviteAccept",
                "HpsLeave",
                "HpsRekey",
                "HpsReachAck",
                "HpsPublish",
                "SessionReset",
            ]),
            "payload_name is exhaustive, and every named variant needs one primary vector"
        );
        assert!(
            corpus
                .bundles
                .iter()
                .all(|vector| vector.version == BUNDLE_VERSION),
            "every complete bundle must use the current wire version"
        );
        assert_eq!(corpus.bundles.len(), 30);
        let mut private_inner: Vec<_> = corpus
            .bundles
            .iter()
            .filter(|vector| vector.private)
            .filter_map(|vector| vector.private_inner_variant.as_deref())
            .collect();
        private_inner.sort_unstable();
        assert_eq!(
            private_inner,
            vec!["Ack", "SessionInit", "SessionMessage", "SessionMessage"]
        );
        assert_eq!(corpus.bundles.iter().filter(|v| v.private).count(), 4);
        assert_eq!(
            corpus
                .bundles
                .iter()
                .filter(|vector| vector.private && !vector.private_mailbox_present)
                .count(),
            1
        );
        assert!(corpus
            .bundles
            .iter()
            .any(|vector| vector.name == "traced-envelope-empty-forwarding"));
        assert!(corpus
            .bundles
            .iter()
            .any(|vector| vector.name == "traced-envelope-carriage-stamped"));
        assert_eq!(
            corpus
                .bundles
                .iter()
                .filter(|vector| vector.access_present)
                .count(),
            1
        );
        assert_eq!(
            corpus
                .bundles
                .iter()
                .filter(|v| v.destination_variant == "Vaccine")
                .count(),
            1
        );
    }

    #[test]
    fn link_and_store_vectors_are_exact_canonical_encodings() {
        let corpus = corpus();
        for vector in corpus.link_packets {
            let bytes = decode_hex(&vector.bytes_hex);
            let packet: LinkPacket = postcard::from_bytes(&bytes).expect("link packet decodes");
            assert_eq!(link_packet_name(&packet), vector.variant);
            assert_eq!(
                postcard::to_allocvec(&packet).expect("link packet re-encodes"),
                bytes,
                "{} is not canonical",
                vector.name
            );
        }

        let auth_bytes = decode_hex(&corpus.link_auth.bytes_hex);
        let auth: LinkAuth = postcard::from_bytes(&auth_bytes).expect("link auth decodes");
        assert_eq!(
            auth.address,
            Identity::from_secret_bytes(&bytes32(0x11)).address()
        );
        assert_eq!(
            postcard::to_allocvec(&auth).expect("link auth re-encodes"),
            auth_bytes
        );

        for vector in corpus.wire_records {
            let bytes = decode_hex(&vector.bytes_hex);
            let wire: Wire = postcard::from_bytes(&bytes).expect("wire record decodes");
            assert_eq!(wire_record_name(&wire), vector.variant);
            assert_eq!(
                postcard::to_allocvec(&wire).expect("wire record re-encodes"),
                bytes,
                "{} is not canonical",
                vector.name
            );
        }

        for vector in corpus.have_sets {
            let bytes = decode_hex(&vector.bytes_hex);
            let have: HaveSet = postcard::from_bytes(&bytes).expect("HaveSet decodes");
            assert_eq!(have.ids.is_empty(), vector.variant == "Empty");
            assert_eq!(
                postcard::to_allocvec(&have).expect("HaveSet re-encodes"),
                bytes,
                "{} is not canonical",
                vector.name
            );
        }
    }

    #[test]
    fn complete_bundle_vectors_are_exact_canonical_encodings() {
        for vector in corpus().bundles {
            let bytes = decode_hex(&vector.bytes_hex);
            let bundle = Bundle::from_bytes(&bytes).expect("complete vector decodes");
            bundle.verify().expect("complete vector verifies");
            assert_eq!(
                bundle.to_bytes().expect("complete vector re-encodes"),
                bytes,
                "{} is not canonical",
                vector.name
            );
            let expected_id = vector.id_hex_bytes();
            assert_eq!(
                bundle.id().as_slice(),
                expected_id.as_slice(),
                "{} id",
                vector.name
            );
            assert_eq!(bundle.env.access.is_some(), vector.access_present);
            assert_eq!(
                postcard::to_allocvec(&bundle.env.access).expect("access re-encodes"),
                decode_hex(&vector.access_hex),
                "{} access layout",
                vector.name
            );
            if !vector.payload_hex.is_empty() {
                let payload_bytes = decode_hex(&vector.payload_hex);
                let payload: Payload =
                    postcard::from_bytes(&payload_bytes).expect("payload vector decodes");
                assert_eq!(
                    postcard::to_allocvec(&payload).expect("payload vector re-encodes"),
                    payload_bytes,
                    "{} payload layout",
                    vector.name
                );
            }
        }
    }

    #[test]
    fn corpus_locks_stamped_and_unstamped_access_layouts() {
        let corpus = corpus();
        let bare = corpus
            .bundles
            .iter()
            .find(|vector| vector.name == "traced-envelope-empty-forwarding")
            .expect("bare traced vector");
        let stamped = corpus
            .bundles
            .iter()
            .find(|vector| vector.name == "traced-envelope-carriage-stamped")
            .expect("stamped traced vector");
        let bare_bundle = Bundle::from_bytes(&decode_hex(&bare.bytes_hex)).expect("bare decodes");
        let stamped_bundle =
            Bundle::from_bytes(&decode_hex(&stamped.bytes_hex)).expect("stamped decodes");

        assert!(!bare.access_present);
        assert!(stamped.access_present);
        assert_eq!(bare.access_hex, "00");
        assert!(stamped.access_hex.starts_with("01"));
        assert_eq!(bare_bundle.inner, stamped_bundle.inner);
        assert_eq!(bare_bundle.sig, stamped_bundle.sig);
        assert_eq!(bare_bundle.id(), stamped_bundle.id());
        let mut stripped = stamped_bundle;
        stripped.env.access = None;
        assert_eq!(stripped, bare_bundle);

        for (variant, present) in [("EnvelopeAccessNone", false), ("EnvelopeAccessSome", true)] {
            let vector = corpus
                .nested_layouts
                .iter()
                .find(|vector| vector.variant == variant)
                .expect("envelope access layout");
            let bytes = decode_hex(&vector.bytes_hex);
            let envelope: Envelope = postcard::from_bytes(&bytes).expect("envelope decodes");
            assert_eq!(envelope.access.is_some(), present);
            assert_eq!(postcard::to_allocvec(&envelope).unwrap(), bytes);
        }
    }

    #[test]
    fn corpus_locks_hps_remediation_authentication_fields() {
        let corpus = corpus();
        let sender = Identity::from_secret_bytes(&bytes32(0x11));
        let app = bytes16(0x81);
        let sender_addr = sender.address();

        let reach = corpus
            .bundles
            .iter()
            .find(|vector| vector.name == "payload-hps-reach-ack")
            .expect("reach ACK vector");
        let reach_payload: Payload =
            postcard::from_bytes(&decode_hex(&reach.payload_hex)).expect("reach ACK decodes");
        match reach_payload {
            Payload::HpsReachAck {
                topic_tag,
                epoch,
                mac,
            } => assert_eq!(
                mac,
                hps::reach_ack_mac(&bytes32(0xd1), &app, &sender_addr, &topic_tag, epoch)
            ),
            other => panic!("expected HpsReachAck, got {other:?}"),
        }

        let publish = corpus
            .bundles
            .iter()
            .find(|vector| vector.name == "payload-hps-publish")
            .expect("publish vector");
        let publish_payload: Payload =
            postcard::from_bytes(&decode_hex(&publish.payload_hex)).expect("publish decodes");
        match publish_payload {
            Payload::HpsPublish {
                topic_tag,
                epoch,
                nonce,
                ciphertext,
                sig,
            } => {
                let nonce: [u8; 12] = nonce.try_into().expect("12-byte publish nonce");
                let sig: [u8; 64] = sig.try_into().expect("64-byte publish signature");
                assert!(hps::verify_publish(
                    &sender_addr,
                    &app,
                    &sender_addr,
                    &topic_tag,
                    epoch,
                    &nonce,
                    &ciphertext,
                    &sig,
                ));
            }
            other => panic!("expected HpsPublish, got {other:?}"),
        }
    }

    #[test]
    fn committed_corpus_matches_deterministic_source() {
        let expected = serde_json::to_string_pretty(&corpus()).expect("corpus serializes") + "\n";
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_FILE);
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "cannot read {}: {error}; run cargo run -p hop-core --example wire-vectors --features wire-vectors -- --generate",
                path.display()
            )
        });
        assert_eq!(
            committed,
            expected,
            "wire vector drift: review BUNDLE_VERSION intentionally, then regenerate with the documented command"
        );
    }
}
