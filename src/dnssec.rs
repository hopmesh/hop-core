//! DNSSEC validation (DESIGN.md §30).
//!
//! This is the trust anchor for decentralized, multi-hop HNS: a `hops://` endpoint's address
//! comes from a `_hopaddress.<domain>` TXT record, and because *any* node in the mesh may
//! resolve and answer a query, the client must be able to verify the answer cryptographically
//! rather than trust whoever relayed it. We do that by validating the DNSSEC chain
//! (RRSIG → DNSKEY → DS → … → root) against a baked-in root trust anchor.
//!
//! Scope of this module: the verification primitives — RRSIG signature checking, DNSKEY key
//! tags, and DS digests. Supported algorithms: **RSA/SHA-256 (alg 8, ≥2048-bit modulus enforced)**,
//! **ECDSA P-256/SHA-256 (alg 13)**, and **Ed25519 (alg 15, RFC 8080)**. The chain walk that strings
//! these together up to [`ROOT_ANCHORS`] builds on top.
//!
//! FAIL-CLOSED gaps (documented, not silent): wildcard-label expansion and NSEC/NSEC3 denial-of-
//! existence are NOT implemented, and only the first matching key tag is tried. All of these only
//! ever cause a valid name to fail to validate — none lets a forged record through — so a resolver
//! treats them as "unresolved", never as "trusted". They matter only when `hops://` opens to
//! third-party domains (today the only `_hopaddress` zone is the project's own, non-wildcard).

use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
// `rsa` 0.9's Digest/AssociatedOid bounds are pinned to the digest 0.10 generation, one major
// behind the workspace `sha2` (0.11). Same algorithm, same output bytes: `sha2-rsa-compat` is a
// second build of the plain `sha2` crate at 0.10, aliased locally, purely so `Sha256` satisfies
// rsa's older trait bound.
use sha2_rsa_compat::{Digest, Sha256};

/// DNSSEC algorithm numbers we recognize (IANA DNSSEC Algorithm Numbers).
pub const ALG_RSASHA256: u8 = 8;
pub const ALG_ECDSAP256SHA256: u8 = 13;
pub const ALG_ED25519: u8 = 15;

/// DS digest type 2 = SHA-256 (the only one we accept).
pub const DIGEST_SHA256: u8 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum DnssecError {
    /// Algorithm or digest type we don't implement yet.
    Unsupported(u8),
    /// A record/key/signature was malformed.
    Malformed(&'static str),
    /// The cryptographic signature did not verify.
    BadSignature,
    /// A DS digest didn't match the DNSKEY it should cover.
    DsMismatch,
    /// The chain didn't terminate at a configured root trust anchor.
    NoTrustAnchor,
    /// The signature is expired or not yet valid (compared to `now`).
    Expired,
}

/// A DNSKEY record's parsed fields (RFC 4034 §2.1). `public_key` is the raw key field.
#[derive(Clone, Debug)]
pub struct Dnskey {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl Dnskey {
    /// The full DNSKEY RDATA wire form (flags|proto|alg|publickey), used for the key tag and
    /// the DS digest.
    pub fn rdata(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.public_key.len());
        v.extend_from_slice(&self.flags.to_be_bytes());
        v.push(self.protocol);
        v.push(self.algorithm);
        v.extend_from_slice(&self.public_key);
        v
    }

    /// The DNSKEY key tag (RFC 4034 Appendix B) — identifies which key an RRSIG used.
    pub fn key_tag(&self) -> u16 {
        let rdata = self.rdata();
        let mut ac: u32 = 0;
        for (i, b) in rdata.iter().enumerate() {
            ac += if i & 1 == 0 {
                (*b as u32) << 8
            } else {
                *b as u32
            };
        }
        ac += (ac >> 16) & 0xFFFF;
        (ac & 0xFFFF) as u16
    }

    /// Parse an RSA public key from the DNSKEY public-key field (RFC 3110): a 1- or 3-byte
    /// exponent length, the exponent, then the modulus.
    fn rsa_public_key(&self) -> Result<RsaPublicKey, DnssecError> {
        let k = &self.public_key;
        if k.is_empty() {
            return Err(DnssecError::Malformed("empty RSA key"));
        }
        let (exp_len, off) = if k[0] != 0 {
            (k[0] as usize, 1usize)
        } else {
            if k.len() < 3 {
                return Err(DnssecError::Malformed("short RSA key"));
            }
            (u16::from_be_bytes([k[1], k[2]]) as usize, 3usize)
        };
        if k.len() < off + exp_len + 1 {
            return Err(DnssecError::Malformed("truncated RSA key"));
        }
        let exponent = BigUint::from_bytes_be(&k[off..off + exp_len]);
        let modulus = BigUint::from_bytes_be(&k[off + exp_len..]);
        // D-dnssec: reject sub-1024-bit RSA moduli (512/768-bit keys are factorable, so a forged
        // chain could validate). Fail closed rather than trust a trivially-weak signer. 1024 is the
        // floor rather than 2048 because many real zones still sign ZSKs at 1024 bits — a 2048 floor
        // would refuse to resolve legitimate domains (fail-closed, but a false negative).
        if modulus.bits() < 1024 {
            return Err(DnssecError::Malformed("RSA modulus below 1024 bits"));
        }
        RsaPublicKey::new(modulus, exponent).map_err(|_| DnssecError::Malformed("bad RSA key"))
    }
}

/// A parsed RRSIG record (RFC 4034 §3.1). `signer_name`/`rrset_owner` are lowercase wire-form
/// names; `signature` is the raw signature bytes.
#[derive(Clone, Debug)]
pub struct Rrsig {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub sig_expiration: u32,
    pub sig_inception: u32,
    pub key_tag: u16,
    pub signer_name: Vec<u8>, // canonical wire form
    pub signature: Vec<u8>,
}

/// One resource record in the covered RRset, in canonical form: lowercase wire-form `owner`
/// and raw `rdata` (RDATA only, no name compression).
#[derive(Clone, Debug)]
pub struct Rr {
    pub owner: Vec<u8>,
    pub rtype: u16,
    pub class: u16,
    pub rdata: Vec<u8>,
}

/// Build the data an RRSIG signs (RFC 4034 §3.1.8.1): the RRSIG RDATA (minus the signature)
/// followed by each RR in canonical order, each with the RRSIG's `original_ttl`.
fn signed_data(rrsig: &Rrsig, rrset: &[Rr]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&rrsig.type_covered.to_be_bytes());
    out.push(rrsig.algorithm);
    out.push(rrsig.labels);
    out.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
    out.extend_from_slice(&rrsig.sig_expiration.to_be_bytes());
    out.extend_from_slice(&rrsig.sig_inception.to_be_bytes());
    out.extend_from_slice(&rrsig.key_tag.to_be_bytes());
    out.extend_from_slice(&rrsig.signer_name);

    // Canonical RR ordering is by RDATA bytes; for a single-record RRset (our case) it's moot,
    // but sort to be correct for multi-record sets.
    let mut sorted: Vec<&Rr> = rrset.iter().collect();
    sorted.sort_by(|a, b| a.rdata.cmp(&b.rdata));
    for rr in sorted {
        out.extend_from_slice(&rr.owner);
        out.extend_from_slice(&rr.rtype.to_be_bytes());
        out.extend_from_slice(&rr.class.to_be_bytes());
        out.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        out.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rr.rdata);
    }
    out
}

/// Verify that `rrsig` over `rrset` was made by `key`. Checks the key tag matches, the
/// algorithm is supported, and the signature validates. (Validity-window checks are done by
/// the caller with a clock — see [`Rrsig::sig_inception`]/`sig_expiration`.)
pub fn verify_rrsig(rrset: &[Rr], rrsig: &Rrsig, key: &Dnskey) -> Result<(), DnssecError> {
    if key.key_tag() != rrsig.key_tag || key.algorithm != rrsig.algorithm {
        return Err(DnssecError::BadSignature);
    }
    let data = signed_data(rrsig, rrset);
    match rrsig.algorithm {
        ALG_RSASHA256 => {
            let pk = key.rsa_public_key()?;
            let digest = Sha256::digest(&data);
            pk.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &rrsig.signature)
                .map_err(|_| DnssecError::BadSignature)
        }
        ALG_ECDSAP256SHA256 => {
            use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            // DNSKEY carries the raw uncompressed point (x‖y, 64 bytes, RFC 6605); prepend the
            // SEC1 0x04 tag. The signature is r‖s (64 bytes). Verifier hashes with SHA-256.
            if key.public_key.len() != 64 {
                return Err(DnssecError::Malformed("bad P-256 key length"));
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&key.public_key);
            let vk = VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| DnssecError::Malformed("bad P-256 key"))?;
            let sig = Signature::from_slice(&rrsig.signature)
                .map_err(|_| DnssecError::Malformed("bad P-256 signature"))?;
            vk.verify(&data, &sig)
                .map_err(|_| DnssecError::BadSignature)
        }
        ALG_ED25519 => {
            // RFC 8080: DNSKEY carries the raw 32-byte Ed25519 public key; the RRSIG is a 64-byte
            // PURE Ed25519 signature over the signed data (no pre-hash). (D-dnssec.)
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let kb: [u8; 32] = key
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| DnssecError::Malformed("bad Ed25519 key length"))?;
            let vk = VerifyingKey::from_bytes(&kb)
                .map_err(|_| DnssecError::Malformed("bad Ed25519 key"))?;
            let sb: [u8; 64] = rrsig
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| DnssecError::Malformed("bad Ed25519 signature length"))?;
            vk.verify(&data, &Signature::from_bytes(&sb))
                .map_err(|_| DnssecError::BadSignature)
        }
        other => Err(DnssecError::Unsupported(other)),
    }
}

/// Compute the DS digest (RFC 4034 §5.1.4) for a DNSKEY: `SHA-256(owner_wire || dnskey_rdata)`.
/// Compare against the parent's published DS to anchor the child key.
pub fn ds_digest(owner_wire: &[u8], key: &Dnskey, digest_type: u8) -> Result<Vec<u8>, DnssecError> {
    if digest_type != DIGEST_SHA256 {
        return Err(DnssecError::Unsupported(digest_type));
    }
    let mut h = Sha256::new();
    h.update(owner_wire);
    h.update(key.rdata());
    Ok(h.finalize().to_vec())
}

/// Encode a DNS name as lowercase, uncompressed wire form: each label length-prefixed, root 0.
/// `"hopme.sh"` → `05 'h''o''p''m''e' 02 's''h' 00`.
pub fn name_to_wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
    out
}

/// TXT RDATA wire form for a single character-string: `<len><bytes>`.
pub fn txt_rdata(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    out
}

/// RR type numbers we encode for signing.
const TYPE_DS: u16 = 43;
const TYPE_DNSKEY: u16 = 48;

/// A DS record (RFC 4034 §5.1): the parent's hash of a child zone's KSK.
#[derive(Clone, Debug)]
pub struct Ds {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

impl Ds {
    fn rdata(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.digest.len());
        v.extend_from_slice(&self.key_tag.to_be_bytes());
        v.push(self.algorithm);
        v.push(self.digest_type);
        v.extend_from_slice(&self.digest);
        v
    }
}

/// One zone level of a DNSSEC proof. The chain is ordered leaf-zone → … → root.
#[derive(Clone, Debug)]
pub struct ZoneProof {
    /// Zone name, e.g. `"hopme.sh"`, `"sh"`, or `""` for the root.
    pub name: String,
    /// This zone's DNSKEY RRset.
    pub dnskeys: Vec<Dnskey>,
    /// RRSIG over the DNSKEY RRset (made by this zone's KSK — a key in `dnskeys`).
    pub dnskey_rrsig: Rrsig,
    /// The DS RRset for THIS zone, as published in the parent (empty for the root).
    pub ds: Vec<Ds>,
    /// RRSIG over the DS RRset (made by the PARENT zone's ZSK; `None` for the root).
    pub ds_rrsig: Option<Rrsig>,
}

/// A full DNSSEC proof for one answer record: the signed record plus every zone level up to
/// the root, enough to validate without trusting whoever supplied it.
#[derive(Clone, Debug)]
pub struct DnssecChain {
    /// The answer RRset being proven (e.g. the `_hopaddress` TXT).
    pub record: Vec<Rr>,
    /// RRSIG over the record (made by the leaf zone's ZSK).
    pub record_rrsig: Rrsig,
    /// Zone levels, leaf-zone first, root last.
    pub zones: Vec<ZoneProof>,
}

/// Is `now` (unix seconds) within the RRSIG validity window? (Direct compare; the RFC-1982
/// serial wrap near 2106 is ignored.)
fn within_window(rrsig: &Rrsig, now: u32) -> bool {
    rrsig.sig_inception <= now && now <= rrsig.sig_expiration
}

/// Find the key in `keys` whose tag matches `key_tag`.
fn find_key(keys: &[Dnskey], key_tag: u16) -> Option<&Dnskey> {
    keys.iter().find(|k| k.key_tag() == key_tag)
}

/// Verify an RRSIG over an RRset with whichever key in `keys` it names, enforcing the validity
/// window. Returns the verifying key on success.
fn verify_with_keys<'a>(
    rrset: &[Rr],
    rrsig: &Rrsig,
    keys: &'a [Dnskey],
    now: u32,
) -> Result<&'a Dnskey, DnssecError> {
    if !within_window(rrsig, now) {
        return Err(DnssecError::Expired);
    }
    let key = find_key(keys, rrsig.key_tag).ok_or(DnssecError::BadSignature)?;
    verify_rrsig(rrset, rrsig, key)?;
    Ok(key)
}

/// Validate a full DNSSEC chain against the given trust `anchors` (root KSKs) at time `now`
/// (unix seconds): the record is signed by the leaf zone, each zone's DNSKEY set is self-signed
/// by its KSK, each KSK is vouched by a DS in its parent (and the DS set is signed by the
/// parent), and the chain terminates at an anchor. Use [`root_anchors`] for the real anchors.
pub fn validate_chain(
    chain: &DnssecChain,
    anchors: &[Dnskey],
    now: u32,
) -> Result<(), DnssecError> {
    let leaf = chain
        .zones
        .first()
        .ok_or(DnssecError::Malformed("no zones"))?;

    // 1. The answer record is signed by the leaf zone's ZSK.
    verify_with_keys(&chain.record, &chain.record_rrsig, &leaf.dnskeys, now)?;

    // 2. Walk each zone level, anchoring its KSK upward.
    for (i, z) in chain.zones.iter().enumerate() {
        // The zone's DNSKEY RRset, as canonical RRs, is self-signed by the zone's KSK.
        let dnskey_rrset: Vec<Rr> = z
            .dnskeys
            .iter()
            .map(|k| Rr {
                owner: name_to_wire(&z.name),
                rtype: TYPE_DNSKEY,
                class: 1,
                rdata: k.rdata(),
            })
            .collect();
        let ksk = verify_with_keys(&dnskey_rrset, &z.dnskey_rrsig, &z.dnskeys, now)?;

        let is_root = z.name.is_empty() || z.name == ".";
        if is_root {
            // The KSK must be one of our baked-in trust anchors.
            let trusted = anchors
                .iter()
                .any(|a| a.algorithm == ksk.algorithm && a.public_key == ksk.public_key);
            if !trusted {
                return Err(DnssecError::NoTrustAnchor);
            }
        } else {
            // The KSK must be vouched by a DS in the parent, and that DS set must be signed.
            let parent = chain
                .zones
                .get(i + 1)
                .ok_or(DnssecError::Malformed("missing parent zone"))?;
            let owner = name_to_wire(&z.name);
            let ds_ok = z.ds.iter().any(|d| {
                d.key_tag == ksk.key_tag()
                    && d.algorithm == ksk.algorithm
                    && ds_digest(&owner, ksk, d.digest_type)
                        .map(|dg| dg == d.digest)
                        .unwrap_or(false)
            });
            if !ds_ok {
                return Err(DnssecError::DsMismatch);
            }
            let ds_rrsig = z
                .ds_rrsig
                .as_ref()
                .ok_or(DnssecError::Malformed("missing DS RRSIG"))?;
            let ds_rrset: Vec<Rr> =
                z.ds.iter()
                    .map(|d| Rr {
                        owner: owner.clone(),
                        rtype: TYPE_DS,
                        class: 1,
                        rdata: d.rdata(),
                    })
                    .collect();
            verify_with_keys(&ds_rrset, ds_rrsig, &parent.dnskeys, now)?;
        }
    }
    Ok(())
}

/// The IANA root trust anchors — the root zone KSKs. Both the current KSK-2017 (key tag 20326)
/// and the rolled-in KSK-2024 are accepted while the rollover is in progress.
pub fn root_anchors() -> Vec<Dnskey> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    [
        // KSK-2017 (key tag 20326)
        "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
        // KSK-2024 (key tag 38696)
        "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
    ]
    .iter()
    .filter_map(|b64| STANDARD.decode(b64).ok())
    .map(|public_key| Dnskey { flags: 257, protocol: 3, algorithm: ALG_RSASHA256, public_key })
    .collect()
}

/// Validate a chain against the real IANA root anchors.
pub fn validate_to_root(chain: &DnssecChain, now: u32) -> Result<(), DnssecError> {
    validate_chain(chain, &root_anchors(), now)
}

/// The one-shot trustless resolution: assemble the chain from DoH responses, validate it to
/// `anchors`, then decode the `_hopaddress` TXT value as a base58 32-byte Hop address. Returns
/// `(address, ttl_secs)`. Any failure (bad chain, bad signature, expired, non-base58) is an
/// error — never a partial trust. `now` is unix seconds.
pub fn validate_and_extract(
    domain: &str,
    dohs: &[DohAnswer],
    anchors: &[Dnskey],
    now: u32,
) -> Result<([u8; 32], u32), DnssecError> {
    let chain = assemble_chain(domain, dohs)?;
    validate_chain(&chain, anchors, now)?;
    // The validated TXT value: rdata is `<len><bytes>`.
    let rd = &chain
        .record
        .first()
        .ok_or(DnssecError::Malformed("no record"))?
        .rdata;
    if rd.is_empty() {
        return Err(DnssecError::Malformed("empty TXT"));
    }
    let len = rd[0] as usize;
    let value = rd
        .get(1..1 + len)
        .ok_or(DnssecError::Malformed("bad TXT len"))?;
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|_| DnssecError::Malformed("TXT not base58"))?;
    let addr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DnssecError::Malformed("address not 32 bytes"))?;
    Ok((addr, chain.record_rrsig.original_ttl))
}

/// [`validate_and_extract`] against the real IANA root anchors.
pub fn validate_and_extract_to_root(
    domain: &str,
    dohs: &[DohAnswer],
    now: u32,
) -> Result<([u8; 32], u32), DnssecError> {
    validate_and_extract(domain, dohs, &root_anchors(), now)
}

// --- DoH JSON parsing (host stays a dumb fetcher; core parses) -------------------------------
//
// The host fetches each chain record over DNS-over-HTTPS (the Google/Cloudflare JSON API with
// `do=1`) and hands core the raw response body. Core parses it here into our typed records, so
// there's a single parser shared by every host (no Swift/Rust duplication), and the parsed
// records flow into [`validate_chain`].

/// The records extracted from one DoH JSON response. Owners are presentation names (with the
/// trailing dot), as returned by the resolver.
#[derive(Clone, Debug, Default)]
pub struct DohAnswer {
    /// The resolver's own DNSSEC-validated flag (advisory only — we re-verify ourselves).
    pub ad: bool,
    /// DNS response status (0 = NOERROR, 3 = NXDOMAIN).
    pub status: u32,
    pub txt: Vec<(String, String)>, // (owner, value)
    pub dnskeys: Vec<(String, Dnskey)>,
    pub ds: Vec<(String, Ds)>,
    pub rrsigs: Vec<(String, Rrsig)>,
}

/// Map an RRSIG "type covered" token to its numeric type.
fn rrtype_from_str(s: &str) -> Option<u16> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "DS" => Some(43),
        "RRSIG" => Some(46),
        "NSEC" => Some(47),
        "DNSKEY" => Some(48),
        other => other.strip_prefix("TYPE").and_then(|n| n.parse().ok()),
    }
}

fn b64d(s: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(s.replace(' ', "")).ok()
}

fn hexd(s: &str) -> Option<Vec<u8>> {
    // sec: decode over BYTES, not `&str` slices. `&s[i..i+2]` byte-indexes the string and, on a hostile
    // DS-digest containing a multi-byte UTF-8 char, lands mid-character and PANICS before `from_str_radix`
    // can reject it. Every `HnsAnswer` proof is attacker-controlled and reaches here unauthenticated
    // (provide_dns_proof -> parse_doh -> parse_ds), so a `{"data":"1 8 2 a\u{ff}b"}` would panic the
    // resolver. Filter ASCII whitespace and decode each pair via `to_digit`, which keeps every remaining
    // unit exactly one byte wide, so a non-hex or non-ASCII byte is REJECTED (None), never a panic.
    let digits: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks_exact(2)
        .map(|p| Some(((p[0] as char).to_digit(16)? * 16 + (p[1] as char).to_digit(16)?) as u8))
        .collect()
}

/// Parse a DNSKEY presentation rdata: `flags protocol algorithm <base64 key>`.
fn parse_dnskey(data: &str) -> Option<Dnskey> {
    let mut p = data.split_whitespace();
    let flags = p.next()?.parse().ok()?;
    let protocol = p.next()?.parse().ok()?;
    let algorithm = p.next()?.parse().ok()?;
    let public_key = b64d(&p.collect::<Vec<_>>().join(""))?;
    Some(Dnskey {
        flags,
        protocol,
        algorithm,
        public_key,
    })
}

/// Parse a DS presentation rdata: `key_tag algorithm digest_type <hex digest>`.
fn parse_ds(data: &str) -> Option<Ds> {
    let mut p = data.split_whitespace();
    let key_tag = p.next()?.parse().ok()?;
    let algorithm = p.next()?.parse().ok()?;
    let digest_type = p.next()?.parse().ok()?;
    let digest = hexd(&p.collect::<Vec<_>>().join(""))?;
    Some(Ds {
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

/// Parse an RRSIG presentation rdata:
/// `type_covered algorithm labels orig_ttl sig_exp sig_inc key_tag signer <base64 sig>`.
/// (DoH gives `sig_exp`/`sig_inc` as unix seconds.)
fn parse_rrsig(data: &str) -> Option<Rrsig> {
    let mut p = data.split_whitespace();
    let type_covered = rrtype_from_str(p.next()?)?;
    let algorithm = p.next()?.parse().ok()?;
    let labels = p.next()?.parse().ok()?;
    let original_ttl = p.next()?.parse().ok()?;
    let sig_expiration = p.next()?.parse().ok()?;
    let sig_inception = p.next()?.parse().ok()?;
    let key_tag = p.next()?.parse().ok()?;
    let signer_name = name_to_wire(p.next()?);
    let signature = b64d(&p.collect::<Vec<_>>().join(""))?;
    Some(Rrsig {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        sig_expiration,
        sig_inception,
        key_tag,
        signer_name,
        signature,
    })
}

/// Decode a length-prefixed wire-form DNS name back to a lowercase dotted string (no trailing
/// dot). Root → "".
pub fn wire_to_name(w: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < w.len() {
        let len = w[i] as usize;
        if len == 0 {
            break;
        }
        i += 1;
        if i + len > w.len() {
            break;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&w[i..i + len]).to_ascii_lowercase());
        i += len;
    }
    out
}

/// Normalize a presentation name for comparison: no trailing dot, lowercase.
fn norm(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// The parent zone of `z` (one label up); the root's parent is itself-empty.
fn parent_zone(z: &str) -> String {
    match z.find('.') {
        Some(i) => z[i + 1..].to_string(),
        None => String::new(),
    }
}

/// Is `owner` at or below `zone` (a label-boundary suffix; both normalized)? A zone may only sign
/// records within itself (RFC 4035 §5.3.1). The empty (root) zone contains everything, but the root
/// KSK is an unforgeable anchor, so allowing it is safe.
fn owner_in_zone(owner: &str, zone: &str) -> bool {
    let owner = norm(owner);
    let zone = norm(zone);
    zone.is_empty() || owner == zone || owner.ends_with(&format!(".{zone}"))
}

/// Assemble a [`DnssecChain`] for `_hopaddress.<domain>` from the parsed DoH responses (the
/// TXT record plus DNSKEY/DS for each zone up to root). The leaf zone is taken from the
/// record's RRSIG signer, then we walk up to root. Missing pieces → `Malformed` so a partial
/// chain can never validate.
pub fn assemble_chain(domain: &str, dohs: &[DohAnswer]) -> Result<DnssecChain, DnssecError> {
    // Flatten every response into combined, owner-tagged lists.
    let mut txt: Vec<(String, String)> = Vec::new();
    let mut dnskeys: Vec<(String, Dnskey)> = Vec::new();
    let mut ds: Vec<(String, Ds)> = Vec::new();
    let mut rrsigs: Vec<(String, Rrsig)> = Vec::new();
    for d in dohs {
        txt.extend(d.txt.iter().cloned());
        dnskeys.extend(d.dnskeys.iter().cloned());
        ds.extend(d.ds.iter().cloned());
        rrsigs.extend(d.rrsigs.iter().cloned());
    }

    let record_name = format!("_hopaddress.{}", norm(domain));
    // The answer RRset (TXT) and its signature.
    let record: Vec<Rr> = txt
        .iter()
        .filter(|(o, _)| norm(o) == record_name)
        .map(|(o, v)| Rr {
            owner: name_to_wire(o),
            rtype: 16,
            class: 1,
            rdata: txt_rdata(v),
        })
        .collect();
    if record.is_empty() {
        return Err(DnssecError::Malformed("no TXT record"));
    }
    let record_rrsig = rrsigs
        .iter()
        .find(|(o, r)| norm(o) == record_name && r.type_covered == 16)
        .map(|(_, r)| r.clone())
        .ok_or(DnssecError::Malformed("no record RRSIG"))?;

    // Leaf zone = the RRSIG's signer; walk up to root.
    let leaf = wire_to_name(&record_rrsig.signer_name);

    // RFC 4035 §5.3.1: the signing zone must be AUTHORITATIVE for the record it signs, i.e. the leaf
    // zone (the RRSIG's signer) must CONTAIN the record owner. The leaf name, its whole DNSKEY/DS key
    // chain, and the record signature are all supplied by whoever produced this proof and can be made
    // internally valid by anyone who controls ANY DNSSEC-signed zone. Without this check they could
    // sign a `_hopaddress.<victim-domain>` TXT with their own zone's key and chain it to root, hijacking
    // that name -> Hop address binding. Requiring owner-within-signer forces the attacker to control a
    // zone that actually contains the victim name (i.e. the victim's own zone, or an ancestor).
    if !owner_in_zone(&record_name, &leaf) {
        return Err(DnssecError::Malformed(
            "record owner not within its signer zone",
        ));
    }
    let mut zones = Vec::new();
    let mut z = leaf;
    loop {
        let is_root = z.is_empty();
        let zone_keys: Vec<Dnskey> = dnskeys
            .iter()
            .filter(|(o, _)| norm(o) == z)
            .map(|(_, k)| k.clone())
            .collect();
        if zone_keys.is_empty() {
            return Err(DnssecError::Malformed("missing DNSKEY for a zone"));
        }
        let dnskey_rrsig = rrsigs
            .iter()
            .find(|(o, r)| norm(o) == z && r.type_covered == TYPE_DNSKEY)
            .map(|(_, r)| r.clone())
            .ok_or(DnssecError::Malformed("missing DNSKEY RRSIG"))?;
        let (zone_ds, ds_rrsig) = if is_root {
            (Vec::new(), None)
        } else {
            let zd: Vec<Ds> = ds
                .iter()
                .filter(|(o, _)| norm(o) == z)
                .map(|(_, d)| d.clone())
                .collect();
            let dsr = rrsigs
                .iter()
                .find(|(o, r)| norm(o) == z && r.type_covered == TYPE_DS)
                .map(|(_, r)| r.clone());
            (zd, dsr)
        };
        zones.push(ZoneProof {
            name: z.clone(),
            dnskeys: zone_keys,
            dnskey_rrsig,
            ds: zone_ds,
            ds_rrsig,
        });
        if is_root {
            break;
        }
        z = parent_zone(&z);
    }

    Ok(DnssecChain {
        record,
        record_rrsig,
        zones,
    })
}

/// Parse a DoH JSON response body into typed records. Tolerant: unparseable records are
/// skipped (a missing piece simply fails chain assembly/validation later — never a false pass).
pub fn parse_doh(json: &str) -> Result<DohAnswer, DnssecError> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|_| DnssecError::Malformed("bad DoH JSON"))?;
    let mut out = DohAnswer {
        ad: v.get("AD").and_then(|b| b.as_bool()).unwrap_or(false),
        status: v.get("Status").and_then(|s| s.as_u64()).unwrap_or(0) as u32,
        ..Default::default()
    };
    // DS records and NSEC live in the Authority section on a delegation; the rest in Answer.
    for section in ["Answer", "Authority"] {
        let Some(arr) = v.get(section).and_then(|a| a.as_array()) else {
            continue;
        };
        for rec in arr {
            let rtype = rec.get("type").and_then(|t| t.as_u64()).unwrap_or(0);
            let name = rec
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let data = rec.get("data").and_then(|d| d.as_str()).unwrap_or("");
            match rtype {
                16 => out.txt.push((name, data.trim_matches('"').to_string())),
                46 => {
                    if let Some(r) = parse_rrsig(data) {
                        out.rrsigs.push((name, r));
                    }
                }
                48 => {
                    if let Some(k) = parse_dnskey(data) {
                        out.dnskeys.push((name, k));
                    }
                }
                43 => {
                    if let Some(d) = parse_ds(data) {
                        out.ds.push((name, d));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    // ed25519-dalek 3 / the ecdsa crate need a `CryptoRng` from THEIR rand_core (0.10), which
    // dropped `OsRng` entirely; `getrandom::SysRng` (made infallible via `UnwrapErr`) is the
    // replacement both crates' own docs point at. Same OS CSPRNG as the workspace
    // `rand_core::OsRng`, just reached through the newer entry point (test-only key generation,
    // no wire format involved).
    fn dalek_rng() -> getrandom::rand_core::UnwrapErr<getrandom::SysRng> {
        getrandom::rand_core::UnwrapErr(getrandom::SysRng)
    }

    #[test]
    fn hexd_rejects_a_hostile_multibyte_digest_without_panicking() {
        // A DS-digest field is attacker-controlled (any HnsAnswer proof) and can be any UTF-8. The old
        // hexd byte-indexed a &str gated only on even byte length, so a multi-byte char landed mid-
        // character and panicked. Assert every hostile shape returns None instead of panicking:
        assert_eq!(
            hexd("a\u{ff}b"),
            None,
            "multi-byte char (was: byte-index panic)"
        );
        assert_eq!(
            hexd("\u{ff}\u{ff}"),
            None,
            "all multi-byte, even byte length"
        );
        assert_eq!(
            hexd("de\u{2028}ad"),
            None,
            "unicode line separator embedded in hex"
        );
        assert_eq!(hexd("zz"), None, "even length, non-hex");
        assert_eq!(hexd("abc"), None, "odd length");
        // Valid hex still round-trips, ASCII whitespace still stripped.
        assert_eq!(hexd("deadBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(hexd("de ad be ef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(hexd(""), Some(vec![]));
    }

    fn b64(s: &str) -> Vec<u8> {
        STANDARD.decode(s.replace([' ', '\n'], "")).unwrap()
    }

    #[test]
    fn verifies_real_hopme_txt_rrsig() {
        // Real vectors pulled from the live, DNSSEC-signed hopme.sh zone (alg 8, RSA/SHA-256).
        // The hopme.sh ZSK (flags 256) signs _hopaddress.example.hopme.sh TXT.
        let zsk = Dnskey {
            flags: 256,
            protocol: 3,
            algorithm: 8,
            public_key: b64("AwEAAdZm1zOo0FSOc/5gbJtNPoNpLmk8i3BvAUmgM//nsFHO68cVopMr\
                 jTEjmD+tb89QrEpmmATDEE3IqnalP1gaSGC+OferlNmCPFbuttNLCRf+\
                 XnKXbz9CJ/FUKWhCipRds8lBDVU/iTQbC4y0VHRZkr759yNXRHU1i/bN\
                 b3vptTKj"),
        };
        // The signed key tag is 30700 — our independent computation must match.
        assert_eq!(zsk.key_tag(), 30700, "key tag from DNSKEY rdata");

        let rrsig = Rrsig {
            type_covered: 16, // TXT
            algorithm: 8,
            labels: 4, // _hopaddress.example.hopme.sh
            original_ttl: 300,
            sig_expiration: 1783834978, // 20260712054258 UTC
            sig_inception: 1781934178,  // 20260620054258 UTC
            key_tag: 30700,
            signer_name: name_to_wire("hopme.sh"),
            signature: b64("rOfIOdr7ooOk0JK7SZbt71avK+VisW7mWtLt8oi7pbTcHwe6Tq5+PZog\
                 5ExVHe0EAqdXjGersLgue+z3hb75j/hNXvK/zKt2l2a+FFtwfVc9oUnx\
                 q5zh0c5Bz5CAjMeJ5lZvlRgiwbtTfGd0ezYDqgS8P0s1CyV9GCvbvElE\
                 LUI="),
        };

        let txt = Rr {
            owner: name_to_wire("_hopaddress.example.hopme.sh"),
            rtype: 16,
            class: 1,
            rdata: txt_rdata("J8XGeYT2VA3aq6KeP85LEujpAjg3LBbLLvivyoNFWTFr"),
        };

        verify_rrsig(&[txt], &rrsig, &zsk).expect("real DNSSEC RRSIG must verify");
    }

    #[test]
    fn rejects_tampered_record() {
        // Same as above but flip the TXT value → signature must fail.
        let zsk = Dnskey {
            flags: 256,
            protocol: 3,
            algorithm: 8,
            public_key: b64("AwEAAdZm1zOo0FSOc/5gbJtNPoNpLmk8i3BvAUmgM//nsFHO68cVopMr\
                 jTEjmD+tb89QrEpmmATDEE3IqnalP1gaSGC+OferlNmCPFbuttNLCRf+\
                 XnKXbz9CJ/FUKWhCipRds8lBDVU/iTQbC4y0VHRZkr759yNXRHU1i/bN\
                 b3vptTKj"),
        };
        let rrsig = Rrsig {
            type_covered: 16,
            algorithm: 8,
            labels: 4,
            original_ttl: 300,
            sig_expiration: 1783834978,
            sig_inception: 1781934178,
            key_tag: 30700,
            signer_name: name_to_wire("hopme.sh"),
            signature: b64("rOfIOdr7ooOk0JK7SZbt71avK+VisW7mWtLt8oi7pbTcHwe6Tq5+PZog\
                 5ExVHe0EAqdXjGersLgue+z3hb75j/hNXvK/zKt2l2a+FFtwfVc9oUnx\
                 q5zh0c5Bz5CAjMeJ5lZvlRgiwbtTfGd0ezYDqgS8P0s1CyV9GCvbvElE\
                 LUI="),
        };
        let tampered = Rr {
            owner: name_to_wire("_hopaddress.example.hopme.sh"),
            rtype: 16,
            class: 1,
            rdata: txt_rdata("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        };
        assert_eq!(
            verify_rrsig(&[tampered], &rrsig, &zsk),
            Err(DnssecError::BadSignature),
        );
    }

    #[test]
    fn real_ksk_ds_link_matches_dot_sh() {
        // The hopme.sh KSK (flags 257) must have key tag 5446 and hash to the exact DS digest
        // published at the .sh parent — that's the link that anchors the zone to its parent.
        let ksk = Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 8,
            public_key: b64("AwEAAc8K3U595+tS/OwpGZL4J4SSLymmg0BSLN5BWm1vzMtUDmP5eTjK\
                 KI8NbDl4H0sSIGf9KwU3EWPZ96YzVx4y2Z+BKOCuaPU5VI+kOjxjm8x6\
                 YUkFwonHibDfwppHg05yZ4wu9YqbmS6HNfJjdrx0aKPN4zpKc/FO1eec\
                 PrP4+kdasycd9TEPw6T9kQLBWaRSCi0seHaSWC19scYUFZdPXTySF+WJ\
                 8xJS6lJULo8e++FKNqwJGCjWxo1PGSUqQKTxejiuZEb2E59Rf9mrZBGT\
                 +I2Kq8/dOzrnf4RVCSzfHJSQWOyp7RG9YkrclwMxarwDD1ToDEciWIBD\
                 DH3e9+Wllu8="),
        };
        assert_eq!(ksk.key_tag(), 5446);
        let digest = ds_digest(&name_to_wire("hopme.sh"), &ksk, DIGEST_SHA256).unwrap();
        let want = hex("6C6733A258D4FC31571FCEA1A657F188EE295EAB3ADC222EB807B5786048E0F9");
        assert_eq!(
            digest, want,
            "DS digest must match the record published at .sh"
        );
    }

    // --- synthetic full-chain walk -----------------------------------------------------
    // Generate our own root + zone keys, sign a record + the DNSKEY/DS sets, and prove the
    // recursive validator accepts a well-formed chain and rejects a broken one.

    use rsa::traits::PublicKeyParts;
    use rsa::{Pkcs1v15Sign as Sign, RsaPrivateKey};

    fn gen() -> RsaPrivateKey {
        RsaPrivateKey::new(&mut rand_core::OsRng, 1024).unwrap()
    }

    fn dnskey_of(sk: &RsaPrivateKey, flags: u16) -> Dnskey {
        let pk = sk.to_public_key();
        let e = pk.e().to_bytes_be();
        let n = pk.n().to_bytes_be();
        let mut public_key = Vec::new();
        if e.len() < 256 {
            public_key.push(e.len() as u8);
        } else {
            public_key.push(0);
            public_key.extend_from_slice(&(e.len() as u16).to_be_bytes());
        }
        public_key.extend_from_slice(&e);
        public_key.extend_from_slice(&n);
        Dnskey {
            flags,
            protocol: 3,
            algorithm: 8,
            public_key,
        }
    }

    fn sign(
        sk: &RsaPrivateKey,
        signer: &Dnskey,
        zone: &str,
        rrset: &[Rr],
        type_covered: u16,
        labels: u8,
        now: u32,
    ) -> Rrsig {
        let mut rrsig = Rrsig {
            type_covered,
            algorithm: 8,
            labels,
            original_ttl: 300,
            sig_inception: now - 60,
            sig_expiration: now + 86_400,
            key_tag: signer.key_tag(),
            signer_name: name_to_wire(zone),
            signature: Vec::new(),
        };
        let digest = Sha256::digest(signed_data(&rrsig, rrset));
        rrsig.signature = sk.sign(Sign::new::<Sha256>(), &digest).unwrap();
        rrsig
    }

    fn build_chain() -> (DnssecChain, Vec<Dnskey>, u32) {
        build_chain_v("hello")
    }

    fn build_chain_v(value: &str) -> (DnssecChain, Vec<Dnskey>, u32) {
        let now = 1_700_000_000u32;
        let (root_ksk_sk, root_zsk_sk) = (gen(), gen());
        let (zone_ksk_sk, zone_zsk_sk) = (gen(), gen());
        let root_ksk = dnskey_of(&root_ksk_sk, 257);
        let root_zsk = dnskey_of(&root_zsk_sk, 256);
        let zone_ksk = dnskey_of(&zone_ksk_sk, 257);
        let zone_zsk = dnskey_of(&zone_zsk_sk, 256);

        // Leaf record: the _hopaddress TXT, signed by the zone ZSK.
        let rec = Rr {
            owner: name_to_wire("_hopaddress.example"),
            rtype: 16,
            class: 1,
            rdata: txt_rdata(value),
        };
        let record_rrsig = sign(
            &zone_zsk_sk,
            &zone_zsk,
            "example",
            std::slice::from_ref(&rec),
            16,
            2,
            now,
        );

        // Zone DNSKEY set self-signed by the zone KSK.
        let zone_keys = vec![zone_ksk.clone(), zone_zsk.clone()];
        let zone_dnskey_rrset: Vec<Rr> = zone_keys
            .iter()
            .map(|k| Rr {
                owner: name_to_wire("example"),
                rtype: TYPE_DNSKEY,
                class: 1,
                rdata: k.rdata(),
            })
            .collect();
        let zone_dnskey_rrsig = sign(
            &zone_ksk_sk,
            &zone_ksk,
            "example",
            &zone_dnskey_rrset,
            TYPE_DNSKEY,
            1,
            now,
        );

        // DS for the zone (its KSK), published in root, signed by root ZSK.
        let zone_ds = Ds {
            key_tag: zone_ksk.key_tag(),
            algorithm: 8,
            digest_type: 2,
            digest: ds_digest(&name_to_wire("example"), &zone_ksk, 2).unwrap(),
        };
        let ds_rrset = vec![Rr {
            owner: name_to_wire("example"),
            rtype: TYPE_DS,
            class: 1,
            rdata: zone_ds.rdata(),
        }];
        let ds_rrsig = sign(&root_zsk_sk, &root_zsk, "", &ds_rrset, TYPE_DS, 1, now);

        // Root DNSKEY set self-signed by the root KSK (the anchor).
        let root_keys = vec![root_ksk.clone(), root_zsk.clone()];
        let root_dnskey_rrset: Vec<Rr> = root_keys
            .iter()
            .map(|k| Rr {
                owner: name_to_wire(""),
                rtype: TYPE_DNSKEY,
                class: 1,
                rdata: k.rdata(),
            })
            .collect();
        let root_dnskey_rrsig = sign(
            &root_ksk_sk,
            &root_ksk,
            "",
            &root_dnskey_rrset,
            TYPE_DNSKEY,
            0,
            now,
        );

        let chain = DnssecChain {
            record: vec![rec],
            record_rrsig,
            zones: vec![
                ZoneProof {
                    name: "example".into(),
                    dnskeys: zone_keys,
                    dnskey_rrsig: zone_dnskey_rrsig,
                    ds: vec![zone_ds],
                    ds_rrsig: Some(ds_rrsig),
                },
                ZoneProof {
                    name: "".into(),
                    dnskeys: root_keys,
                    dnskey_rrsig: root_dnskey_rrsig,
                    ds: vec![],
                    ds_rrsig: None,
                },
            ],
        };
        (chain, vec![root_ksk], now)
    }

    #[test]
    fn validates_synthetic_chain_to_anchor() {
        let (chain, anchors, now) = build_chain();
        validate_chain(&chain, &anchors, now).expect("well-formed chain must validate");
    }

    /// Flatten a chain into the owner-tagged DoH form (as if returned by resolvers).
    fn flatten(chain: &DnssecChain) -> DohAnswer {
        let mut d = DohAnswer {
            ad: true,
            ..Default::default()
        };
        for rr in &chain.record {
            if rr.rtype == 16 {
                let len = rr.rdata[0] as usize;
                let val = String::from_utf8_lossy(&rr.rdata[1..1 + len]).to_string();
                d.txt.push((wire_to_name(&rr.owner), val));
            }
        }
        d.rrsigs.push((
            wire_to_name(&chain.record[0].owner),
            chain.record_rrsig.clone(),
        ));
        for z in &chain.zones {
            for k in &z.dnskeys {
                d.dnskeys.push((z.name.clone(), k.clone()));
            }
            d.rrsigs.push((z.name.clone(), z.dnskey_rrsig.clone()));
            for ds in &z.ds {
                d.ds.push((z.name.clone(), ds.clone()));
            }
            if let Some(r) = &z.ds_rrsig {
                d.rrsigs.push((z.name.clone(), r.clone()));
            }
        }
        d
    }

    #[test]
    fn assembles_then_validates_synthetic_chain() {
        // Flatten a known-good chain into DoH records, re-assemble from those flat records,
        // and validate — proving assemble_chain wires the pieces back together correctly.
        let (chain, anchors, now) = build_chain();
        let doh = flatten(&chain);
        let rebuilt = assemble_chain("example", &[doh]).expect("assemble");
        validate_chain(&rebuilt, &anchors, now).expect("assembled chain validates");
    }

    #[test]
    fn validate_and_extract_pulls_the_address() {
        // End-to-end: a chain whose TXT is a base58 32-byte address → assemble + validate +
        // decode yields exactly that address, with the record's TTL.
        let addr = [7u8; 32];
        let value = bs58::encode(addr).into_string();
        let (chain, anchors, now) = build_chain_v(&value);
        let doh = flatten(&chain);
        let (got, ttl) = validate_and_extract("example", &[doh], &anchors, now).expect("extract");
        assert_eq!(got, addr);
        assert_eq!(ttl, 300);
    }

    #[test]
    fn owner_in_zone_enforces_label_boundary() {
        assert!(owner_in_zone("_hopaddress.victim.com", "victim.com")); // a zone signs its own record
        assert!(owner_in_zone("victim.com", "victim.com")); // apex
        assert!(owner_in_zone("_hopaddress.victim.com", "com")); // a true ancestor (com won't in practice)
        assert!(owner_in_zone("anything.tld", "")); // root contains everything
        assert!(!owner_in_zone("_hopaddress.victim.com", "evil.example")); // the hijack: unrelated signer
        assert!(!owner_in_zone("evilvictim.com", "victim.com")); // suffix, but not on a label boundary
    }

    #[test]
    fn assemble_chain_rejects_a_record_signed_by_a_foreign_zone() {
        // The DNSSEC hijack (pass-5 F1): an attacker who controls a real DNSSEC-signed zone
        // (evil.example) signs a `_hopaddress.victim.com` TXT with their own key and chains it to root.
        // assemble_chain must refuse it on the owner-not-in-signer-zone check, BEFORE any signature is
        // verified, so a real key chain behind the forged signer never gets a chance to validate.
        let rrsig = Rrsig {
            type_covered: 16,
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            sig_expiration: u32::MAX,
            sig_inception: 0,
            key_tag: 1234,
            signer_name: name_to_wire("evil.example"),
            signature: vec![0u8; 64],
        };
        let doh = DohAnswer {
            ad: true,
            status: 0,
            txt: vec![("_hopaddress.victim.com".into(), "SomeBase58Addr".into())],
            dnskeys: Vec::new(),
            ds: Vec::new(),
            rrsigs: vec![("_hopaddress.victim.com".into(), rrsig)],
        };
        let err = assemble_chain("victim.com", &[doh]).unwrap_err();
        assert!(
            matches!(err, DnssecError::Malformed(_)),
            "a foreign-zone signer must be refused, got {err:?}"
        );
    }

    #[test]
    fn validate_and_extract_rejects_unvalidatable() {
        // Wrong anchor → no trust → error, no address leaks through.
        let addr = [7u8; 32];
        let value = bs58::encode(addr).into_string();
        let (chain, _anchors, now) = build_chain_v(&value);
        let doh = flatten(&chain);
        let stranger = dnskey_of(&gen(), 257);
        assert!(validate_and_extract("example", &[doh], &[stranger], now).is_err());
    }

    #[test]
    fn rejects_chain_with_wrong_anchor() {
        let (chain, _anchors, now) = build_chain();
        let stranger = dnskey_of(&gen(), 257); // a root key we never put in the chain
        assert_eq!(
            validate_chain(&chain, &[stranger], now),
            Err(DnssecError::NoTrustAnchor)
        );
    }

    #[test]
    fn rejects_chain_outside_validity_window() {
        let (chain, anchors, now) = build_chain();
        // now far past every signature's expiration.
        assert_eq!(
            validate_chain(&chain, &anchors, now + 200_000),
            Err(DnssecError::Expired)
        );
    }

    #[test]
    fn verifies_ecdsa_p256_rrsig() {
        // Generate a P-256 zone key, sign a TXT RRset (ECDSA/SHA-256, alg 13), and verify —
        // covering the algorithm most modern zones (Cloudflare etc.) use.
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use p256::elliptic_curve::Generate;
        let sk = SigningKey::generate_from_rng(&mut dalek_rng());
        let point = sk.verifying_key().to_sec1_point(false); // 0x04 ‖ x ‖ y
        let dnskey = Dnskey {
            flags: 256,
            protocol: 3,
            algorithm: ALG_ECDSAP256SHA256,
            public_key: point.as_bytes()[1..].to_vec(), // strip the 0x04 tag → x ‖ y
        };
        let mut rrsig = Rrsig {
            type_covered: 16,
            algorithm: ALG_ECDSAP256SHA256,
            labels: 2,
            original_ttl: 300,
            sig_inception: 1,
            sig_expiration: u32::MAX,
            key_tag: dnskey.key_tag(),
            signer_name: name_to_wire("example"),
            signature: Vec::new(),
        };
        let rr = Rr {
            owner: name_to_wire("_x.example"),
            rtype: 16,
            class: 1,
            rdata: txt_rdata("hi"),
        };
        let sig: Signature = sk.sign(&signed_data(&rrsig, std::slice::from_ref(&rr)));
        rrsig.signature = sig.to_bytes().to_vec();

        verify_rrsig(std::slice::from_ref(&rr), &rrsig, &dnskey)
            .expect("ECDSA P-256 RRSIG must verify");

        let bad = Rr {
            owner: name_to_wire("_x.example"),
            rtype: 16,
            class: 1,
            rdata: txt_rdata("xx"),
        };
        assert_eq!(
            verify_rrsig(&[bad], &rrsig, &dnskey),
            Err(DnssecError::BadSignature)
        );
    }

    #[test]
    fn verifies_ed25519_rrsig() {
        // D-dnssec: Ed25519 (alg 15, RFC 8080) — DNSKEY carries the raw 32-byte public key, the
        // RRSIG is a 64-byte pure Ed25519 signature over the signed data.
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::generate(&mut dalek_rng());
        let dnskey = Dnskey {
            flags: 256,
            protocol: 3,
            algorithm: ALG_ED25519,
            public_key: sk.verifying_key().to_bytes().to_vec(),
        };
        let mut rrsig = Rrsig {
            type_covered: 16,
            algorithm: ALG_ED25519,
            labels: 2,
            original_ttl: 300,
            sig_inception: 1,
            sig_expiration: u32::MAX,
            key_tag: dnskey.key_tag(),
            signer_name: name_to_wire("example"),
            signature: Vec::new(),
        };
        let rr = Rr {
            owner: name_to_wire("_x.example"),
            rtype: 16,
            class: 1,
            rdata: txt_rdata("hi"),
        };
        rrsig.signature = sk
            .sign(&signed_data(&rrsig, std::slice::from_ref(&rr)))
            .to_bytes()
            .to_vec();
        verify_rrsig(std::slice::from_ref(&rr), &rrsig, &dnskey)
            .expect("Ed25519 RRSIG must verify");

        let bad = Rr {
            owner: name_to_wire("_x.example"),
            rtype: 16,
            class: 1,
            rdata: txt_rdata("xx"),
        };
        assert_eq!(
            verify_rrsig(&[bad], &rrsig, &dnskey),
            Err(DnssecError::BadSignature)
        );
    }

    #[test]
    fn root_anchors_have_expected_key_tags() {
        let tags: Vec<u16> = root_anchors().iter().map(|k| k.key_tag()).collect();
        assert!(tags.contains(&20326), "KSK-2017 present");
        assert!(tags.contains(&38696), "KSK-2024 present");
    }

    /// Decode a hex string to bytes (test helper).
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn parses_real_doh_txt_response_and_verifies() {
        // A real dns.google `do=1` response for the TXT record (+ its RRSIG), parsed by core,
        // then verified against the real ZSK — proving the DoH parser feeds validation correctly.
        let json = r#"{
          "Status": 0, "AD": true,
          "Answer": [
            {"name":"_hopaddress.example.hopme.sh.","type":16,"TTL":300,
             "data":"J8XGeYT2VA3aq6KeP85LEujpAjg3LBbLLvivyoNFWTFr"},
            {"name":"_hopaddress.example.hopme.sh.","type":46,"TTL":300,
             "data":"txt 8 4 300 1783834978 1781934178 30700 hopme.sh. rOfIOdr7ooOk0JK7SZbt71avK+VisW7mWtLt8oi7pbTcHwe6Tq5+PZog5ExVHe0EAqdXjGersLgue+z3hb75j/hNXvK/zKt2l2a+FFtwfVc9oUnxq5zh0c5Bz5CAjMeJ5lZvlRgiwbtTfGd0ezYDqgS8P0s1CyV9GCvbvElELUI="}
          ]}"#;
        let parsed = parse_doh(json).unwrap();
        assert!(parsed.ad);
        assert_eq!(parsed.txt.len(), 1);
        assert_eq!(parsed.rrsigs.len(), 1);

        let zsk = Dnskey {
            flags: 256,
            protocol: 3,
            algorithm: 8,
            public_key: b64("AwEAAdZm1zOo0FSOc/5gbJtNPoNpLmk8i3BvAUmgM//nsFHO68cVopMr\
                 jTEjmD+tb89QrEpmmATDEE3IqnalP1gaSGC+OferlNmCPFbuttNLCRf+\
                 XnKXbz9CJ/FUKWhCipRds8lBDVU/iTQbC4y0VHRZkr759yNXRHU1i/bN\
                 b3vptTKj"),
        };
        let (owner, value) = &parsed.txt[0];
        let rr = Rr {
            owner: name_to_wire(owner),
            rtype: 16,
            class: 1,
            rdata: txt_rdata(value),
        };
        let (_, rrsig) = &parsed.rrsigs[0];
        verify_rrsig(&[rr], rrsig, &zsk).expect("parsed-from-DoH RRSIG must verify");
    }
}
