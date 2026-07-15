<p align="center">
  <img alt="Hop" src="https://hopme.sh/hop-mark.svg" width="200">
</p>

<h1 align="center">hop-core</h1>

<p align="center">
  <b>The Hop protocol, in pure Rust.</b><br>
  Bundles, crypto, store-and-forward, and routing for the <a href="https://hopme.sh">Hop</a> mesh, with no platform in it.
</p>

<p align="center">
  <a href="https://crates.io/crates/hop-core"><img src="https://img.shields.io/crates/v/hop-core?color=dea584&label=crates.io" alt="crates.io"></a>
  <img src="https://img.shields.io/badge/license-FSL--1.1--ALv2-3ddc84" alt="license">
  <img src="https://img.shields.io/badge/rust-2021-dea584" alt="rust 2021">
</p>

---

Hop is a **delay-tolerant mesh**: end-to-end encrypted datagrams that hop device to device, over BLE,
Wi-Fi, and the internet, until they reach the person you meant. Held, never dropped.

`hop-core` is the whole protocol as one deterministic, `no-radio` Rust crate: the bundle codec and wire
format, the Noise link handshake, spray-and-wait routing, the untraceable-by-default metadata path, the
Double Ratchet, and the `Store` seam. Everything else binds through here. It runs identically in unit
tests, in the browser via WebAssembly, and on-device through the C ABI, because the only thing it doesn't
contain is the radio: a bearer hands it opaque bytes, and it does the rest.

## Install

```toml
[dependencies]
hop-core = "0.0"
```

## Two nodes, one link

The core is a state machine you pump. A **bearer** feeds it bytes (`BearerEvent`) and drains what it
wants to send (`drain_outgoing`); the core owns all crypto and routing. Here two nodes are wired by a
plain in-memory loopback, and A sends B an untraceable message:

```rust
use hop_core::prelude::*;

let mut a = Node::new(Identity::generate());
let mut b = Node::new(Identity::generate());
let mut now = 1_700_000_000_000; // a real epoch-ms clock so prekey adverts aren't judged expired

for n in [&mut a, &mut b] {
    n.set_time(now);
    n.publish_prekey().unwrap();       // so a peer can open a forward-secret session with us
}

// One bearer link, same id each side. A dialed, B accepted.
a.handle(BearerEvent::Connected(1, Role::Initiator));
b.handle(BearerEvent::Connected(1, Role::Responder));

// Send the untraceable (§39) datagram: B's address is sealed, never on the wire.
let dst = b.address();
a.send_message(dst, "text/plain".into(), b"meet at the ridge".to_vec(), true).unwrap();

// Pump the loopback + clock until B's inbox has it.
for _ in 0..400 {
    for (link, bytes) in a.drain_outgoing() { b.handle(BearerEvent::Data(link, bytes)); }
    for (link, bytes) in b.drain_outgoing() { a.handle(BearerEvent::Data(link, bytes)); }
    for bundle in b.take_inbox() {
        if let Ok(Some(msg)) = b.read_message(&bundle) {
            println!("{}", String::from_utf8_lossy(&msg.body));
        }
    }
    now += 100;
    a.set_time(now);
    b.set_time(now);
}
```

`send_message` is the default, untraceable path; `send_message_traced` is the opt-in directed path with
cleartext src/dst provenance. `send_hops_request` / `register_service` carry the `hops://`
request/response surface, and `hps_*` carry group channels.

## What's inside

- **`bundle`** the wire format. `BUNDLE_VERSION` is the contract: any layout change bumps it, and a
  bundle's id *is* its integrity check (§39 bundles are unsigned and self-verifying).
- **`crypto`** Ed25519 identity, X25519 sealing, ChaCha20-Poly1305, and the Double Ratchet, over a real
  OS CSPRNG.
- **`link`** the Noise-framed bearer contract: opaque bytes in, opaque bytes out, no protocol logic in
  the radio.
- **`routing` / `route` / `relay`** spray-and-wait and the route-toward gradient that makes the
  untraceable path directed rather than a blind flood.
- **`store`** the `Store` trait: put/get/dedup and the spray-and-wait copy budget. Pick a backend
  (SQLite, Firestore) or bring your own; an in-memory one ships in-crate.
- **`app` / `hps` / `reach`** app-fabric keys, `hps://` pub/sub channels, and self-certifying reach
  records.

## Verify

```sh
cargo test -p hop-core        # the §39 + wire round-trip tests are the crown jewels
cargo clippy -p hop-core --all-targets -- -D warnings
```

A dependency bump must produce byte-identical wire output; the round-trip tests prove it before merge.

## Status

Prototype, iterating in the open. Breaking wire changes are fine for now and are gated behind
`BUNDLE_VERSION`, so a peer on an older wire fails cleanly rather than silently misreading. The crypto
and routing are exercised hard by the core suite and the WebAssembly swarm simulator.

## The Hop family

`hop-core` is the protocol everything binds. The C ABI over it is
[libhop](https://github.com/hopmesh/libhop); the browser build is
[hop-wasm](https://github.com/hopmesh/hop-wasm). The language SDKs:
[node](https://github.com/hopmesh/hop-sdk-node) ·
[python](https://github.com/hopmesh/hop-sdk-python) ·
[go](https://github.com/hopmesh/hop-sdk-go) ·
[ruby](https://github.com/hopmesh/hop-sdk-ruby) ·
[crystal](https://github.com/hopmesh/hop-sdk-crystal) ·
[elixir](https://github.com/hopmesh/hop-sdk-elixir) ·
[apple](https://github.com/hopmesh/hop-sdk-apple) ·
[android](https://github.com/hopmesh/hop-sdk-android).

## License

[FSL-1.1-ALv2](./LICENSE.md): source-available, and converts to Apache-2.0 after two years. The SDKs
that bind this are Apache-2.0.
