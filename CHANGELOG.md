# Changelog

Notable changes, generated from [conventional commits](https://www.conventionalcommits.org) by
git-cliff. Do not edit by hand.
## Unreleased

### Bug Fixes
- bump corpus + all wire-version consumers to v10 (e68d804)
- coarsen private created_at to defeat a sender timing fingerprint (ADV18-08) (c80f342)
- bind a response to the endpoint we asked, not just the id (ADV18-07) (ea39ccd)
- forged SessionInit cannot destroy an established ratchet (ADV18-01) (45bc983)
- stamp before fragmentation so streamed bundles stay attributable (b277676)
- close adversarial protocol gaps (cad3deb)
- re-ingest mailbox pulls via LOCAL_LINK so a >cap backlog isn't dropped-after-delete (#143) (ea4c235)
- pass-5 audit remediation - DNSSEC name-hijack (CRITICAL) + Node reply UAF (HIGH) (#138) (d207acc)
- close F-18d, HpsRekey fails safe under a mid-arm panic (#104) (879019b)
- make hexd byte-safe so a hostile DS-digest can't panic the resolver (2nd-pass audit finding) (#78) (b75aef7)
- cover Destination::Vaccine in every workspace crate (relay/relayd/hop-sim) + workspace fmt/clippy (e611c4d)
- dense contact chains everywhere, honest congestion, per-device bubble truth, real-street clockin (19b3580)
- per-device delivery truth — sender learns delivery only via ACK (5868328)
- prune old bundles (real OOM fix) + conversation view + compose close (e2f0592)

### CI
- bump create-github-app-token to v3.2.0 across all mirrored components (efc9f6c)

### Chore
- gate ssrf ip filter behind reqwest feature; fmt (a6f4665)
- drop the root license, license per-component (FSL-1.1-ALv2) (#146) (be2a5a7)

### Dependencies
- land the grouped rust-dependencies bump (sha2, ed25519/x25519-dalek, chacha20poly1305, snow, rusqlite, p256, uniffi, tungstenite) (#89) (2038ce9)

### Documentation
- branded, marketable READMEs for every sub-repo (9c2a477)
- stop mentioning DNSSEC (no longer part of the design) (179a278)
- decouple hop-core's vocabulary from the sim (comments only) (#119) (d153989)

### Features
- telemetry metering, tenant-attributed observability (§40 -> §37) (b823dcc)
- OTel-over-Hop telemetry transport (DESIGN.md §40) (8da170c)
- custody beacon (mode-1 HaveSet exchange) to cut duplicate-ingress COGS (708b565)
- bill the offline/spooled delivery path (attribute at durable re-ingest) (9558240)
- delivery/pull-justified metering + vaccine exemption (d35cc61)
- rotating key-hint carriage stamps (no tenant id on the wire) (a5e592d)
- §35 carriage stamps - keyed relays, per-bundle metering (wire v8) (4aae50f)
- self-clustering endpoints (phase 1 dedup) as a hop-endpoint-core layer over the mesh (#153) (487e4d2)
- self-certifying reachability records (core + ABI) for DNS-free endpoint discovery (#126) (7c31123)
- channels + mine scenario + curated homepage; fix two real protocol bugs the honest harness exposed (dc20947)
- real hop counts + LoRa net modeled + clockin & multi-hop everywhere + bubble timers (48b8e98)
- beacon ripple viz + average delivery/ack cards (5599e1b)
- visualize the §39 gradient routing tree + fix store indicator (692ccca)
- §39 delivery vaccine — relays purge on ack, bundle-id only, no src/dst (16995ef)
- real hop-debug send status (Sent·N peers) + TTL cleanup + fix convo focus (42c5481)
- back each node with a real host Store (SQLite/OPFS) instead of wasm memory (9504585)
- flood driven by REAL held-copy state (not a timer) (13070a2)
- observe bundle-per-link transfers for the swarm viz (325a0ae)

### Other
- box the envelope stamp (clippy large-variant), fmt, §35 addendum (6b601b6)
- publish the Rust crates under the hop-mesh-* namespace (3bb9d0c)
- CLA gate on contributions (preserve commercial relicensing of core) (5a9aa7d)
- SECURITY.md per component + enable-security in the bootstrap script (a1492e9)
- copyright holder is Hop Mesh, LLC (7d8c514)
- CHANGE_REQUEST sync-back + document merge/conversation + confidentiality (9e1dec2)
- make the TLS-served reach record the only name path (drop DNSSEC-over-DoH) (#139) (8998288)
- verify_publish uses verify_strict, matching the crate-wide ed25519 convention (#95) (9f40004)
- canonicalize the delivery-vaccine shape at verify (r15-01) — close the is_ack twin on the vaccine id (#56) (3a1c666)
- bind the entire private inner into the wire id (r14-01) — close the flags.request_ack twin residual (#55) (23228cf)
- bind the §39 recognition header into the private wire id (r13-01) — close the 7th chimera vector at its root (#52) (0b6e366)
- cargo fmt the r12 chimera test (rustfmt line-wrap) (#51) (6c7fb6d)
- close the §39 recognition-header chimera (r12-01) — the 6th vector (#50) (e97faed)
- authorize the response-cleanup purges (r11-01) - close the last purge vector (#47) (69cdbed)
- enforce the §39 private-bundle invariant at the gate (r10-01 root fix) (#46) (9450375)
- close the traced-ACK forgery on the DEFAULT private send path (r9-01) (#45) (cc16340)
- close the private-chimera bypass of the traced-ACK authorization (r8-01) (#44) (bf3168b)
- cargo fmt + clippy across the touched crates (c6216a1)
- DNSSEC Ed25519 + RSA modulus floor; document the 429 ceiling (e210ba7)
- session GC, sqlite schema guard, remove dead k-bit fields (103084e)
- remove Destination::InternetEgress (mesh-visible internet-bound leak) (5dd64d3)

### Testing
- close store.rs and hps.rs coverage gaps to 100 percent (#81) (0f9ad2d)

