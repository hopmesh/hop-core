//! OTel-over-Hop: an OpenTelemetry-shaped telemetry batch carried as an addressed, statically
//! sealed Hop bundle to a collector, instead of OTLP-over-HTTP/gRPC (DESIGN.md §40).
//!
//! The transport is a Hop bundle, so telemetry from a device with no internet still reaches a
//! collector: the batch spools and delivers over the mesh when a path opens (delay-tolerant by
//! construction). This is exactly the P2P observability the platform sells, because pure-P2P
//! traffic never touches a server, the only telemetry a collector can see is what a device chooses
//! to self-report over this path.
//!
//! Privacy: a batch rides the `hop.telemetry` service, which is statically sealed to the
//! collector's key (§29), not a ratcheted `PeerMessage`. It is data *about* the app, not user
//! content, so a static seal is the right class. A device is expected to keep it low-cardinality
//! and free of user identifiers; resource labels like `platform` / `region` are opt-in and coarse.
//!
//! The model maps 1:1 onto OTLP on the collector side: [`TelemetryBatch::resource`] is an OTLP
//! Resource, and each [`Record`] is a metric point ([`Signal::Counter`] -> Sum, [`Signal::Gauge`]
//! -> Gauge) or a log record ([`Signal::Event`]). Values are fixed-point integers so the wire stays
//! byte-stable and language-neutral across every SDK (no float wobble); the collector scales by
//! `unit`.

use serde::{Deserialize, Serialize};

/// Max records in one batch (a DoS bound applied on decode). A device batches then flushes; higher
/// volumes span multiple batches.
pub const MAX_RECORDS: usize = 512;
/// Max attributes on the resource, or on any one record.
pub const MAX_ATTRS: usize = 32;
/// Max length in bytes of any attribute key/value, metric name, or unit.
pub const MAX_STR: usize = 128;

/// The kind of a telemetry point, mapped onto an OTLP signal on the collector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signal {
    /// A monotonic counter delta (OTLP Sum, monotonic).
    Counter,
    /// A point-in-time measurement (OTLP Gauge).
    Gauge,
    /// A discrete event or log record (OTLP LogRecord).
    Event,
}

/// One telemetry point. `value` is a fixed-point integer (a count for `Counter`/`Event`, or a
/// unit-scaled measure for `Gauge`, e.g. milliseconds), so the wire is identical across languages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub signal: Signal,
    /// Dotted name, e.g. `hop.bundle.delivered` or `hop.delivery.latency_ms`.
    pub name: String,
    /// Fixed-point value. Count for `Counter`/`Event`; unit-scaled measure for `Gauge`.
    pub value: i64,
    /// Optional unit hint for the collector (`ms`, `by`, `1`, ...). Empty = dimensionless.
    pub unit: String,
    /// Low-cardinality labels (`bearer=ble`, `result=delivered`, ...). Keep tiny and anonymous.
    pub attrs: Vec<(String, String)>,
    /// Event time, unix millis on the device clock (the collector may correct against receipt).
    pub time_ms: u64,
}

impl Record {
    pub fn counter(name: &str, value: i64, time_ms: u64) -> Record {
        Record {
            signal: Signal::Counter,
            name: name.into(),
            value,
            unit: String::new(),
            attrs: Vec::new(),
            time_ms,
        }
    }

    pub fn gauge(name: &str, value: i64, time_ms: u64) -> Record {
        Record {
            signal: Signal::Gauge,
            ..Record::counter(name, value, time_ms)
        }
    }

    pub fn event(name: &str, time_ms: u64) -> Record {
        Record {
            signal: Signal::Event,
            ..Record::counter(name, 1, time_ms)
        }
    }

    pub fn with_unit(mut self, unit: &str) -> Record {
        self.unit = unit.into();
        self
    }

    pub fn with_attr(mut self, key: &str, value: &str) -> Record {
        self.attrs.push((key.into(), value.into()));
        self
    }
}

/// A batch of telemetry from one device, addressed to a collector. `resource` describes the emitter
/// (platform, app, sdk version) the way an OTLP Resource does.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryBatch {
    /// Resource attributes: `platform=ios`, `app=...`, `sdk=hop/x`. Opt-in, coarse, anonymous.
    pub resource: Vec<(String, String)>,
    pub records: Vec<Record>,
}

impl TelemetryBatch {
    pub fn new() -> TelemetryBatch {
        TelemetryBatch::default()
    }

    pub fn with_resource(mut self, key: &str, value: &str) -> TelemetryBatch {
        self.resource.push((key.into(), value.into()));
        self
    }

    pub fn push(mut self, record: Record) -> TelemetryBatch {
        self.records.push(record);
        self
    }

    pub fn counter(self, name: &str, value: i64, time_ms: u64) -> TelemetryBatch {
        self.push(Record::counter(name, value, time_ms))
    }

    pub fn gauge(self, name: &str, value: i64, time_ms: u64) -> TelemetryBatch {
        self.push(Record::gauge(name, value, time_ms))
    }

    pub fn event(self, name: &str, time_ms: u64) -> TelemetryBatch {
        self.push(Record::event(name, time_ms))
    }

    /// Encode for the `hop.telemetry` service `args` (postcard, the same codec as the wire).
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Decode a received batch, rejecting anything past the DoS bounds. Returns `None` on malformed
    /// or oversized input, so a collector drops attacker-shaped telemetry rather than trusting it.
    pub fn from_bytes(bytes: &[u8]) -> Option<TelemetryBatch> {
        let batch: TelemetryBatch = postcard::from_bytes(bytes).ok()?;
        batch.within_bounds().then_some(batch)
    }

    /// Whether the batch respects the decode bounds (record/attr counts + string lengths).
    pub fn within_bounds(&self) -> bool {
        self.records.len() <= MAX_RECORDS
            && self.resource.len() <= MAX_ATTRS
            && attrs_ok(&self.resource)
            && self.records.iter().all(|r| {
                r.name.len() <= MAX_STR
                    && r.unit.len() <= MAX_STR
                    && r.attrs.len() <= MAX_ATTRS
                    && attrs_ok(&r.attrs)
            })
    }

    /// The count of records, the unit billed to the `hop_telemetry_events` observability meter
    /// (DESIGN.md §37); the collector meters this per tenant on receipt.
    pub fn billable_events(&self) -> u64 {
        self.records.len() as u64
    }
}

fn attrs_ok(attrs: &[(String, String)]) -> bool {
    attrs
        .iter()
        .all(|(k, v)| k.len() <= MAX_STR && v.len() <= MAX_STR)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TelemetryBatch {
        TelemetryBatch::new()
            .with_resource("platform", "ios")
            .with_resource("app", "acme.dispatch")
            .push(Record::counter("hop.bundle.delivered", 3, 1000).with_attr("bearer", "ble"))
            .push(Record::gauge("hop.delivery.latency_ms", 2100, 1000).with_unit("ms"))
            .event("hop.spool.parked", 1200)
    }

    #[test]
    fn round_trips_through_postcard() {
        let batch = sample();
        let decoded = TelemetryBatch::from_bytes(&batch.to_bytes()).expect("valid");
        assert_eq!(decoded, batch);
        assert_eq!(decoded.billable_events(), 3);
    }

    #[test]
    fn rejects_batches_over_the_record_bound() {
        let mut batch = TelemetryBatch::new();
        for i in 0..(MAX_RECORDS + 1) {
            batch = batch.counter("hop.x", i as i64, 0);
        }
        assert!(!batch.within_bounds());
        // A crafted over-bound batch decodes structurally but is dropped by the bound check.
        assert!(TelemetryBatch::from_bytes(&batch.to_bytes()).is_none());
    }

    #[test]
    fn rejects_oversized_strings() {
        let big = "x".repeat(MAX_STR + 1);
        let batch = TelemetryBatch::new().push(Record::counter(&big, 1, 0));
        assert!(!batch.within_bounds());
        assert!(TelemetryBatch::from_bytes(&batch.to_bytes()).is_none());
    }

    #[test]
    fn rejects_malformed_bytes() {
        assert!(TelemetryBatch::from_bytes(&[0xff, 0xff, 0xff, 0xff]).is_none());
    }
}
