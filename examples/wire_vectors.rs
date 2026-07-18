use std::collections::BTreeMap;
use std::path::Path;

use hop_core::bundle::wire_vectors::{corpus, CORPUS_FILE};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg != "--generate") || args.len() > 1 {
        eprintln!("usage: cargo run -p hop-core --example wire-vectors --features wire-vectors -- [--generate]");
        std::process::exit(2);
    }

    let corpus = corpus();
    let rendered = serde_json::to_string_pretty(&corpus).expect("corpus serializes") + "\n";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_FILE);
    if args.first().map(String::as_str) == Some("--generate") {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create vector directory");
        }
        std::fs::write(&path, rendered).expect("write wire corpus");
        println!("generated {}", path.display());
    } else {
        let committed = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            eprintln!("wire corpus missing at {}: {error}", path.display());
            eprintln!("review BUNDLE_VERSION, then run with --generate for an intentional change");
            std::process::exit(1);
        });
        if committed != rendered {
            eprintln!("wire vector drift in {}", path.display());
            eprintln!("review BUNDLE_VERSION intentionally before regenerating");
            eprintln!("run: cargo run -p hop-core --example wire-vectors --features wire-vectors -- --generate");
            std::process::exit(1);
        }
        println!("wire corpus matches {}", path.display());
    }

    let mut families = BTreeMap::<&str, usize>::new();
    for vector in corpus
        .bundles
        .iter()
        .filter(|vector| vector.primary_payload)
    {
        *families.entry(&vector.family).or_default() += 1;
    }
    println!(
        "vectors: destinations={} primary_payloads={} complete_bundles={} adverts={} nested_layouts={} link_packets={} wire_records={} have_sets={}",
        corpus.destinations.len(),
        corpus.bundles.iter().filter(|vector| vector.primary_payload).count(),
        corpus.bundles.len(),
        corpus.adverts.len(),
        corpus.nested_layouts.len(),
        corpus.link_packets.len(),
        corpus.wire_records.len(),
        corpus.have_sets.len(),
    );
    for (family, count) in families {
        println!("payload family {family}: {count}");
    }
}
