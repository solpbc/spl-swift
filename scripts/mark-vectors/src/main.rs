// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

//! Prints the shared journal-mark vectors, every value computed by `spl_core::mark`.

use indexmap::IndexMap;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use spl_core::mark::mark_from_jid;
use spl_core::relay_window::jid_from_spki;

const REFERENCE_SPKIS: [&str; 4] = [
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714cdd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858",
    "3059301306072a8648ce3d020106082a8648ce3d030107034200047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
    "3059301306072a8648ce3d020106082a8648ce3d030107034200048e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a373eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4",
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004ea68d7b6fedf0b71878938d51d71f8729e0acb8c2c6df8b3d79e8a4b90949ee02a2744c972c9fce787014a964a8ea0c84d714feaa4de823fe85a224a4dd048fa",
];

const REFUSED_JOURNAL_IDS: [&str; 6] = [
    "",
    "not-a-journal-id",
    "f30ed159ef468e9c913fe49f0fe7d2010000",
    "f30ed159-ef46-8e9c-913f-e49f0fe7d20g",
    "f30ed159-ef46-8e9c-913f-e49f0fe7d20",
    "f30ed159-ef46-8e9c-913f-e49f-fe7d201",
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn spread_journal_id(seed: u32) -> String {
    let digest = Sha256::digest(format!("spl-swift mark vector {seed}"));
    let h = hex(&digest[..16]);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

fn mark(journal_id: &str) -> Value {
    serde_json::to_value(mark_from_jid(journal_id).unwrap().to_render_spec()).unwrap()
}

fn digest_of_lines(lines: impl Iterator<Item = String>) -> String {
    let mut hasher = Sha256::new();
    for line in lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex(&hasher.finalize())
}

fn main() {
    let from_spki: Vec<Value> = REFERENCE_SPKIS
        .iter()
        .map(|spki| {
            let jid = jid_from_spki(&unhex(spki)).unwrap();
            json!({"spki_hex": spki, "journal_id": jid, "mark": mark(&jid)})
        })
        .collect();

    let mut from_journal_id: Vec<Value> = (0..10)
        .map(|seed| {
            let jid = spread_journal_id(seed);
            json!({"journal_id": jid, "mark": mark(&jid)})
        })
        .collect();
    let upper = spread_journal_id(0).to_uppercase();
    from_journal_id.push(json!({"journal_id": upper, "mark": mark(&upper)}));

    let refused: Vec<Value> = REFUSED_JOURNAL_IDS
        .iter()
        .map(|jid| {
            assert!(mark_from_jid(jid).is_err(), "{jid} should be refused");
            json!(jid)
        })
        .collect();

    // Every table entry, in order, without a derivation per entry.
    let checkout = std::env::args().nth(1).expect("usage: spl-swift-mark-vectors <spl-rust checkout>");
    let asset = |name: &str| {
        std::fs::read_to_string(format!("{checkout}/crates/spl-core/assets/mark_assets/{name}")).unwrap()
    };
    let glyphs: IndexMap<String, String> = serde_json::from_str(&asset("glyphs.json")).unwrap();
    let colors: Vec<(String, String)> = serde_json::from_str(&asset("colors.json")).unwrap();
    let words: Vec<String> = serde_json::from_str(&asset("words.json")).unwrap();
    let tables = json!({
        "glyphs_sha256": digest_of_lines(glyphs.iter().map(|(name, svg)| format!("{name}\t{svg}"))),
        "colors_sha256": digest_of_lines(colors.iter().map(|(name, value)| format!("{name}\t{value}"))),
        "words_sha256": digest_of_lines(words.iter().cloned()),
    });

    let vectors = json!({
        "generator": "scripts/mark-vectors, computed by spl_core::mark::mark_from_jid",
        "spl_rust_revision": "6ecae85c0606896d9ea29d50f3718ae15ed96821",
        "from_spki": from_spki,
        "from_journal_id": from_journal_id,
        "refused_journal_ids": refused,
        "tables": tables,
    });
    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}
