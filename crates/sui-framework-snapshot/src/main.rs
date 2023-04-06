// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use sui_framework::make_system_packages;
use sui_protocol_config::ProtocolVersion;
use sui_types::move_package::MovePackage;

fn main() {
    let (network, git_version) = parse_args();
    // Always generate snapshot for the latest version.
    let version = ProtocolVersion::MAX.as_u64();
    let mut files = vec![];
    for package in make_system_packages() {
        let id = package.id().to_string();
        write_package_to_file(&network, version, &id, &package);
        files.push(id);
    }
    update_manifest(&network, git_version, version, files);
}

/// Parse args and return network name and git revision.
fn parse_args() -> (String, String) {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <devnet|testnet|mainnet> <git_version>", args[0]);
        std::process::exit(1);
    }

    // Check if the argument is one of the allowed values
    let allowed_values = ["devnet", "testnet", "mainnet"];
    let arg = args[1].as_str();
    if !allowed_values.contains(&arg) {
        eprintln!(
            "Error: argument must be one of {}",
            allowed_values.join(", ")
        );
        std::process::exit(1);
    }
    (args[1].clone(), args[2].clone())
}

fn write_package_to_file(network: &str, version: u64, package_id: &str, package: &MovePackage) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.extend(["bytecode_snapshot", network, version.to_string().as_str()]);
    fs::create_dir_all(&path)
        .or_else(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => Ok(()),
            _ => Err(e),
        })
        .expect("Unable to create snapshot directory");
    let bytes = bcs::to_bytes(package).expect("Deserialization cannot fail");
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true) // Truncate file to zero length if it exists
        .create(true)
        .open(path.join(package_id))
        .expect("Unable to open file"); // Open file to write to

    // Write the data to the file
    file.write_all(&bytes)
        .expect("Unable to write data to file");
}

#[derive(Serialize, Default, Deserialize)]
struct SnapshotManifest {
    /// Map from network name (e.g. testnet) to a map from
    /// protocol version to each corresponding snapshot.
    map: BTreeMap<String, BTreeMap<u64, SingleSnapshot>>,
}

#[derive(Serialize, Deserialize)]
struct SingleSnapshot {
    /// Git revision that this snapshot is taken on.
    git_revision: String,
    /// List of file names (also identical to object ID) of the bytecode package files.
    file_names: Vec<String>,
}

fn update_manifest(network: &str, git_revision: String, version: u64, files: Vec<String>) {
    let filename = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("bytecode_snapshot")
        .join("manifest.json");
    let mut snapshot = deserialize_from_file(&filename);

    let entry = snapshot
        .map
        .entry(network.to_owned())
        .or_insert_with(BTreeMap::new);
    entry.insert(
        version,
        SingleSnapshot {
            git_revision,
            file_names: files,
        },
    );

    serialize_to_file(&filename, &snapshot);
}

fn deserialize_from_file(filename: &PathBuf) -> SnapshotManifest {
    let mut file = match File::open(filename) {
        Ok(f) => f,
        Err(_) => {
            let mut new_file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(filename)
                .expect("Could not create new file");
            let snapshot = SnapshotManifest::default();
            let json =
                serde_json::to_string(&snapshot).expect("Could not serialize SnapshotManifest");
            new_file
                .write_all(json.as_bytes())
                .expect("Could not write to new file");
            new_file.flush().expect("Could not flush new file");
            return snapshot;
        }
    };

    let mut json_str = String::new();
    file.read_to_string(&mut json_str)
        .expect("Could not read file");

    serde_json::from_str::<SnapshotManifest>(&json_str)
        .expect("Could not deserialize SnapshotManifest")
}

fn serialize_to_file(filename: &PathBuf, snapshot: &SnapshotManifest) {
    let mut file = File::create(filename).expect("Could not create file");
    let json = serde_json::to_string(snapshot).expect("Could not serialize SnapshotManifest");
    file.write_all(json.as_bytes())
        .expect("Could not write to file");
    file.flush().expect("Could not flush file");
}
