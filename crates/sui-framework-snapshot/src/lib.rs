// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{io::Read, path::PathBuf};

use sui_types::{
    digests::TransactionDigest,
    move_package::MovePackage,
    object::{Data, Object},
};

pub fn load_bytecode_snapshot(network: &str, protocol_version: u64) -> anyhow::Result<Vec<Object>> {
    let mut snapshot_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    snapshot_path.extend([
        "bytecode_snapshot",
        network,
        protocol_version.to_string().as_str(),
    ]);
    let snapshot_objects: anyhow::Result<Vec<_>> = std::fs::read_dir(&snapshot_path)?
        .flatten()
        .map(|entry| {
            let file_name = entry.file_name().to_str().unwrap().to_string();
            let mut file = std::fs::File::open(snapshot_path.clone().join(file_name))?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            let package: MovePackage = bcs::from_bytes(&buffer)?;
            Ok(Object::new_package_from_data(
                Data::Package(package),
                TransactionDigest::genesis(),
            ))
        })
        .collect();
    snapshot_objects
}
