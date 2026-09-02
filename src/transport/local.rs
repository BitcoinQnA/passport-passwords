// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::Arc;

use vaults_bridge_core::engine::Engine;
use vaults_bridge_keystore::Keystore;

pub async fn serve(_engine: Arc<Engine<Keystore>>, _bind: &str) -> anyhow::Result<()> {
    // TODO: localize
    super::set_status("Local vault ready; browser connection requires QLv2");
    Ok(())
}
