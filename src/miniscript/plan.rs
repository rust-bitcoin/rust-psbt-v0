// SPDX-License-Identifier: CC0-1.0

//! Implements the `Plan::update_pstb_input` function.
// Taken from `rust-miniscript::plan`.

use bitcoin::taproot::{TapLeafHash, ControlBlock, LeafVersion};
use bitcoin::{bip32, ScriptBuf, XOnlyPublicKey};
use miniscript::plan::Plan;
use miniscript::miniscript::satisfy::{SchnorrSigType, Placeholder};
use miniscript::descriptor::{self, Descriptor};
use miniscript::ToPublicKey;

use crate::Input;
use crate::prelude::BTreeMap;

/// Update a PSBT input with the metadata required to complete this plan
///
/// This will only add the metadata for items required to complete this plan. For example, if
/// there are multiple keys present in the descriptor, only the few used by this plan will be
/// added to the PSBT.
pub fn update_psbt_input(plan: &Plan, input: &mut Input) {
    if let Descriptor::Tr(tr) = &plan.descriptor {
        enum SpendType {
            KeySpend { internal_key: XOnlyPublicKey },
            ScriptSpend { leaf_hash: TapLeafHash },
        }

        #[derive(Default)]
        struct TrDescriptorData {
            tap_script: Option<ScriptBuf>,
            control_block: Option<ControlBlock>,
            spend_type: Option<SpendType>,
            key_origins: BTreeMap<XOnlyPublicKey, bip32::KeySource>,
        }

        let spend_info = tr.spend_info();
        input.tap_merkle_root = spend_info.merkle_root();

        let data = plan
            .template
            .iter()
            .fold(TrDescriptorData::default(), |mut data, item| {
                match item {
                    Placeholder::TapScript(script) => data.tap_script = Some(script.clone()),
                    Placeholder::TapControlBlock(cb) => data.control_block = Some(cb.clone()),
                    Placeholder::SchnorrSigPk(pk, sig_type, _) => {
                        let raw_pk = pk.to_x_only_pubkey();

                        match (&data.spend_type, sig_type) {
                            // First encountered schnorr sig, update the `TrDescriptorData` accordingly
                            (None, SchnorrSigType::KeySpend { .. }) => data.spend_type = Some(SpendType::KeySpend { internal_key: raw_pk }),
                            (None, SchnorrSigType::ScriptSpend { leaf_hash }) => data.spend_type = Some(SpendType::ScriptSpend { leaf_hash: *leaf_hash }),

                            // Inconsistent placeholders (should be unreachable with the
                            // current implementation)
                            (Some(SpendType::KeySpend {..}), SchnorrSigType::ScriptSpend { .. }) | (Some(SpendType::ScriptSpend {..}), SchnorrSigType::KeySpend{..}) => unreachable!("Mixed taproot key-spend and script-spend placeholders in the same plan"),

                            _ => {},
                        }

                        for path in pk.full_derivation_paths() {
                            data.key_origins.insert(raw_pk, (pk.master_fingerprint(), path));
                        }
                    }
                    Placeholder::SchnorrSigPkHash(_, tap_leaf_hash, _) => {
                        data.spend_type = Some(SpendType::ScriptSpend { leaf_hash: *tap_leaf_hash });
                    }
                    _ => {}
                }

                data
            });

        // TODO: TapTree. we need to re-traverse the tree to build it, sigh

        let leaf_hash = match data.spend_type {
            Some(SpendType::KeySpend { internal_key }) => {
                input.tap_internal_key = Some(internal_key);
                None
            }
            Some(SpendType::ScriptSpend { leaf_hash }) => Some(leaf_hash),
            _ => None,
        };
        for (pk, key_source) in data.key_origins {
            input
                .tap_key_origins
                .entry(pk)
                .and_modify(|(leaf_hashes, _)| {
                    if let Some(lh) = leaf_hash {
                        if leaf_hashes.iter().all(|&i| i != lh) {
                            leaf_hashes.push(lh);
                        }
                    }
                })
                .or_insert_with(|| (vec![], key_source));
        }
        if let (Some(tap_script), Some(control_block)) = (data.tap_script, data.control_block) {
            input
                .tap_scripts
                .insert(control_block, (tap_script, LeafVersion::TapScript));
        }
    } else {
        for item in &plan.template {
            if let Placeholder::EcdsaSigPk(pk) = item {
                let public_key = pk.to_public_key().inner;
                let master_fingerprint = pk.master_fingerprint();
                for derivation_path in pk.full_derivation_paths() {
                    input
                        .bip32_derivation
                        .insert(public_key, (master_fingerprint, derivation_path));
                }
            }
        }

        match &plan.descriptor {
            Descriptor::Bare(_) | Descriptor::Pkh(_) | Descriptor::Wpkh(_) => {}
            Descriptor::Sh(sh) => match sh.as_inner() {
                descriptor::ShInner::Wsh(wsh) => {
                    input.witness_script = Some(wsh.inner_script());
                    input.redeem_script = Some(wsh.inner_script().to_p2wsh());
                }
                descriptor::ShInner::Wpkh(..) => input.redeem_script = Some(sh.inner_script()),
                descriptor::ShInner::SortedMulti(_) | descriptor::ShInner::Ms(_) => {
                    input.redeem_script = Some(sh.inner_script())
                }
            },
            Descriptor::Wsh(wsh) => input.witness_script = Some(wsh.inner_script()),
            Descriptor::Tr(_) => unreachable!("Tr is dealt with separately"),
        }
    }
}
