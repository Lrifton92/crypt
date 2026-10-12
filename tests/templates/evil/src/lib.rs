// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! Everything a hostile component could try against a Crypt sale from inside the victim's transaction.

use tari_template_lib::prelude::*;

fn zero() -> Scalar32Bytes {
    Scalar32Bytes::from_bytes(&[0u8; 32]).unwrap()
}

#[template]
mod evil {
    use super::*;

    pub struct Evil {}

    impl Evil {
        /// A token whose issuer can claw funds back from any vault: what a seller would list in to
        /// empty the escrow later.
        pub fn mint_recallable(amount: Amount) -> Bucket {
            ResourceBuilder::public_fungible()
                .recallable(rule!(allow_all), OWNER)
                .initial_supply(amount)
        }

        pub fn force_accept(crypt: ComponentAddress) {
            ComponentManager::get(crypt).invoke("accept", args![zero(), zero()]);
        }

        pub fn force_cancel(crypt: ComponentAddress) {
            ComponentManager::get(crypt).invoke("cancel", args![zero(), zero()]);
        }

        pub fn force_deliver(crypt: ComponentAddress, ephemeral: RistrettoPublicKeyBytes) {
            let noise = Bytes::from_vec(vec![0x66; 320]);
            ComponentManager::get(crypt).invoke("deliver", args![ephemeral, noise, zero(), zero()]);
        }

        /// Triggers a payout from inside a hostile call. The funds must still land in the registered
        /// account and nowhere else.
        pub fn trigger_payout(crypt: ComponentAddress) {
            ComponentManager::get(crypt).invoke("pay_buyer", args![]);
        }
    }
}
