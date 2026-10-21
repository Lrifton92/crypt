// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! The demo's engine for the browser: `game::Game` behind wasm-bindgen. Results come back as plain
//! JS objects; a refused step throws an `Error` whose message the page shows as is.

use serde::Serialize;
use wasm_bindgen::prelude::*;

pub mod game;
pub mod live;

fn js<T: Serialize>(value: &T) -> JsValue {
    serde_wasm_bindgen::to_value(value).expect("plain data serializes")
}

fn out<T: Serialize>(result: Result<T, String>) -> Result<JsValue, JsError> {
    result.map(|value| js(&value)).map_err(|error| JsError::new(&error))
}

#[wasm_bindgen]
pub struct Game(game::Game);

#[wasm_bindgen]
impl Game {
    #[wasm_bindgen(constructor)]
    #[must_use]
    pub fn new() -> Game {
        Game(game::Game::new())
    }

    /// Amounts are `u32` so the page passes plain numbers, not `BigInt`s.
    ///
    /// # Errors
    /// See `game::Game::list`.
    pub fn list(&mut self, secret: &str, price: u32, buyer_bond: u32, seller_bond: u32) -> Result<JsValue, JsError> {
        out(self.0.list(secret, price.into(), buyer_bond.into(), seller_bond.into()))
    }

    /// # Errors
    /// See `game::Game::buy`.
    pub fn buy(&mut self) -> Result<JsValue, JsError> {
        out(self.0.buy())
    }

    /// # Errors
    /// See `game::Game::deliver_honest`.
    pub fn deliver_honest(&mut self) -> Result<JsValue, JsError> {
        out(self.0.deliver_honest())
    }

    /// # Errors
    /// See `game::Game::deliver_fake`.
    pub fn deliver_fake(&mut self, fake_secret: &str) -> Result<JsValue, JsError> {
        out(self.0.deliver_fake(fake_secret))
    }

    /// # Errors
    /// See `game::Game::buyer_open`.
    pub fn buyer_open(&self) -> Result<JsValue, JsError> {
        out(self.0.buyer_open())
    }

    /// # Errors
    /// See `game::Game::accept`.
    pub fn accept(&mut self) -> Result<JsValue, JsError> {
        out(self.0.accept())
    }

    /// # Errors
    /// See `game::Game::dispute`.
    pub fn dispute(&mut self) -> Result<JsValue, JsError> {
        out(self.0.dispute())
    }

    pub fn advance_epochs(&mut self, n: u32) {
        self.0.advance_epochs(n.into());
    }

    /// # Errors
    /// See `game::Game::claim_undelivered`.
    pub fn claim_undelivered(&mut self) -> Result<JsValue, JsError> {
        out(self.0.claim_undelivered())
    }

    /// # Errors
    /// See `game::Game::claim_uncontested`.
    pub fn claim_uncontested(&mut self) -> Result<JsValue, JsError> {
        out(self.0.claim_uncontested())
    }

    #[must_use]
    pub fn state(&self) -> JsValue {
        js(&self.0.state())
    }
}

impl Default for Game {
    fn default() -> Self {
        Self::new()
    }
}

/// A real sale on esmeralda: the client side of each step, for the visitor's wallet to send.
#[wasm_bindgen]
pub struct LiveSale(live::LiveSale);

#[wasm_bindgen]
impl LiveSale {
    /// # Errors
    /// See `live::LiveSale::new`.
    #[wasm_bindgen(constructor)]
    pub fn new(secret: &str) -> Result<LiveSale, JsError> {
        live::LiveSale::new(secret)
            .map(LiveSale)
            .map_err(|error| JsError::new(&error))
    }

    #[must_use]
    pub fn list(&self) -> JsValue {
        js(&self.0.list())
    }

    /// # Errors
    /// See `live::LiveSale::buy`.
    pub fn buy(&mut self, component: &str) -> Result<JsValue, JsError> {
        out(self.0.buy(component))
    }

    /// # Errors
    /// See `live::LiveSale::deliver`.
    pub fn deliver(&mut self) -> Result<JsValue, JsError> {
        out(self.0.deliver())
    }

    /// # Errors
    /// See `live::LiveSale::accept`.
    pub fn accept(&self) -> Result<JsValue, JsError> {
        out(self.0.accept())
    }
}
