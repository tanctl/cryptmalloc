//! Keys owns the client key, exposes encrypted constants, and reseats tfhe's global server key before every ciphertext operation so downstream modules never touch plaintext secrets.

use core::fmt;
use once_cell::sync::Lazy;
use std::sync::RwLock;
use tfhe::{
    generate_keys, prelude::FheEncrypt, set_server_key, ClientKey, ConfigBuilder, FheBool,
    FheUint32, FheUint64, ServerKey,
};

static GLOBAL_SERVER_KEY: Lazy<RwLock<Option<ServerKey>>> = Lazy::new(|| RwLock::new(None));

pub struct Keys {
    client_key: ClientKey,
    server_key: ServerKey,
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("client_key", &"<elided>")
            .field("server_key", &"<elided>")
            .finish()
    }
}

impl Keys {
    pub fn new() -> Self {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);
        set_server_key(server_key.clone());
        install_global_server_key(&server_key);
        Self {
            client_key,
            server_key,
        }
    }

    pub fn enc_false(&self) -> FheBool {
        set_server_key(self.server_key.clone());
        FheBool::encrypt(false, &self.client_key)
    }

    pub fn enc_true(&self) -> FheBool {
        set_server_key(self.server_key.clone());
        FheBool::encrypt(true, &self.client_key)
    }

    pub fn enc_u32(&self, val: u32) -> FheUint32 {
        set_server_key(self.server_key.clone());
        FheUint32::encrypt(val, &self.client_key)
    }

    pub fn enc_u64(&self, val: u64) -> FheUint64 {
        set_server_key(self.server_key.clone());
        FheUint64::encrypt(val, &self.client_key)
    }

    pub fn enc_zero_u32(&self) -> FheUint32 {
        set_server_key(self.server_key.clone());
        FheUint32::encrypt(0u32, &self.client_key)
    }

    pub fn enc_zero_u64(&self) -> FheUint64 {
        set_server_key(self.server_key.clone());
        FheUint64::encrypt(0u64, &self.client_key)
    }

    pub fn build_enc_indices_u32(&self, count: usize) -> Vec<FheUint32> {
        set_server_key(self.server_key.clone());
        let mut table = Vec::with_capacity(count);
        for idx in 0..count {
            table.push(self.enc_u32(idx as u32));
        }
        table
    }

    pub fn build_enc_offsets_u64(&self, count: usize, block_size: usize) -> Vec<FheUint64> {
        set_server_key(self.server_key.clone());
        let mut table = Vec::with_capacity(count);
        for idx in 0..count {
            let offset = (idx * block_size) as u64;
            table.push(self.enc_u64(offset));
        }
        table
    }
}

impl Default for Keys {
    fn default() -> Self {
        Self::new()
    }
}

fn install_global_server_key(server_key: &ServerKey) {
    if let Ok(mut slot) = GLOBAL_SERVER_KEY.write() {
        *slot = Some(server_key.clone());
    }
}

pub(crate) fn refresh_global_server_key() {
    if let Ok(slot) = GLOBAL_SERVER_KEY.read() {
        if let Some(server_key) = slot.as_ref() {
            set_server_key(server_key.clone());
        }
    }
}
