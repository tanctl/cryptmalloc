use std::fmt;
use std::sync::{Arc, RwLock, RwLockReadGuard};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tfhe::prelude::{FheDecrypt, FheTryEncrypt};
use tfhe::shortint::parameters::list_compression::COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::{
    generate_keys, set_server_key, ClientKey, Config, ConfigBuilder, FheBool, FheUint16, FheUint32,
    FheUint8, ServerKey,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityLevel {
    Performance,
    Balanced,
    Secure,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::Balanced
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextConfig {
    pub security_level: SecurityLevel,
    pub enable_compression: bool,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::default(),
            enable_compression: true,
        }
    }
}

#[derive(Clone)]
pub struct TfheContext {
    inner: Arc<RwLock<ContextState>>,
}

struct ContextState {
    config: Config,
    config_descriptor: ContextConfig,
    client_key: Arc<ClientKey>,
    server_key: Arc<ServerKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TfheContextError {
    KeyGeneration(String),
    Encryption(String),
    Serialization(String),
    IntegrityViolation,
    LockPoisoned,
}

impl std::fmt::Display for TfheContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGeneration(msg) => write!(f, "key generation failure: {msg}"),
            Self::Encryption(msg) => write!(f, "encryption failure: {msg}"),
            Self::Serialization(msg) => write!(f, "serialization failure: {msg}"),
            Self::IntegrityViolation => write!(f, "serialized key integrity check failed"),
            Self::LockPoisoned => write!(f, "internal lock poisoned"),
        }
    }
}

impl std::error::Error for TfheContextError {}

impl TfheContext {
    pub fn new(config: ContextConfig) -> Result<Self, TfheContextError> {
        let tfhe_config = build_config(&config);

        let (client_key, server_key) = generate_keys(tfhe_config);

        let state = ContextState {
            config: tfhe_config,
            config_descriptor: config,
            client_key: Arc::new(client_key),
            server_key: Arc::new(server_key),
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(state)),
        })
    }

    pub fn balanced() -> Result<Self, TfheContextError> {
        Self::new(ContextConfig::default())
    }

    pub fn with_security_level(security_level: SecurityLevel) -> Result<Self, TfheContextError> {
        Self::new(ContextConfig {
            security_level,
            enable_compression: true,
        })
    }

    fn read_keys(&self) -> Result<RwLockReadGuard<'_, ContextState>, TfheContextError> {
        self.inner
            .read()
            .map_err(|_| TfheContextError::LockPoisoned)
    }

    pub fn client_key(&self) -> Result<Arc<ClientKey>, TfheContextError> {
        let handle = {
            let guard = self.read_keys()?;
            Arc::clone(&guard.client_key)
        };
        Ok(handle)
    }

    pub fn server_key(&self) -> Result<Arc<ServerKey>, TfheContextError> {
        let handle = {
            let guard = self.read_keys()?;
            Arc::clone(&guard.server_key)
        };
        Ok(handle)
    }

    pub fn install_server_key(&self) -> Result<(), TfheContextError> {
        let server_key = {
            let guard = self.read_keys()?;
            guard.server_key.as_ref().clone()
        };
        set_server_key(server_key);
        Ok(())
    }

    pub fn config(&self) -> Result<ContextConfig, TfheContextError> {
        let config = {
            let guard = self.read_keys()?;
            guard.config_descriptor.clone()
        };
        Ok(config)
    }

    pub fn noise_capacity(&self) -> Result<usize, TfheContextError> {
        let config = self.config()?;
        Ok(capacity_for_security_profile(&config))
    }

    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub fn encrypt_u8(&self, value: u8) -> Result<FheUint8, TfheContextError> {
        let guard = self.read_keys()?;
        FheUint8::try_encrypt(value, guard.client_key.as_ref())
            .map_err(|err| TfheContextError::Encryption(err.to_string()))
    }

    pub fn decrypt_u8(&self, value: &FheUint8) -> Result<u8, TfheContextError> {
        let guard = self.read_keys()?;
        Ok(value.decrypt(guard.client_key.as_ref()))
    }

    pub fn encrypt_u16(&self, value: u16) -> Result<FheUint16, TfheContextError> {
        let guard = self.read_keys()?;
        FheUint16::try_encrypt(value, guard.client_key.as_ref())
            .map_err(|err| TfheContextError::Encryption(err.to_string()))
    }

    pub fn decrypt_u16(&self, value: &FheUint16) -> Result<u16, TfheContextError> {
        let guard = self.read_keys()?;
        Ok(value.decrypt(guard.client_key.as_ref()))
    }

    pub fn encrypt_u32(&self, value: u32) -> Result<FheUint32, TfheContextError> {
        let guard = self.read_keys()?;
        FheUint32::try_encrypt(value, guard.client_key.as_ref())
            .map_err(|err| TfheContextError::Encryption(err.to_string()))
    }

    pub fn decrypt_u32(&self, value: &FheUint32) -> Result<u32, TfheContextError> {
        let guard = self.read_keys()?;
        Ok(value.decrypt(guard.client_key.as_ref()))
    }

    pub fn encrypt_bool(&self, value: bool) -> Result<FheBool, TfheContextError> {
        let guard = self.read_keys()?;
        FheBool::try_encrypt(value, guard.client_key.as_ref())
            .map_err(|err| TfheContextError::Encryption(err.to_string()))
    }

    pub fn decrypt_bool(&self, value: &FheBool) -> Result<bool, TfheContextError> {
        let guard = self.read_keys()?;
        Ok(value.decrypt(guard.client_key.as_ref()))
    }

    pub fn export_keys(&self) -> Result<Zeroizing<Vec<u8>>, TfheContextError> {
        let (config, descriptor, client_key, server_key) = {
            let guard = self.read_keys()?;
            (
                guard.config,
                guard.config_descriptor.clone(),
                guard.client_key.as_ref().clone(),
                guard.server_key.as_ref().clone(),
            )
        };
        let payload = KeyPayload {
            config,
            descriptor,
            client_key,
            server_key,
        };

        let payload_bytes = Zeroizing::new(
            bincode::serialize(&payload)
                .map_err(|err| TfheContextError::Serialization(err.to_string()))?,
        );
        let checksum: [u8; 32] = Sha256::digest(&payload_bytes).into();

        let envelope = KeyEnvelope { checksum, payload };

        let encoded = Zeroizing::new(
            bincode::serialize(&envelope)
                .map_err(|err| TfheContextError::Serialization(err.to_string()))?,
        );
        Ok(encoded)
    }

    pub fn from_serialized(bytes: &[u8]) -> Result<Self, TfheContextError> {
        let envelope: KeyEnvelope = bincode::deserialize(bytes)
            .map_err(|err| TfheContextError::Serialization(err.to_string()))?;

        let payload_bytes = Zeroizing::new(
            bincode::serialize(&envelope.payload)
                .map_err(|err| TfheContextError::Serialization(err.to_string()))?,
        );
        let expected: [u8; 32] = Sha256::digest(&payload_bytes).into();
        if envelope.checksum != expected {
            return Err(TfheContextError::IntegrityViolation);
        }

        let payload = envelope.payload;
        let state = ContextState {
            config: payload.config,
            config_descriptor: payload.descriptor,
            client_key: Arc::new(payload.client_key),
            server_key: Arc::new(payload.server_key),
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(state)),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct KeyEnvelope {
    checksum: [u8; 32],
    payload: KeyPayload,
}

#[derive(Serialize, Deserialize)]
struct KeyPayload {
    config: Config,
    descriptor: ContextConfig,
    client_key: ClientKey,
    server_key: ServerKey,
}

fn build_config(config: &ContextConfig) -> Config {
    let base_builder = match config.security_level {
        SecurityLevel::Performance => ConfigBuilder::default_with_small_encryption(),
        SecurityLevel::Balanced => ConfigBuilder::default(),
        SecurityLevel::Secure => ConfigBuilder::default_with_big_encryption(),
    };

    let builder = if config.enable_compression
        && !matches!(config.security_level, SecurityLevel::Performance)
    {
        base_builder.enable_compression(COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
    } else {
        base_builder
    };

    builder.build()
}

// noise capacity numbers are heuristic placeholders until tfhe exposes precise budgets
fn capacity_for_security_profile(config: &ContextConfig) -> usize {
    match config.security_level {
        SecurityLevel::Performance => 48,
        SecurityLevel::Balanced => {
            if config.enable_compression {
                96
            } else {
                80
            }
        }
        SecurityLevel::Secure => {
            if config.enable_compression {
                160
            } else {
                128
            }
        }
    }
}

impl fmt::Debug for TfheContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.config() {
            Ok(cfg) => f
                .debug_struct("TfheContext")
                .field("security_level", &cfg.security_level)
                .field("compression", &cfg.enable_compression)
                .finish_non_exhaustive(),
            Err(_) => f.debug_struct("TfheContext").finish_non_exhaustive(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    const LEVELS: &[SecurityLevel] = &[
        SecurityLevel::Performance,
        SecurityLevel::Balanced,
        SecurityLevel::Secure,
    ];

    fn roundtrip_u8(ctx: &TfheContext) {
        let cipher = ctx.encrypt_u8(123).expect("encrypt");
        let clear = ctx.decrypt_u8(&cipher).expect("decrypt");
        assert_eq!(clear, 123);
    }

    fn roundtrip_u16(ctx: &TfheContext) {
        let cipher = ctx.encrypt_u16(1024).expect("encrypt");
        let clear = ctx.decrypt_u16(&cipher).expect("decrypt");
        assert_eq!(clear, 1024);
    }

    fn roundtrip_u32(ctx: &TfheContext) {
        let cipher = ctx.encrypt_u32(655_360).expect("encrypt");
        let clear = ctx.decrypt_u32(&cipher).expect("decrypt");
        assert_eq!(clear, 655_360);
    }

    fn bool_roundtrip(ctx: &TfheContext) {
        let cipher = ctx.encrypt_bool(true).expect("encrypt");
        assert!(ctx.decrypt_bool(&cipher).expect("decrypt"));
    }

    #[test]
    fn creates_context_for_all_security_levels() {
        for &level in LEVELS {
            let context = TfheContext::new(ContextConfig {
                security_level: level,
                enable_compression: true,
            })
            .expect("context");
            context.install_server_key().expect("install");

            roundtrip_u8(&context);
            roundtrip_u16(&context);
            roundtrip_u32(&context);
            bool_roundtrip(&context);
        }
    }

    #[test]
    fn context_serialization_roundtrip() {
        let context = TfheContext::balanced().expect("context");
        let exported = context.export_keys().expect("export");
        let imported = TfheContext::from_serialized(&exported).expect("import");

        roundtrip_u8(&imported);
        roundtrip_u16(&imported);
        roundtrip_u32(&imported);
    }

    #[test]
    fn serialization_rejects_modified_payload() {
        let context = TfheContext::balanced().expect("context");
        let mut exported = context.export_keys().expect("export");
        let mid = exported.len() / 2;
        exported[mid] ^= 0xFF;
        let result = TfheContext::from_serialized(&exported);
        assert!(matches!(result, Err(TfheContextError::IntegrityViolation)));
    }

    #[test]
    fn thread_safe_encryption() {
        let context = TfheContext::balanced().expect("context");

        let mut handles = Vec::with_capacity(4);
        for i in 0..4 {
            let ctx = context.clone();
            handles.push(thread::spawn(move || {
                let cipher = ctx.encrypt_u32(i * 10).expect("encrypt");
                ctx.decrypt_u32(&cipher).expect("decrypt")
            }));
        }

        for (idx, handle) in handles.into_iter().enumerate() {
            let value = handle.join().expect("thread join");
            let expected = u32::try_from(idx).expect("thread index fits in u32") * 10;
            assert_eq!(value, expected);
        }
    }
}
