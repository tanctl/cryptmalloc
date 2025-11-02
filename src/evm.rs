// evm maintains encrypted pc/halt plus fully encrypted stack and memory, runs plaintext opcodes, and never owns a client key; pre-encrypted pc values are injected so execution avoids runtime encryption.
use core::fmt;
use tfhe::{prelude::*, set_server_key, FheBool, FheUint32, FheUint64, ServerKey};

#[allow(dead_code)]
pub struct EVM {
    pc: FheUint32,
    stack: Vec<FheUint64>,
    stack_len: FheUint32,
    memory: Vec<FheUint64>,
    halt: FheBool,
    program: Vec<u8>,
    server_key: ServerKey,
    enc_false: FheBool,
    enc_true: FheBool,
    enc_zero_u32: FheUint32,
    enc_zero_u64: FheUint64,
    enc_one_u32: FheUint32,
    enc_pc_values: Vec<FheUint32>,
}

impl fmt::Debug for EVM {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EVM")
            .field("program_len", &self.program.len())
            .field("memory_len", &self.memory.len())
            .field("stack_cap", &1024)
            .finish()
    }
}

#[allow(dead_code)]
impl EVM {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        program: Vec<u8>,
        memory_size: usize,
        server_key: ServerKey,
        enc_false: FheBool,
        enc_true: FheBool,
        enc_zero_u32: FheUint32,
        enc_zero_u64: FheUint64,
        enc_one_u32: FheUint32,
        enc_pc_values: Vec<FheUint32>,
    ) -> Self {
        set_server_key(server_key.clone());

        let pc = enc_zero_u32.clone();
        let halt = enc_false.clone();
        let stack_len = enc_zero_u32.clone();
        let stack = Vec::with_capacity(1024);
        let memory = vec![enc_zero_u64.clone(); memory_size];

        Self {
            pc,
            stack,
            stack_len,
            memory,
            halt,
            program,
            server_key,
            enc_false,
            enc_true,
            enc_zero_u32,
            enc_zero_u64,
            enc_one_u32,
            enc_pc_values,
        }
    }

    // stack helpers use encrypted guards for overflow/underflow, run fixed-length scans, and never branch on ciphertexts.
    // encrypted push: always appends a ciphertext payload, guards logical growth with can_push, and bumps stack_len conditionally; physical growth is ignored by consumers beyond stack_len.
    fn stack_push(&mut self, value: FheUint64, condition: FheBool) {
        set_server_key(self.server_key.clone());

        let enc_cap =
            FheUint32::try_encrypt_trivial(1024u32).unwrap_or_else(|_| self.enc_zero_u32.clone());
        let has_space = self.stack_len.lt(&enc_cap);
        let can_push = has_space & condition;

        let stored = can_push.if_then_else(&value, &self.enc_zero_u64);
        self.stack.push(stored);

        let bumped = &self.stack_len + &self.enc_one_u32;
        self.stack_len = can_push.if_then_else(&bumped, &self.stack_len);
    }

    // encrypted pop: scans the fixed logical depth, selects the top element under can_pop, and conditionally decrements stack_len.
    fn stack_pop(&mut self, condition: FheBool) -> FheUint64 {
        set_server_key(self.server_key.clone());

        let has_item = self.stack_len.gt(&self.enc_zero_u32);
        let can_pop = has_item & condition;
        let target_index = &self.stack_len - &self.enc_one_u32;

        let mut value = self.enc_zero_u64.clone();
        for idx in 0..1024 {
            let enc_idx =
                FheUint32::try_encrypt_trivial(idx as u32).unwrap_or_else(|_| self.enc_zero_u32.clone());
            let slot = self
                .stack
                .get(idx)
                .cloned()
                .unwrap_or_else(|| self.enc_zero_u64.clone());
            let is_target = can_pop.clone() & enc_idx.eq(&target_index);
            value = is_target.if_then_else(&slot, &value);
        }

        let decremented = &self.stack_len - &self.enc_one_u32;
        self.stack_len = can_pop.if_then_else(&decremented, &self.stack_len);
        value
    }

    // encrypted double-pop: requires two items, returns (second, first) with underflow masked to zeros.
    fn stack_pop2(&mut self, condition: FheBool) -> (FheUint64, FheUint64) {
        set_server_key(self.server_key.clone());

        let enc_two =
            FheUint32::try_encrypt_trivial(2u32).unwrap_or_else(|_| self.enc_zero_u32.clone());
        let has_two = self.stack_len.ge(&enc_two);
        let can_pop = has_two & condition;

        let first = self.stack_pop(can_pop.clone());
        let second = self.stack_pop(can_pop);
        (second, first)
    }
}
