use crate::{
    allocator::CryptMalloc,
    encrypted_option::EncryptedOption,
    encrypted_ptr::EncryptedPtr,
    keys::refresh_global_server_key,
};
use tfhe::{prelude::*, set_server_key, FheUint64};

#[derive(Debug)]
pub struct EVM<'a> {
    allocator: &'a mut CryptMalloc,
}

impl<'a> EVM<'a> {
    pub fn new(allocator: &'a mut CryptMalloc) -> Self {
        set_server_key(allocator.keys().server_key());
        Self { allocator }
    }

    pub fn allocator(&mut self) -> &mut CryptMalloc {
        set_server_key(self.allocator.keys().server_key());
        self.allocator
    }

    fn refresh_server_key(&self) {
        refresh_global_server_key();
        set_server_key(self.allocator.keys().server_key());
    }

    pub fn execute(
        &mut self,
        program: &[FheUint64],
        steps: usize,
    ) -> EncryptedOption<EncryptedPtr> {
        self.refresh_server_key();

        let keys = self.allocator.keys();
        let enc_zero = keys.enc_zero_u64();
        let enc_one = keys.enc_u64(1);
        let enc_false = keys.enc_false();

        let enc_program_len = keys.enc_u64(program.len() as u64);

        let mut pc = enc_zero.clone();
        let mut halted = enc_false.clone();
        let mut acc = EncryptedOption::none(EncryptedPtr::new(enc_zero.clone()), enc_false.clone());

        for _ in 0..steps {
            self.refresh_server_key();

            let pc_lt_len = pc.lt(&enc_program_len);
            let mut instr = enc_zero.clone();

            for (idx, op) in program.iter().enumerate() {
                let enc_idx = keys.enc_u64(idx as u64);
                let is_match = pc.eq(&enc_idx) & pc_lt_len.clone();
                instr = is_match.if_then_else(op, &instr);
            }

            let is_halt = instr.eq(&enc_zero);
            let active = halted.clone().not();
            let should_alloc = (&active) & (&is_halt.not());
            let request_size = should_alloc.if_then_else(&instr, &enc_zero);

            let allocation = self.allocator.allocate(request_size);
            let masked_alloc = EncryptedOption {
                value: allocation.value,
                is_some: allocation.is_some & should_alloc.clone(),
            };

            acc = acc.combine_with(&masked_alloc);
            halted = halted | is_halt;

            let pc_next = &pc + &enc_one;
            let clamped = pc_lt_len.if_then_else(&pc_next, &pc);
            pc = active.if_then_else(&clamped, &pc);
        }

        acc
    }
}
