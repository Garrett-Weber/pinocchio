#![no_main]
use libfuzzer_sys::fuzz_target;
use pinocchio::instruction::{Instruction, AccountMeta, Seed, Signer};
use pinocchio::pubkey::Pubkey;

fuzz_target!(|data: &[u8]| {
    // Fuzz CPI (Cross-Program Invocation) operations
    if data.len() < 32 {
        return;
    }

    // Create program ID from fuzz data
    let program_id: Pubkey = data[0..32].try_into().unwrap_or([0u8; 32]);

    // Create a simple instruction with minimal accounts
    let pubkey1: Pubkey = if data.len() >= 64 {
        data[32..64].try_into().unwrap_or([0u8; 32])
    } else {
        [1u8; 32]
    };
    
    let pubkey2: Pubkey = if data.len() >= 96 {
        data[64..96].try_into().unwrap_or([0u8; 32])
    } else {
        [2u8; 32]
    };

    // Create account metas
    let account_metas = [
        AccountMeta::new(&pubkey1, true, false),
        AccountMeta::new(&pubkey2, false, true),
    ];

    // Create instruction data from remaining bytes
    let instruction_data = if data.len() > 96 {
        &data[96..]
    } else {
        &[]
    };

    // Create instruction for CPI
    let instruction = Instruction {
        program_id: &program_id,
        accounts: &account_metas,
        data: instruction_data,
    };

    // Test instruction access
    let _ = instruction.program_id;
    let _ = instruction.accounts;
    let _ = instruction.data;
    
    // Test account meta creation
    let _ = AccountMeta::readonly(&pubkey1);
    let _ = AccountMeta::writable(&pubkey1);
    let _ = AccountMeta::readonly_signer(&pubkey1);
    let _ = AccountMeta::writable_signer(&pubkey1);
    
    // Test seed creation for PDA signing
    if data.len() >= 128 {
        let seed_data = &data[96..128];
        let seed = Seed::from(seed_data);
        let _ = &*seed; // Test deref
    }
    
    // Test signer creation for PDA signing
    if data.len() >= 160 {
        let seed1 = Seed::from(&data[96..128]);
        let seed2 = Seed::from(&data[128..160]);
        let seeds = [seed1, seed2];
        let signer = Signer::from(&seeds);
        let _ = signer;
    }
    
    // Test PDA creation patterns that might be used in CPI
    if data.len() >= 192 {
        let seeds = [&data[128..160], &data[160..192]];
        let _ = pinocchio::pubkey::try_find_program_address(&seeds, &program_id);
    }
});