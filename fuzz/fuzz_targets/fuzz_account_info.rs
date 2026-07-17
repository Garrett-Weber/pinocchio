#![no_main]
use libfuzzer_sys::fuzz_target;
use pinocchio::pubkey::Pubkey;

fuzz_target!(|data: &[u8]| {
    // Fuzz pubkey operations and PDA creation
    if data.len() < 32 {
        return;
    }

    // Create pubkeys from fuzz data
    let pubkey1: Pubkey = data[0..32].try_into().unwrap_or([0u8; 32]);
    let pubkey2: Pubkey = if data.len() >= 64 {
        data[32..64].try_into().unwrap_or([0u8; 32])
    } else {
        [1u8; 32]
    };

    // Test pubkey operations
    let _ = pubkey1 == pubkey2;
    let _ = pubkey1 != pubkey2;
    
    // Test pubkey comparison function
    let _ = pinocchio::pubkey::pubkey_eq(&pubkey1, &pubkey2);
    
    // Test with different data patterns
    if data.len() >= 96 {
        let seed = &data[64..96];
        let _ = pinocchio::pubkey::create_with_seed(&pubkey1, seed, &pubkey2);
    }
    
    // Test PDA creation with various seeds
    if data.len() >= 128 {
        let seeds = [&data[64..96], &data[96..128]];
        let _ = pinocchio::pubkey::try_find_program_address(&seeds, &pubkey1);
    }
    
    // Test checked PDA creation
    if data.len() >= 160 {
        let seeds = [&data[64..96], &data[96..128], &data[128..160]];
        let _ = pinocchio::pubkey::checked_create_program_address(&seeds, &pubkey1);
    }
});