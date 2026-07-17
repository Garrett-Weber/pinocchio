#![no_main]
use libfuzzer_sys::fuzz_target;
use pinocchio::{account_info::AccountInfo, entrypoint, pubkey::Pubkey, MAX_TX_ACCOUNTS};
use solana_program::entrypoint as solana_entrypoint;
use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    mem::{size_of, MaybeUninit},
    ptr::copy_nonoverlapping,
};

/// Mock program ID for testing
const MOCK_PROGRAM_ID: Pubkey = [5u8; 32];

/// Value used to indicate that a serialized account is not a duplicate
const NON_DUP_MARKER: u8 = u8::MAX;

/// The account header in the input buffer: dup marker, is_signer, is_writable,
/// executable, resize_delta (u32), key, owner, lamports, data_len
const ACCOUNT_HEADER: usize = 88;

/// Bytes the runtime leaves after each account's data so a program can grow it
/// in place. The deserializers stride over this, so it has to be here.
const MAX_PERMITTED_DATA_INCREASE: usize = 10 * 1024;

/// BPF alignment constant
const BPF_ALIGN_OF_U128: usize = 8;

/// Cap on instruction data, so the buffer stays a fixed size
const MAX_INSTRUCTION_DATA: usize = 4096;

/// Enough for the worst case we build: 10 accounts, each with a header, its
/// data, the realloc padding and a rent epoch, plus the instruction data.
const INPUT_BUFFER_SIZE: usize = 256 * 1024;

/// Struct representing a memory region with specific alignment
struct AlignedMemory {
    ptr: *mut u8,
    layout: Layout,
}

impl AlignedMemory {
    pub fn new(len: usize) -> Self {
        let layout = Layout::from_size_align(len, BPF_ALIGN_OF_U128).unwrap();
        unsafe {
            // Zeroed: the realloc padding and rent epoch are never written, but
            // both deserializers walk over them.
            let ptr = alloc_zeroed(layout);
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            AlignedMemory { ptr, layout }
        }
    }

    pub unsafe fn write(&mut self, data: &[u8], offset: usize) {
        copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len());
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }
}

impl Drop for AlignedMemory {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr, self.layout);
        }
    }
}

/// Creates an input buffer that mimics the SVM loader format
// This func should be exposed in Agave......
unsafe fn create_input_buffer(
    num_accounts: usize,
    account_flags: &[u8],
    instruction_data: &[u8],
    duplicated_accounts: usize,
) -> AlignedMemory {
    let mut input = AlignedMemory::new(INPUT_BUFFER_SIZE);
    let mut offset = 0;

    // Number of accounts, counting the duplicates appended below
    input.write(
        &((num_accounts + duplicated_accounts) as u64).to_le_bytes(),
        offset,
    );
    offset += size_of::<u64>();

    // Create unique accounts
    for i in 0..num_accounts {
        let mut account = [0u8; ACCOUNT_HEADER];
        account[0] = NON_DUP_MARKER; // Not duplicated
        account[1] = account_flags[i] & 0b1; // is_signer
        account[2] = account_flags[i] & 0b10; // is_writable
        account[3] = 0; // executable
                        // account[4..8] is resize_delta, which the runtime zeroes
        account[8..40].copy_from_slice(&[i as u8; 32]); // key
        account[40..72].copy_from_slice(&[i as u8; 32]); // owner
        account[72..80].copy_from_slice(&(62u64).to_le_bytes()); // lamports
        account[80..88].copy_from_slice(&(i as u64).to_le_bytes()); // data_len

        input.write(&account, offset);
        offset += account.len();

        // Account data, then the realloc padding, then align, then rent epoch
        let account_data = vec![i as u8; i];
        input.write(&account_data, offset);
        offset += account_data.len();
        offset += MAX_PERMITTED_DATA_INCREASE;
        offset += (BPF_ALIGN_OF_U128 - (offset % BPF_ALIGN_OF_U128)) % BPF_ALIGN_OF_U128;
        offset += size_of::<u64>(); // rent epoch
    }

    // Create duplicated accounts
    for _ in 0..duplicated_accounts {
        let dup_marker = (num_accounts - 1) as u8;
        input.write(&[dup_marker, 0, 0, 0, 0, 0, 0, 0], offset);
        offset += size_of::<u64>();
    }

    // Instruction data length
    input.write(&instruction_data.len().to_le_bytes(), offset);
    offset += size_of::<u64>();

    // Instruction data
    input.write(instruction_data, offset);
    offset += instruction_data.len();

    // Program ID
    input.write(&MOCK_PROGRAM_ID, offset);

    input
}

/// Compare deserialize results
fn compare_accounts(
    pinocchio_program_id: &Pubkey,
    pinocchio_accounts: &[MaybeUninit<AccountInfo>],
    pinocchio_count: usize,
    pinocchio_instruction_data: &[u8],
    solana_program_id: &[u8],
    solana_accounts: &[solana_program::account_info::AccountInfo],
    solana_instruction_data: &[u8],
) -> bool {
    // Compare program IDs
    if pinocchio_program_id.as_ref() != solana_program_id {
        return false;
    }

    // Compare instruction data
    if pinocchio_instruction_data != solana_instruction_data {
        return false;
    }

    // Compare account counts
    if pinocchio_count != solana_accounts.len() {
        return false;
    }

    // Compare each account's fields
    for (i, solana_account) in solana_accounts.iter().enumerate() {
        let pinocchio_account = unsafe { pinocchio_accounts[i].assume_init_ref() };

        if pinocchio_account.key().as_ref() != solana_account.key.as_ref() {
            return false;
        }
        if pinocchio_account.owner().as_ref() != solana_account.owner.as_ref() {
            return false;
        }
        if pinocchio_account.lamports() != **solana_account.lamports.borrow() {
            return false;
        }
        if pinocchio_account.is_signer() != solana_account.is_signer {
            return false;
        }
        if pinocchio_account.is_writable() != solana_account.is_writable {
            return false;
        }
        if pinocchio_account.executable() != solana_account.executable {
            return false;
        }
        if pinocchio_account.data_len() != solana_account.data_len() {
            return false;
        }

        let pinocchio_data = pinocchio_account.try_borrow_data().unwrap();
        if *pinocchio_data != **solana_account.data.borrow() {
            return false;
        }
    }

    true
}

fuzz_target!(|data: &[u8]| {
    // Skip if data is too small (reduced threshold for better coverage)
    if data.len() < 20 {
        return;
    }

    // Extract parameters from fuzz data with bounds checking
    let num_accounts = (data[0] as usize % 10) + 1; // 1-10 accounts
    let duplicated_accounts = data[1] as usize % 3; // 0-2 duplicated

    // Ensure we have enough data for account flags
    if data.len() < num_accounts + 2 {
        return;
    }

    let account_flags = &data[2..num_accounts + 2];
    let instruction_data = &data[num_accounts + 2..];
    let instruction_data = &instruction_data[..instruction_data.len().min(MAX_INSTRUCTION_DATA)];

    // Create input buffer
    let mut input = unsafe {
        create_input_buffer(
            num_accounts,
            account_flags,
            instruction_data,
            duplicated_accounts,
        )
    };

    // Test Pinocchio deserialize
    let mut pinocchio_accounts = [const { MaybeUninit::<AccountInfo>::uninit() }; MAX_TX_ACCOUNTS];
    let pinocchio_result = unsafe {
        entrypoint::deserialize::<MAX_TX_ACCOUNTS>(input.as_mut_ptr(), &mut pinocchio_accounts)
    };

    // Test Solana deserialize
    let solana_result = unsafe { solana_entrypoint::deserialize(input.as_mut_ptr()) };

    // Compare results
    let (pinocchio_program_id, pinocchio_count, pinocchio_instruction_data) = pinocchio_result;
    let (solana_program_id, solana_accounts, solana_instruction_data) = solana_result;

    let comparison_result = compare_accounts(
        pinocchio_program_id,
        &pinocchio_accounts,
        pinocchio_count,
        pinocchio_instruction_data,
        solana_program_id.as_ref(),
        &solana_accounts,
        solana_instruction_data,
    );

    // The comparison should pass for valid inputs
    if !comparison_result {
        panic!("Deserialize results don't match between Pinocchio and Solana");
    }
});
