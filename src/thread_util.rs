use std::sync::OnceLock;

static NUM_THREADS: OnceLock<usize> = OnceLock::new();

// Used by the binary (main.rs) and tests, not directly by library code
#[allow(dead_code)]
pub fn set_num_threads(num_threads: usize) {
    let _ = NUM_THREADS.set(num_threads);
}

pub fn get_num_threads() -> usize {
    *NUM_THREADS.get().unwrap()
}
