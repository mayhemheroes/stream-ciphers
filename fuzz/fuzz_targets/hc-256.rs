use honggfuzz::fuzz;
use cipher::{KeyIvInit};
use hc_256::Hc256;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            if data.len() < 32 {
                return;
            }

            // Create a key from the seed
            let key = &data[0..16];
            let iv = &data[16..32];

            // Test with IV
            let _ = Hc256::new_from_slices(key, iv).unwrap();
        });
    }
}
