use honggfuzz::fuzz;
use rabbit::{Rabbit, RabbitKeyOnly};
use cipher::{KeyInit, KeyIvInit, StreamCipher};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            if data.len() < 32 {
                return;
            }

            // Create a seed for rng
            let mut seed = [0u8; 32];
            for (dst, src) in seed.iter_mut().zip(data.iter()) {
                *dst = *src;
            }
            let mut rng = StdRng::from_seed(seed);

            // Create a key/iv
            let key = &data[0..16];
            let iv = &data[16..32];

            // Test without IV
            let _ = RabbitKeyOnly::new_from_slice(key).unwrap();

            // Test with IV
            let _ = Rabbit::new_from_slices(key, iv).unwrap();

            // Get inputs
            let mut rabbit_key_only = RabbitKeyOnly::new_from_slice(key).unwrap();
            let mut rabbit = Rabbit::new_from_slices(key, iv).unwrap();

            let data_len: usize = rng.gen_range(1..=50);
            let mut random_data: Vec<u8> = (0..data_len).map(|_| rng.gen()).collect();

            // Clone the random data for comparison after applying keystream
            let original_data = random_data.clone();

            // Apply the keystream to the random data using RabbitKeyOnly
            rabbit_key_only.apply_keystream(&mut random_data);

            // Apply the keystream again to decrypt the data (with RabbitKeyOnly)
            rabbit_key_only.apply_keystream(&mut random_data);

            // Check if the data is decrypted correctly
            assert_eq!(original_data, random_data);

            // Apply the keystream to the random data using Rabbit
            rabbit.apply_keystream(&mut random_data);

            // Apply the keystream again to decrypt the data (with Rabbit)
            rabbit.apply_keystream(&mut random_data);

            // Check if the data is decrypted correctly
            assert_eq!(original_data, random_data);
        });
    }
}
