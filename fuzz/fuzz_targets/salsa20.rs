use honggfuzz::fuzz;
use cipher::{KeyIvInit, StreamCipher};
use salsa20::{Salsa20, XSalsa20};

const KEY_BYTES: usize = 32;
const IV_BYTES: usize = 8;
const IV_BYTES_XSALSA20: usize = 24;

fn fuzz_salsa20(data: &[u8]) {
    if data.len() < KEY_BYTES + IV_BYTES {
        return;
    }

    let (key, rest) = data.split_at(KEY_BYTES);
    let (iv, input) = rest.split_at(IV_BYTES);
    let mut key_arr = [0u8; KEY_BYTES];
    let mut iv_arr = [0u8; IV_BYTES];
    key_arr.copy_from_slice(key);
    iv_arr.copy_from_slice(iv);

    let mut cipher = Salsa20::new(&key_arr.into(), &iv_arr.into());
    let mut buf = input.to_vec();
    cipher.apply_keystream(&mut buf);
}

fn fuzz_xsalsa20(data: &[u8]) {
    if data.len() < KEY_BYTES + IV_BYTES_XSALSA20 {
        return;
    }

    let (key, rest) = data.split_at(KEY_BYTES);
    let (iv, input) = rest.split_at(IV_BYTES_XSALSA20);
    let mut key_arr = [0u8; KEY_BYTES];
    let mut iv_arr = [0u8; IV_BYTES_XSALSA20];
    key_arr.copy_from_slice(key);
    iv_arr.copy_from_slice(iv);

    let mut cipher = XSalsa20::new(&key_arr.into(), &iv_arr.into());
    let mut buf = input.to_vec();
    cipher.apply_keystream(&mut buf);
}

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            fuzz_salsa20(data);
            fuzz_xsalsa20(data);
        });
    }
}