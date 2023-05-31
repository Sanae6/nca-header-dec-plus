use neon::prelude::*;
use neon::types::buffer::TypedArray;
use aes::{Aes128, cipher::KeyInit, cipher::generic_array::GenericArray};
use xts_mode::{Xts128};

pub fn get_nintendo_tweak(sector_index: u128) -> [u8; 0x10] {
    sector_index.to_be_bytes()
}

fn decrypt_nca_header(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let mut key_buffer = [0; 0x20];
    key_buffer.copy_from_slice(cx.argument::<JsArrayBuffer>(0)?.as_slice(&cx));
    let input_buffer = cx.argument::<JsArrayBuffer>(1)?;
    let mut buffer = [0; 0xC00];

    buffer.copy_from_slice(input_buffer.as_slice(&cx));

    // Read into buffer header to be decrypted

    let cipher_1 = Aes128::new(GenericArray::from_slice(&key_buffer[..0x10]));
    let cipher_2 = Aes128::new(GenericArray::from_slice(&key_buffer[0x10..]));

    let xts = Xts128::new(cipher_1, cipher_2);

    // Decrypt the first 0x400 bytes of the header in 0x200 sections
    xts.decrypt_area(&mut buffer[0..0x400], 0x200, 0, get_nintendo_tweak);

    let magic = &buffer[0x200..0x204];
    assert_eq!(magic, b"NCA3"); // In older NCA versions the section index used in header encryption was different

    // Decrypt the rest of the header
    xts.decrypt_area(&mut buffer[0x400..0xC00], 0x200, 2, get_nintendo_tweak);
    let mut output_buffer = cx.array_buffer(0xC00)?;
    output_buffer.as_mut_slice(&mut cx).copy_from_slice(&buffer);
    Ok(output_buffer)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("decrypt", decrypt_nca_header)?;
    Ok(())
}