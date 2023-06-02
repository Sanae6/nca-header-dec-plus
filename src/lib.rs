use std::cell::RefCell;

use aes::{Aes128, cipher::generic_array::GenericArray, cipher::KeyInit};
use aes::cipher::KeyIvInit;
use ctr::cipher::{StreamCipher, StreamCipherSeek};
use ctr::Ctr128LE;
use ecb::cipher::BlockDecryptMut;
use neon::prelude::*;
use neon::types::buffer::TypedArray;
use xts_mode::Xts128;

type Aes128EcbDec = ecb::Decryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes128CtrDec = ctr::Ctr128LE<Aes128>;

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

fn decrypt_nca_area(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let mut key_buffer = [0; 0x10];
    key_buffer.copy_from_slice(cx.argument::<JsArrayBuffer>(0)?.as_slice(&cx));
    let buffer = cx.argument::<JsArrayBuffer>(1)?;
    let slice = buffer.as_slice(&mut cx);
    // let buffer = cx.argument::<JsArrayBuffer>(2)?;

    let mut ecb = Aes128EcbDec::new(&key_buffer.into());
    let mut out_slice = [0; 0x10];
    ecb.decrypt_block_b2b_mut(slice.into(), (&mut out_slice).into());
    // for s in slice.chunks_mut(0x10) {
    //     println!("test {:02X?}", s);
    //     ecb.decrypt_block_mut(s.into());
    // }

    let mut output_buffer = cx.array_buffer(0x10)?;
    output_buffer.as_mut_slice(&mut cx).copy_from_slice(&out_slice);
    Ok(output_buffer)
}

fn decrypt_xci_enc_header(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let mut key_buffer = [0; 0x10];
    key_buffer.copy_from_slice(cx.argument::<JsArrayBuffer>(0)?.as_slice(&cx));
    let mut iv_buffer = [0; 0x10];
    iv_buffer.copy_from_slice(cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx));
    let contents = cx.argument::<JsArrayBuffer>(2)?.as_mut_slice(&mut cx);
    let mut buffer = [0; 0x70];

    buffer.copy_from_slice(contents);

    type CbcBlock = cbc::cipher::Block<Aes128CbcDec>;

    let iter = buffer
        .chunks_mut(0x10)
        .map(|c| CbcBlock::from_mut_slice(c));
    let mut cbc = Aes128CbcDec::new((&key_buffer).into(), (&iv_buffer).into());

    for chunk in iter {
        cbc.decrypt_block_mut(chunk);
    }

    let mut output_buffer = cx.array_buffer(0x70)?;
    output_buffer.as_mut_slice(&mut cx).copy_from_slice(&buffer);
    Ok(output_buffer)
}

struct XtsWrapper(Xts128<Aes128>);
impl Finalize for XtsWrapper {
    fn finalize<'a, C: Context<'a>>(self, _: &mut C) {
        // don't particularly need to do anything
    }
}

fn create_dec_xts(mut cx: FunctionContext) -> JsResult<JsBox<XtsWrapper>> {
    let mut key_buffer = [0; 0x20];
    key_buffer.copy_from_slice(cx.argument::<JsArrayBuffer>(0)?.as_slice(&cx));

    let cipher_1 = Aes128::new(GenericArray::from_slice(&key_buffer[..0x10]));
    let cipher_2 = Aes128::new(GenericArray::from_slice(&key_buffer[0x10..]));

    let xts = XtsWrapper(Xts128::new(cipher_1, cipher_2));
    let b = cx.boxed(xts);
    let decrypt = JsFunction::new(&mut cx, |mut cx| {
        let mut buffer = [0u8; 0x10];
        buffer.copy_from_slice(cx.argument::<JsArrayBuffer>(0)?.as_slice(&cx));

        let mut out = cx.array_buffer(0x10)?;
        out.as_mut_slice(&mut cx).copy_from_slice(&mut buffer);
        Ok(cx.undefined())
    })?;
    b.set(&mut cx, "decrypt", decrypt)?;
    Ok(b)
}

struct CtrWrapper([u8; 0x10], [u8; 0x10]);
impl CtrWrapper {
    fn read(&mut self, offset: u64, buffer: &mut [u8]) {
    }
}
impl Finalize for CtrWrapper {
    fn finalize<'a, C: Context<'a>>(self, _: &mut C) {
        // don't particularly need to do anything
    }
}

fn dec_ctr_read(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let mut key_buffer = [0; 0x10];
    key_buffer.copy_from_slice(cx.argument::<JsArrayBuffer>(0)?.as_slice(&cx));
    let mut iv_buffer = [0; 0x10];
    iv_buffer.copy_from_slice(cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx));
    let mut out = cx.argument::<JsArrayBuffer>(2)?;

    let mut a = Aes128CtrDec::new(&key_buffer.into(), &iv_buffer.into());
    a.apply_keystream(out.as_mut_slice(&mut cx));

    Ok(out)
}

// fn create_dec_ctr(mut cx: FunctionContext) -> JsResult<JsBox<RefCell<CtrWrapper>>> {
//
//     let iv_buffer = [0; 0x10];
//     let b = cx.boxed(RefCell::new(CtrWrapper(a)));
//     Ok(b)
// }

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("decryptHeader", decrypt_nca_header)?;
    cx.export_function("decryptArea", decrypt_nca_area)?;
    cx.export_function("decryptXciHeader", decrypt_xci_enc_header)?;
    // cx.export_function("createDecXts", create_dec_xts)?;
    // cx.export_function("createDecCtr", create_dec_ctr)?;
    cx.export_function("decCtrRead", dec_ctr_read)?;
    Ok(())
}
