use std::cell::RefCell;
use std::ops::{Deref, Div};

use aes::{Aes128, cipher::generic_array::GenericArray, cipher::KeyInit};
use aes::cipher::KeyIvInit;
use bytemuck::{cast_slice, cast_slice_mut};
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

struct CtrWrapper {
    key: [u8; 0x10],
    counter: [u8; 0x10],
}

impl CtrWrapper {
    fn update_counter(&mut self, offset: u64) {
        let mut off = offset >> 4;
        for j in 0..7 {
            self.counter[0x10 - j - 1] = (off & 0xFF) as u8;
            off >>= 8;
        }
    }

    fn read(&mut self, offset: u64, in_buffer: &mut [u8]) {
        let len = in_buffer.len();
        let iter = in_buffer.chunks_mut(0x10)
            .zip(0..(len / 0x10));

        for (chunk, i) in iter {
            self.update_counter(offset + (i * 0x10) as u64);
            let mut ctr = Aes128CtrDec::new(&self.key.into(), &self.counter.into());
            ctr.apply_keystream(chunk);
        };
    }
}

impl Finalize for CtrWrapper {
    fn finalize<'a, C: Context<'a>>(self, _: &mut C) {
        // don't particularly need to do anything
    }
}

fn dec_ctr_read(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let cell = cx.argument::<JsBox<RefCell<CtrWrapper>>>(0)?;
    let offset = cx.argument::<JsNumber>(1)?.value(&mut cx) as u64;
    let mut wrapper = cell.borrow_mut();

    let mut in_buffer = cx.argument::<JsArrayBuffer>(2)?;

    let in_buffer_slice = in_buffer.as_mut_slice(&mut cx);
    wrapper.read(offset, in_buffer_slice);

    Ok(cx.undefined())
}

fn create_dec_ctr(mut cx: FunctionContext) -> JsResult<JsBox<RefCell<CtrWrapper>>> {
    let mut key_buffer = [0; 0x10];
    key_buffer.copy_from_slice(cx.argument::<JsArrayBuffer>(0)?.as_slice(&cx));
    let mut counter = [0; 0x10];
    counter[..8].copy_from_slice(cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx));
    let mut offset = cx.argument::<JsNumber>(2)?.value(&mut cx) as u64;
    counter[8..].copy_from_slice(&(offset >> 4).to_be_bytes());
    let b = cx.boxed(RefCell::new(CtrWrapper {
        key: key_buffer.clone(),
        counter,
    }));
    Ok(b)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("decryptHeader", decrypt_nca_header)?;
    cx.export_function("decryptArea", decrypt_nca_area)?;
    cx.export_function("decryptXciHeader", decrypt_xci_enc_header)?;
    // cx.export_function("createDecXts", create_dec_xts)?;
    cx.export_function("createDecCtr", create_dec_ctr)?;
    cx.export_function("decCtrRead", dec_ctr_read)?;
    Ok(())
}
