import bindings from "bindings";

type BufferOrView = ArrayBufferView | ArrayBufferLike;

function sliceHelper(view: ArrayBufferView, length?: number) {
    return view.buffer.slice(view.byteOffset, view.byteOffset + (length ?? view.byteLength));
}

const decBinds: {
    decryptHeader(key: ArrayBufferLike, header: ArrayBufferLike): ArrayBuffer,
    decryptArea(key: ArrayBufferLike, chunk: ArrayBufferLike): ArrayBuffer
    decryptXciHeader(key: ArrayBufferLike, iv: ArrayBufferLike, contents: ArrayBufferLike): ArrayBuffer;
    createDecCtr(key: ArrayBufferLike): {};
    decCtrRead(key: ArrayBufferLike, iv: ArrayBufferLike, buffer: ArrayBufferLike): ArrayBuffer;
} = bindings({});

export function decryptNcaHeader(key: BufferOrView, header: BufferOrView): Uint8Array {
    if (key.byteLength !== 0x20)
        throw new Error(`'key' must be 0x20 bytes long, got ${key.byteLength}`);
    if (ArrayBuffer.isView(key))
        key = sliceHelper(key);
    if (header.byteLength < 0xC00)
        throw new Error("'header' must be at least 0xC00 bytes long, got " + header.byteLength)
    if (ArrayBuffer.isView(header))
        header = sliceHelper(header, 0xC00);

    return new Uint8Array(decBinds.decryptHeader(key, header));
}

export function decryptNcaKeyArea(key: BufferOrView, area: BufferOrView[]) {
    if (key.byteLength !== 0x10)
        throw new Error(`'key' must be 0x10 bytes long, got ${key.byteLength}`);
    if (ArrayBuffer.isView(key))
        key = sliceHelper(key);

    const k = key;

    return area.map((chunk) => {
        if (chunk.byteLength !== 0x10)
            throw new Error("element of 'area' must of 0x10 bytes long, got " + chunk.byteLength)
        if (ArrayBuffer.isView(chunk))
            chunk = sliceHelper(chunk);
        return new Uint8Array(decBinds.decryptArea(k, chunk));
    })
}

export function decryptXciEncryptedHeader(key: BufferOrView, iv: BufferOrView, contents: BufferOrView) {
    if (key.byteLength !== 0x10)
        throw new Error(`'key' must be 0x10 bytes long, got ${key.byteLength}`);
    if (ArrayBuffer.isView(key))
        key = sliceHelper(key);
    if (iv.byteLength !== 0x10)
        throw new Error(`'iv' must be 0x10 bytes long, got ${iv.byteLength}`);
    if (ArrayBuffer.isView(iv))
        iv = sliceHelper(iv);
    if (contents.byteLength !== 0x70)
        throw new Error(`'contents' must be 0x70 bytes long, got ${contents.byteLength}`);
    if (ArrayBuffer.isView(contents))
        contents = sliceHelper(contents);

    return new Uint8Array(decBinds.decryptXciHeader(key, iv, contents));
}

export function createXts(key: BufferOrView) {
    if (key.byteLength !== 0x20)
        throw new Error(`'key' must be 0x20 bytes long, got ${key.byteLength}`);
    if (ArrayBuffer.isView(key))
        key = sliceHelper(key);

}

class CtrWrapper implements Queryable {
    private iv = new ArrayBuffer(0x10);
    private ctr = new Uint8Array(this.iv);
    constructor(
        private key: ArrayBufferLike,
        private base: Queryable,
    ) {}

    get size() {
        return this.base.size;
    }

    updateIv(offset: bigint) {
        offset >>= 4n;
        for (let j = 0; j < 0x8; j++) {
            this.ctr[0x10-j-1] = Number(offset & 0xFFn);
            offset >>= 8n;
        }
    }

    async read(offset: number, size: number): Promise<DataView> {
        const view = await this.base.read(offset, size);
        this.updateIv(BigInt(offset));
        const s = decBinds.decCtrRead(this.key, this.iv, sliceHelper(view));
        console.log(`s${s}`);
        return new DataView(s);
    }
}

export function createCtr(key: BufferOrView, queryable: Queryable) {
    if (key.byteLength !== 0x10)
        throw new Error(`'key' must be 0x10 bytes long, got ${key.byteLength}`);
    if (ArrayBuffer.isView(key))
        key = sliceHelper(key);

    return new CtrWrapper(key, queryable);
}

import {readFileSync, writeFileSync} from "fs";

const file = sliceHelper(readFileSync("./encryptedContents"));

const ctr = createCtr(
    Buffer.from("ac31f3da4bd7c4a56116789b748cdf1f", "hex"),
    {
        read(offset: number, size: number): Promise<DataView> {
            return new Promise((res) => res(new DataView(file, offset, size)))
        },
        size: 0
    }
);


console.log(
    ctr.read(0, file.byteLength).then(b => writeFileSync("nca.bin", b))
);

export interface Queryable {
    read(offset: number, size: number): Promise<DataView>;

    size: number;
}
// class CtrContentArchiveEntryDecryptionContext implements Queryable {
//     constructor(
//         private queryable: Queryable,
//         key: BufferOrView,
//     ) {
//     }
//
//     read(offset: number, size: number): Promise<DataView> | DataView {
//
//     }
//
//     size: number = 0;
// }
