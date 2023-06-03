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
    private sectorOffset = 0n;
    private currentSeek = 0n;

    constructor(
        private key: ArrayBufferLike,
        private base: Queryable,
    ) {}

    get size() {
        return this.base.size;
    }

    private updateIv(offset: bigint) {
        console.log("Offset-2 0x", offset.toString(16));
        offset >>= 4n;
        console.log("Offset-1 0x", offset.toString(16), this.ctr.buffer);
        for (let j = 0; j < 0x8; j++) {
            this.ctr[0x10-j-1] = Number(offset & 0xFFn);
            offset >>= 8n;
            console.log("Offset" + j + " 0x", offset.toString(16), this.ctr.buffer);
        }
    }

    private seek(offset: bigint) {
        this.currentSeek = offset & ~0xFn;
        this.sectorOffset = offset & 0xFn;
        this.updateIv(offset);
    }

    async read(offset: number, size: number): Promise<DataView> {
        this.seek(BigInt(offset));

        const encryptedData = await this.base.read(offset, size);

        if (this.sectorOffset === 0n) {
            const r = decBinds.decCtrRead(this.key, this.iv, sliceHelper(encryptedData));

            return new DataView(r);
        }

        const blockBuf = Buffer.alloc(0x10);

        throw new Error("Non-zero sectorOffset: " + this.sectorOffset);

        // this.updateCtr(BigInt(offset));
        // return new DataView(decBinds.decCtrRead(this.key, this.iv, sliceHelper(view)));
    }
}

export function createCtr(key: BufferOrView, queryable: Queryable) {
    if (key.byteLength !== 0x10)
        throw new Error(`'key' must be 0x10 bytes long, got ${key.byteLength}`);
    if (ArrayBuffer.isView(key))
        key = sliceHelper(key);

    return new CtrWrapper(key, queryable);
}

// import {readFileSync, writeFileSync} from "fs";

// const file = sliceHelper(readFileSync("./test.nca"));

// const ctr = createCtr(
//     Buffer.from("AC31F3DA4BD7C4A56116789B748CDF1F", "hex"),
//     {
//         read(offset: number, size: number): Promise<DataView> {
//             return new Promise((res) => res(new DataView(file, offset, size)))
//         },
//         size: 0
//     }
// );

// ctr.read(0xC00, file.byteLength - 0xC00).then(b => writeFileSync("nca.bin", b))

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
