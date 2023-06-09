import bindings from "bindings";

type BufferOrView = ArrayBufferView | ArrayBufferLike;

function sliceHelper(view: ArrayBufferView, length?: number) {
    return view.buffer.slice(view.byteOffset, view.byteOffset + (length ?? view.byteLength));
}

const decBinds: {
    decryptHeader(key: ArrayBufferLike, header: ArrayBufferLike): ArrayBuffer,
    decryptArea(key: ArrayBufferLike, chunk: ArrayBufferLike): ArrayBuffer
    decryptXciHeader(key: ArrayBufferLike, iv: ArrayBufferLike, contents: ArrayBufferLike): ArrayBuffer;
    createDecCtr(key: ArrayBufferLike, counter: ArrayBufferLike, offset: number): unknown;
    decCtrRead(ext: unknown, offset: number, buffer: ArrayBufferLike, output: ArrayBufferLike): ArrayBuffer;
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
    constructor(
        private ext: unknown,
        private base: Queryable,
        private offset: number,
    ) {}

    get size() {
        return this.base.size;
    }

    async read(offset: number, size: number): Promise<DataView> {
        const start = (this.offset + offset) & ~0xF;
        const encryptedData = await this.base.read(start, size);
        const input = sliceHelper(encryptedData);
        const output = new ArrayBuffer(input.byteLength);
        decBinds.decCtrRead(this.ext, this.offset + offset, input, output);
        return new DataView(input);
    }
}

export function createCtr(key: BufferOrView, counter: BufferOrView, offset: number, queryable: Queryable) {
    if (key.byteLength !== 0x10)
        throw new Error(`'key' must be 0x10 bytes long, got ${key.byteLength}`);
    if (ArrayBuffer.isView(key))
        key = sliceHelper(key);
    if (counter.byteLength !== 0x8)
        throw new Error(`'counter' must be 0x10 bytes long, got ${counter.byteLength}`);
    if (ArrayBuffer.isView(counter))
        counter = sliceHelper(counter);

    return new CtrWrapper(decBinds.createDecCtr(key, counter, offset), queryable, offset);
}

export interface Queryable {
    read(offset: number, size: number): Promise<DataView>;

    size: number;
}
