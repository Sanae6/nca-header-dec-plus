import bindings from "bindings";

type BufferOrView = ArrayBufferView | ArrayBufferLike;

function sliceHelper(view: ArrayBufferView, length?: number) {
    return view.buffer.slice(view.byteOffset, view.byteOffset + (length ?? view.byteLength));
}

const decBinds: {
    decryptHeader(key: ArrayBufferLike, header: ArrayBufferLike): ArrayBuffer,
    decryptArea(key: ArrayBufferLike, chunk: ArrayBufferLike): ArrayBuffer
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
