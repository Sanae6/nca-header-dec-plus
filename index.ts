import bindings from "bindings";

type BufferOrView = ArrayBufferView | ArrayBufferLike;

function sliceHelper(view: ArrayBufferView, length?: number) {
    return view.buffer.slice(view.byteOffset, view.byteOffset + (length ?? view.byteLength));
}

const decBinds: { decrypt(key: ArrayBufferLike, header: ArrayBufferLike): ArrayBuffer } = bindings({});

export function decryptNcaHeader(key: BufferOrView, header: BufferOrView): Uint8Array {
    if (key.byteLength !== 0x20)
        throw new Error(`'key' must be 0x20 bytes long, got ${key.byteLength}`);
    if (ArrayBuffer.isView(key))
        key = sliceHelper(key);
    if (header.byteLength < 0xC00)
        throw new Error("'header' must be at least 0xC00 bytes long, got " + header.byteLength)
    if (ArrayBuffer.isView(header))
        header = sliceHelper(header, 0xC00);

    return new Uint8Array(decBinds.decrypt(key, header));
}
