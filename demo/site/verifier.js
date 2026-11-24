// Loads verifier.wasm (plain C ABI, no bindings generator) and exposes a tiny API. Works in browsers and Node ≥ 20.
export const ERRORS = {
  "-1": "proof bytes do not parse",
  "-2": "header length",
  "-3": "header domain tag",
  "-4": "inclusion path does not reach the header's batch root",
  "-5": "unknown validator index",
  "-6": "duplicate signer",
  "-7": "fewer signatures than the quorum",
  "-8": "a validator signature is invalid",
  "-9": "weak validator key",
  "-10": "no validator set loaded",
  "-11": "validator set length",
};

export function hexToBytes(h) {
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(2 * i, 2), 16);
  return b;
}

export async function loadVerifier(wasmBytes) {
  let memory;
  const env = {
    random_fill(ptr, len) {
      globalThis.crypto.getRandomValues(new Uint8Array(memory.buffer, ptr, len));
    },
  };
  const { instance } = await WebAssembly.instantiate(wasmBytes, { env });
  const x = instance.exports;
  memory = x.memory;
  const call = (fn, bytes) => {
    const p = x.alloc(bytes.length);
    new Uint8Array(memory.buffer, p, bytes.length).set(bytes);
    const r = Number(fn(p, bytes.length));
    x.dealloc(p, bytes.length);
    return r;
  };
  return {
    setValidators(hexKeys) {
      const all = new Uint8Array(32 * hexKeys.length);
      hexKeys.forEach((k, i) => all.set(hexToBytes(k), 32 * i));
      return call(x.set_validators, all);
    },
    /** Returns the proven height (≥ 0) or a negative error code. */
    verify(bytes) {
      return call(x.verify, bytes);
    },
  };
}
