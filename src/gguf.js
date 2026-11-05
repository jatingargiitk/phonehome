// Minimal GGUF metadata reader: returns the key/value header (strings,
// numbers, bools; arrays are summarised) without touching tensor data.
import fs from 'node:fs';

const T = { U8: 0, I8: 1, U16: 2, I16: 3, U32: 4, I32: 5, F32: 6, BOOL: 7, STRING: 8, ARRAY: 9, U64: 10, I64: 11, F64: 12 };
const FIXED = { 0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8 };

export function isGguf(file) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const b = Buffer.alloc(4);
    return fs.readSync(fd, b, 0, 4, 0) === 4 && b.toString('latin1') === 'GGUF';
  } catch {
    return false;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

class Reader {
  constructor(file, limit) {
    this.fd = fs.openSync(file, 'r');
    this.pos = 0;
    this.limit = limit;
  }
  bytes(n) {
    if (n > this.limit) throw new Error('GGUF field too large');
    const b = Buffer.alloc(n);
    const got = fs.readSync(this.fd, b, 0, n, this.pos);
    if (got !== n) throw new Error('truncated GGUF header');
    this.pos += n;
    return b;
  }
  skip(n) {
    this.pos += n;
  }
  u32() { return this.bytes(4).readUInt32LE(0); }
  u64() { return Number(this.bytes(8).readBigUInt64LE(0)); }
  str() { return this.bytes(this.u64()).toString('utf8'); }
  close() { fs.closeSync(this.fd); }
}

function readValue(r, type, keepStrings) {
  switch (type) {
    case T.STRING: return r.str();
    case T.BOOL: return r.bytes(1)[0] !== 0;
    case T.U8: return r.bytes(1).readUInt8(0);
    case T.I8: return r.bytes(1).readInt8(0);
    case T.U16: return r.bytes(2).readUInt16LE(0);
    case T.I16: return r.bytes(2).readInt16LE(0);
    case T.U32: return r.bytes(4).readUInt32LE(0);
    case T.I32: return r.bytes(4).readInt32LE(0);
    case T.F32: return r.bytes(4).readFloatLE(0);
    case T.U64: return Number(r.bytes(8).readBigUInt64LE(0));
    case T.I64: return Number(r.bytes(8).readBigInt64LE(0));
    case T.F64: return r.bytes(8).readDoubleLE(0);
    case T.ARRAY: {
      const itemType = r.u32();
      const n = r.u64();
      if (FIXED[itemType]) {
        r.skip(FIXED[itemType] * n);
        return { array: n };
      }
      if (itemType === T.STRING) {
        // token lists can be huge; skip without keeping them
        for (let i = 0; i < n; i++) r.skip(r.u64());
        return { array: n };
      }
      const items = [];
      for (let i = 0; i < n; i++) items.push(readValue(r, itemType, keepStrings));
      return items;
    }
    default:
      throw new Error(`unknown GGUF value type ${type}`);
  }
}

/** { version, metadata: { key: value } } */
export function readGgufMetadata(file, { maxField = 64 * 1024 * 1024 } = {}) {
  const r = new Reader(file, maxField);
  try {
    if (r.bytes(4).toString('latin1') !== 'GGUF') throw new Error('not a GGUF file');
    const version = r.u32();
    if (version < 2) throw new Error(`unsupported GGUF version ${version}`);
    r.u64(); // tensor count
    const kvCount = r.u64();
    const metadata = {};
    for (let i = 0; i < kvCount; i++) {
      const key = r.str();
      const type = r.u32();
      metadata[key] = readValue(r, type);
    }
    return { version, metadata };
  } finally {
    r.close();
  }
}

/** Build a small GGUF file (header only) — used by tests and fixtures. */
export function writeGguf(file, metadata) {
  const parts = [];
  const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); parts.push(b); };
  const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); parts.push(b); };
  const str = (s) => { const b = Buffer.from(s, 'utf8'); u64(b.length); parts.push(b); };
  parts.push(Buffer.from('GGUF', 'latin1'));
  u32(3);
  u64(0);
  u64(Object.keys(metadata).length);
  for (const [k, v] of Object.entries(metadata)) {
    str(k);
    if (typeof v === 'string') { u32(T.STRING); str(v); }
    else if (typeof v === 'boolean') { u32(T.BOOL); parts.push(Buffer.from([v ? 1 : 0])); }
    else if (Array.isArray(v)) { u32(T.ARRAY); u32(T.STRING); u64(v.length); v.forEach(str); }
    else { u32(T.U32); u32(v); }
  }
  fs.writeFileSync(file, Buffer.concat(parts));
}
