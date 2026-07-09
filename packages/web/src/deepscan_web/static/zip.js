/* Minimal store-only (uncompressed) ZIP writer - vanilla JS, no dependency.
 * Produces a valid .zip that the server reads with Python's zipfile. We always
 * upload a zip, so a folder picked/dropped in the browser is packed here.
 */
"use strict";

const DEEPSCAN_ZIP_CRC = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    c = DEEPSCAN_ZIP_CRC[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function u16(value) {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, value & 0xffff, true);
  return b;
}

function u32(value) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, value >>> 0, true);
  return b;
}

function concat(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

/* entries: [{ name: string, bytes: Uint8Array }] -> Blob (application/zip) */
function buildStoreZip(entries) {
  const enc = new TextEncoder();
  const FLAG_UTF8 = 0x0800;
  const chunks = [];
  const central = [];
  let offset = 0;

  for (const entry of entries) {
    const name = enc.encode(entry.name);
    const data = entry.bytes;
    const crc = crc32(data);
    const lfh = concat([
      u32(0x04034b50), u16(20), u16(FLAG_UTF8), u16(0), u16(0), u16(0),
      u32(crc), u32(data.length), u32(data.length), u16(name.length), u16(0), name,
    ]);
    chunks.push(lfh, data);
    central.push({ name, crc, size: data.length, offset });
    offset += lfh.length + data.length;
  }

  const cdStart = offset;
  for (const c of central) {
    const cdh = concat([
      u32(0x02014b50), u16(20), u16(20), u16(FLAG_UTF8), u16(0), u16(0), u16(0),
      u32(c.crc), u32(c.size), u32(c.size),
      u16(c.name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(c.offset),
      c.name,
    ]);
    chunks.push(cdh);
    offset += cdh.length;
  }
  const cdSize = offset - cdStart;
  chunks.push(concat([
    u32(0x06054b50), u16(0), u16(0), u16(central.length), u16(central.length),
    u32(cdSize), u32(cdStart), u16(0),
  ]));

  return new Blob(chunks, { type: "application/zip" });
}

window.DeepScanZip = { buildStoreZip, crc32 };
