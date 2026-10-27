import { deflateRawSync, gzipSync } from 'node:zlib';

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

export function crc32(buffer) {
  let value = 0xffffffff;
  for (const byte of buffer) {
    value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

/**
 * Minimal ZIP writer used only by tests.
 * entries: { name, data, method, flags, externalAttributes, crc, uncompressedSize }
 */
export function buildZip(entries) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data || '');
    const method = entry.method ?? 8;
    const compressed = method === 8 ? deflateRawSync(data) : data;
    const crc = entry.crc ?? crc32(data);
    const uncompressedSize = entry.uncompressedSize ?? data.length;
    const flags = entry.flags ?? 0;
    const externalAttributes = (entry.externalAttributes ?? (0o100644 << 16)) >>> 0;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(uncompressedSize, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(0x031e, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(uncompressedSize, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(externalAttributes, 38);
    central.writeUInt32LE(offset, 42);

    localParts.push(local, name, compressed);
    centralParts.push(central, name);
    offset += local.length + name.length + compressed.length;
  }

  const centralDirectory = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirectory.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDirectory, eocd]);
}

function octal(value, length) {
  return value.toString(8).padStart(length - 1, '0') + '\0';
}

/**
 * Minimal USTAR writer used only by tests.
 * entries: { name, data, type, size }
 */
export function buildTar(entries) {
  const blocks = [];
  for (const entry of entries) {
    const data = entry.type && entry.type !== '0' ? Buffer.alloc(0) : Buffer.from(entry.data || '');
    const header = Buffer.alloc(512, 0);
    header.write(entry.name, 0, 100, 'utf8');
    header.write(octal(entry.type === '5' ? 0o755 : 0o644, 8), 100, 8, 'latin1');
    header.write(octal(0, 8), 108, 8, 'latin1');
    header.write(octal(0, 8), 116, 8, 'latin1');
    header.write(octal(entry.size ?? data.length, 12), 124, 12, 'latin1');
    header.write(octal(0, 12), 136, 12, 'latin1');
    header.fill(0x20, 148, 156);
    header.write(entry.type ?? '0', 156, 1, 'latin1');
    header.write('ustar\0', 257, 6, 'latin1');
    header.write('00', 263, 2, 'latin1');
    header.write('root', 265, 32, 'latin1');
    header.write('root', 297, 32, 'latin1');
    let checksum = 0;
    for (const byte of header) checksum += byte;
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'latin1');
    blocks.push(header);
    if (data.length > 0) {
      blocks.push(data);
      const padding = (512 - (data.length % 512)) % 512;
      if (padding > 0) blocks.push(Buffer.alloc(padding));
    }
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

export function buildTarGz(entries) {
  return gzipSync(buildTar(entries));
}
