/**
 * Field codecs (S5 §7.2): the target stores `encode(logical)` in a field of width w bytes; BEA writes encoded
 * inputs and decodes out-buffer fields. The key is the multiplier/addend/mask that maps a LOGICAL value to its
 * STORED value, applied to the field's bit pattern (floats included). Pure BigInt arithmetic mod 2^(8w).
 */
export type CodecKind = "xor" | "add" | "mul";
export type CodecWidth = 1 | 2 | 4 | 8;

const modulus = (width: CodecWidth): bigint => 1n << BigInt(width * 8);
const mod = (value: bigint, width: CodecWidth): bigint => {
  const m = modulus(width);
  return ((value % m) + m) % m;
};

/**
 * Inverse of an odd key mod 2^(8w) by Newton iteration x <- x(2 - kx): each round doubles the correct low bits,
 * starting from x = k (correct to 3 bits for odd k), so six rounds cover 192 > 64 bits.
 */
export const mulInverse = (key: bigint, width: CodecWidth): bigint => {
  const k = mod(key, width);
  if ((k & 1n) === 0n) throw new RangeError("multiplicative codec keys must be odd to be invertible mod 2^w");
  let x = k;
  for (let round = 0; round < 6; round++) x = mod(x * (2n - k * x), width);
  return x;
};

/** Caller-facing key check; null when the key is usable. */
export const codecKeyProblem = (kind: CodecKind, key: bigint, width: CodecWidth): string | null => {
  if (key < 0n || key >= modulus(width)) return `codec_key does not fit the field's ${String(width * 8)}-bit width.`;
  if (kind === "mul" && (key & 1n) === 0n) return "Multiplicative codec keys must be odd to be invertible mod 2^w.";
  return null;
};

export const codecEncode = (kind: CodecKind, key: bigint, logical: bigint, width: CodecWidth): bigint => {
  const v = mod(logical, width);
  switch (kind) {
    case "xor":
      return mod(v ^ key, width);
    case "add":
      return mod(v + key, width);
    case "mul":
      return mod(v * key, width);
  }
};

export const codecDecode = (kind: CodecKind, key: bigint, stored: bigint, width: CodecWidth): bigint => {
  const s = mod(stored, width);
  switch (kind) {
    case "xor":
      return mod(s ^ key, width);
    case "add":
      return mod(s - key, width);
    case "mul":
      return mod(s * mulInverse(key, width), width);
  }
};
