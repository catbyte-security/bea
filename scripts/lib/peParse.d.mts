// Types for scripts/lib/peParse.mjs.

export interface PeSection {
  readonly name: string;
  readonly rva: number;
  readonly virtualSize: number;
  readonly rawOffset: number;
  readonly rawSize: number;
  readonly characteristics: number;
}

export interface PeExport {
  readonly name: string | null;
  readonly ordinal: number;
  readonly rva: number | null;
  readonly forwarder: string | null;
}

export interface PeImage {
  readonly machine: string;
  readonly format: "PE32" | "PE32+";
  readonly characteristics: number;
  readonly isDll: boolean;
  readonly imageBase: string;
  readonly entryRva: number;
  readonly sizeOfImage: number;
  readonly sizeOfHeaders: number;
  readonly subsystem: number;
  readonly dllCharacteristics: number;
  readonly dynamicBase: boolean;
  readonly highEntropyVa: boolean;
  readonly nxCompat: boolean;
  readonly sections: readonly PeSection[];
  readonly exports: readonly PeExport[];
  readonly imports: readonly string[];
  readonly pdata: readonly { readonly begin: number; readonly end: number; readonly unwind: number }[];
  readonly readRva: (rva: number, size: number) => Buffer;
}

export declare class PeFormatError extends Error {}
export declare function parsePe(buffer: Buffer): PeImage;
export declare const exportRvas: (pe: PeImage) => Record<string, number>;
export declare function exportedFunctions(pe: PeImage): Record<string, { readonly rva: number; readonly size: number }>;
