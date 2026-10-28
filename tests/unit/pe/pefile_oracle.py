# Independent oracle for BEA's PE reader (S2 §22 "an optional cross-check against pefile", mirroring S2 lab E1).
# Run with the isolated interpreter: python -I pefile_oracle.py <path>. Prints one JSON summary.
# Ordinal-only imports are reported ordinal-only (pefile substitutes names from a built-in table; BEA never does).
import hashlib
import json
import sys

import pefile


def main(path):
    pe = pefile.PE(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    out = {
        "image_base": hex(base),
        "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
        "size_of_headers": pe.OPTIONAL_HEADER.SizeOfHeaders,
        "entry_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "time_date_stamp": pe.FILE_HEADER.TimeDateStamp,
        "sections": [s.Name.rstrip(b"\0").decode("utf8", "replace") for s in pe.sections],
    }
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append(
                {
                    "ordinal": s.ordinal,
                    "name": s.name.decode("latin1") if s.name else None,
                    "rva": None if s.forwarder else s.address,
                    "forwarder": s.forwarder.decode("latin1") if s.forwarder else None,
                }
            )
    out["exports"] = exports
    imports = []
    for attr, delay in (("DIRECTORY_ENTRY_IMPORT", False), ("DIRECTORY_ENTRY_DELAY_IMPORT", True)):
        for entry in getattr(pe, attr, []):
            for imp in entry.imports:
                by_ordinal = bool(getattr(imp, "import_by_ordinal", False))
                imports.append(
                    {
                        "dll": entry.dll.decode("latin1"),
                        "name": None if by_ordinal or not imp.name else imp.name.decode("latin1"),
                        "ordinal": imp.ordinal if by_ordinal else None,
                        "slot_rva": imp.address - base,
                        "delay": delay,
                    }
                )
    out["imports"] = imports
    pdata = getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])
    out["pdata_count"] = len(pdata)
    out["pdata_chained"] = sum(
        1 for e in pdata if getattr(e, "unwindinfo", None) is not None and (e.unwindinfo.Flags & 4)
    )
    slots = []
    other = 0
    for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for entry in block.entries:
            if entry.type == 10:
                slots.append(entry.rva)
            elif entry.type != 0:
                other += 1
    slots.sort()
    out["relocs_dir64"] = len(slots)
    out["relocs_sha256"] = hashlib.sha256(",".join(str(x) for x in slots).encode()).hexdigest()
    out["reloc_other"] = other
    codeview = None
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        e = d.entry
        if d.struct.Type == 2 and e is not None and hasattr(e, "Signature_Data1"):
            data6 = e.Signature_Data6
            guid = "%08X-%04X-%04X-%s-%s" % (
                e.Signature_Data1,
                e.Signature_Data2,
                e.Signature_Data3,
                bytes([e.Signature_Data4, e.Signature_Data5]).hex().upper(),
                bytes(data6).hex().upper(),
            )
            codeview = {"guid": guid, "age": e.Age, "pdb_path": e.PdbFileName.rstrip(b"\0").decode("utf8", "replace")}
            break
    out["codeview"] = codeview
    tls = []
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        callbacks = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        if callbacks:
            for i in range(256):
                va = pe.get_qword_at_rva(callbacks - base + i * 8)
                if not va:
                    break
                tls.append(va - base)
    out["tls_callbacks"] = tls
    print(json.dumps(out))


if __name__ == "__main__":
    main(sys.argv[1])
