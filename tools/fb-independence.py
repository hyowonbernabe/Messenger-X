#!/usr/bin/env python3
"""
Facebook independence patch for Messenger-X.

Renames the two duplicate <permission> declarations that Messenger (com.facebook.orca)
shares with the Facebook app (com.facebook.katana). When the patched Messenger is
re-signed with a non-Meta key, those shared declarations trigger
INSTALL_FAILED_DUPLICATE_PERMISSION while Facebook is installed. Renaming the prefix
com. -> app. makes them distinct names, so they no longer collide.

The rename is length-preserving ("com" and "app" are both 3 bytes), so the bytes inside
the binary AndroidManifest.xml string pool can be swapped in place without touching any
length/offset fields in the AXML structure.

The APK is then rebuilt with STORED entries aligned (resources.arsc -> 4 bytes,
*.so -> 16384 bytes so both 4KB- and 16KB-page devices are satisfied). The output is
UNSIGNED on purpose; the caller re-signs with apksigner.

Usage: fb-independence.py <input.apk> <output.apk>
Exit codes: 0 = ok, 2 = no permission strings found (nothing renamed -> treated as error)
"""
import sys
import zipfile

# (old, new) — both sides identical length so AXML offsets stay valid.
PAIRS = [
    (b"com.facebook.permission.prod.FB_APP_COMMUNICATION",
     b"app.facebook.permission.prod.FB_APP_COMMUNICATION"),
    (b"com.facebook.receiver.permission.ACCESS",
     b"app.facebook.receiver.permission.ACCESS"),
]

MANIFEST = "AndroidManifest.xml"
ALIGN_DEFAULT = 4
ALIGN_SO = 16384  # multiple of 4096, satisfies both 4KB and 16KB page devices


def is_signature_file(name: str) -> bool:
    """JAR (v1) signature files. Editing the manifest invalidates them; the
    patcher re-signs afterwards, so drop them to avoid stale-digest confusion."""
    u = name.upper()
    if not u.startswith("META-INF/"):
        return False
    return u == "META-INF/MANIFEST.MF" or u.endswith((".SF", ".RSA", ".DSA", ".EC"))


def utf16le(b: bytes) -> bytes:
    return b.decode("ascii").encode("utf-16-le")


def rename_in_manifest(data: bytes) -> tuple[bytes, int]:
    """Replace each permission string in both UTF-8 and UTF-16LE forms."""
    total = 0
    for old, new in PAIRS:
        assert len(old) == len(new), "rename must be length-preserving"
        n = data.count(old)
        if n:
            data = data.replace(old, new)
            total += n
        o16, n16 = utf16le(old), utf16le(new)
        m = data.count(o16)
        if m:
            data = data.replace(o16, n16)
            total += m
    return data, total


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: fb-independence.py <input.apk> <output.apk>", file=sys.stderr)
        return 1
    src, dst = sys.argv[1], sys.argv[2]

    renamed = 0
    with zipfile.ZipFile(src, "r") as zin, \
            zipfile.ZipFile(dst, "w") as zout:
        for zi in zin.infolist():
            if is_signature_file(zi.filename):
                continue
            data = zin.read(zi)
            if zi.filename == MANIFEST:
                data, renamed = rename_in_manifest(data)

            out = zipfile.ZipInfo(zi.filename, date_time=zi.date_time)
            out.compress_type = zi.compress_type
            out.external_attr = zi.external_attr
            out.internal_attr = zi.internal_attr
            out.create_system = zi.create_system
            # Drop the data-descriptor flag; we write sizes inline.
            out.flag_bits = zi.flag_bits & ~0x08

            if zi.compress_type == zipfile.ZIP_STORED and not zi.is_dir():
                align = ALIGN_SO if zi.filename.endswith(".so") else ALIGN_DEFAULT
                # Position where this local header will be written.
                pos = zout.fp.tell()
                header = 30 + len(out.filename.encode("utf-8"))
                pad = (align - ((pos + header) % align)) % align
                out.extra = b"\x00" * pad

            zout.writestr(out, data, zi.compress_type)

    if renamed == 0:
        print("ERROR: no Facebook permission strings found in manifest; "
              "nothing renamed. Aborting so the build doesn't ship a "
              "still-conflicting APK.", file=sys.stderr)
        return 2

    print(f"fb-independence: renamed {renamed} permission reference(s); "
          f"rebuilt aligned APK -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
