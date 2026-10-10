#!/usr/bin/env python3
"""Read-only PNG/export checks. Standard library only. Visual QA stays separate."""
import argparse
import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path
from zipfile import ZipFile, BadZipFile

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def within(base, name):
    if not isinstance(name, str) or not name:
        raise ValueError("file name is missing")
    if Path(name).is_absolute():
        raise ValueError("use a path relative to the manifest")
    path = (base / name).resolve()
    if not path.is_relative_to(base.resolve()):
        raise ValueError("file path leaves the manifest directory")
    return path


def png_info(data):
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("not a PNG file")
    offset, first, ihdr, idat, ended = 8, True, None, [], False
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("truncated PNG chunk")
        size = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4:offset + 8]
        end = offset + 12 + size
        if end > len(data):
            raise ValueError("truncated PNG data")
        payload = data[offset + 8:offset + 8 + size]
        expected_crc = struct.unpack_from(">I", data, offset + 8 + size)[0]
        if zlib.crc32(kind + payload) & 0xffffffff != expected_crc:
            raise ValueError("PNG chunk CRC mismatch")
        if first and kind != b"IHDR":
            raise ValueError("IHDR must be the first chunk")
        first = False
        if kind == b"IHDR":
            if ihdr is not None or size != 13:
                raise ValueError("invalid IHDR")
            ihdr = struct.unpack(">IIBBBBB", payload)
        elif kind == b"IDAT":
            idat.append(payload)
        elif kind == b"IEND":
            if size != 0 or end != len(data):
                raise ValueError("invalid IEND or trailing data")
            ended = True
            break
        offset = end
    if not (ihdr and idat and ended):
        raise ValueError("PNG lacks IHDR, IDAT or IEND")
    width, height, depth, color, compression, filtering, interlace = ihdr
    allowed_depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
    if not width or not height or color not in allowed_depths or depth not in allowed_depths[color]:
        raise ValueError("invalid PNG dimensions or color depth")
    if compression != 0 or filtering != 0 or interlace not in (0, 1):
        raise ValueError("unsupported PNG header")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    scanlines = []
    if interlace == 0:
        scanlines.append((width, height))
    else:
        for x, y, dx, dy in [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]:
            pw, ph = max(0, (width - x + dx - 1) // dx), max(0, (height - y + dy - 1) // dy)
            if pw and ph:
                scanlines.append((pw, ph))
    expected_size = sum(((w * channels * depth + 7) // 8 + 1) * h for w, h in scanlines)
    if expected_size > 256 * 1024 * 1024:
        raise ValueError("PNG exceeds the 256 MiB scanline limit")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(b"".join(idat), expected_size + 1)
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or len(raw) != expected_size:
        raise ValueError("invalid or truncated PNG scanline stream")
    cursor = 0
    for w, h in scanlines:
        stride = (w * channels * depth + 7) // 8 + 1
        for _ in range(h):
            if raw[cursor] > 4:
                raise ValueError("invalid PNG scanline filter")
            cursor += stride
    return {"width": width, "height": height, "sha256": digest(data)}


def check_manifest(manifest_path):
    manifest_path = Path(manifest_path).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    base = manifest_path.parent
    result = {"technical_status": "pass", "files": [], "legacy_files": [], "zip": None,
              "user_approval": manifest.get("user_approval"), "visual_qa": manifest.get("visual_qa"),
              "scope": "technical checks only; approval and visual QA are not inferred"}
    errors, names, hashes = [], set(), {}
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("manifest must contain at least one file")
    for row in files:
        name = row.get("file")
        try:
            path = within(base, name)
            if name in names:
                raise ValueError("duplicate file in manifest")
            names.add(name)
            if path.suffix.lower() != ".png":
                raise ValueError("this checker supports PNG only")
            info = png_info(path.read_bytes())
            width, height = row.get("width"), row.get("height")
            if type(width) is not int or type(height) is not int or width < 1 or height < 1:
                raise ValueError("positive expected width and height are required")
            if (info["width"], info["height"]) != (width, height):
                raise ValueError(f"expected {width}x{height}; found {info['width']}x{info['height']}")
            if row.get("ratio"):
                a, b = [int(x) for x in row["ratio"].split(":")]
                if a < 1 or b < 1 or width * b != height * a:
                    raise ValueError("pixel dimensions do not match the requested ratio")
            if row.get("sha256") and row["sha256"] != info["sha256"]:
                raise ValueError("file SHA-256 mismatch")
            hashes[name] = info["sha256"]
            result["files"].append({"file": name, "status": "pass", **info})
        except (OSError, ValueError, TypeError, zlib.error, struct.error) as exc:
            errors.append({"file": name, "error": str(exc)})
    for row in manifest.get("legacy_files", []):
        name = row.get("file")
        try:
            if not row.get("sha256"):
                raise ValueError("legacy file requires its earlier SHA-256")
            sha = digest(within(base, name).read_bytes())
            if sha != row["sha256"]:
                raise ValueError("legacy file changed")
            result["legacy_files"].append({"file": name, "status": "unchanged", "sha256": sha})
        except (OSError, ValueError) as exc:
            errors.append({"file": name, "error": str(exc)})
    zip_name = manifest.get("zip")
    if zip_name:
        try:
            with ZipFile(within(base, zip_name)) as archive:
                members = [x.filename for x in archive.infolist() if not x.is_dir()]
                if len(members) != len(set(members)) or set(members) != names:
                    raise ValueError("ZIP must contain exactly the requested image names")
                bad = archive.testzip()
                if bad:
                    raise ValueError("ZIP integrity failure: " + bad)
                for name in members:
                    if name not in hashes or digest(archive.read(name)) != hashes[name]:
                        raise ValueError("ZIP image differs from checked file: " + name)
                result["zip"] = {"file": zip_name, "status": "pass", "members": members}
        except (OSError, ValueError, BadZipFile, RuntimeError) as exc:
            errors.append({"file": zip_name, "error": str(exc)})
    if errors:
        result["technical_status"] = "fail"
        result["errors"] = errors
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--report", type=Path, help="write a NEW technical report; refuses to overwrite")
    args = parser.parse_args()
    try:
        result = check_manifest(args.manifest)
        output = json.dumps(result, ensure_ascii=False, indent=2)
        if args.report:
            with args.report.open("x", encoding="utf-8") as handle:
                handle.write(output + "\n")
        print(output)
        return 0 if result["technical_status"] == "pass" else 1
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(json.dumps({"technical_status": "fail", "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
