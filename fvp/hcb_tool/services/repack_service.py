from __future__ import annotations

import json
from pathlib import Path

from hcb_tool.core.hashcheck import hash_file
from hcb_tool.services.verify_service import VerifyService


class RepackService:
    """Raw-first repacker.

    It starts from original bytes and applies validated patches. With no patches,
    output is an exact byte copy. Unknown fields are not serialized, only preserved.
    """

    def run(self, ir: dict, output_path: str | Path, patches: list[dict] | None = None, verify: bool = True) -> dict:
        output_path = Path(output_path)
        source = Path(ir["source_path"])
        data = bytearray(source.read_bytes())
        patch_report: list[dict] = []
        for p in patches or []:
            off = int(p["offset"])
            length = int(p["length"])
            patch_bytes = bytes.fromhex(p["data_hex"])
            row = {"idx": p.get("idx"), "offset": off, "offset_hex": f"0x{off:08X}", "length": length, "status": "OK", "reason": ""}
            if len(patch_bytes) != length:
                row.update(status="FAIL", reason="patch length mismatch")
                patch_report.append(row)
                continue
            if off < 0 or off + length > len(data):
                row.update(status="FAIL", reason="patch outside file")
                patch_report.append(row)
                continue
            data[off:off + length] = patch_bytes
            patch_report.append(row)
        if any(r["status"] == "FAIL" for r in patch_report):
            raise ValueError("one or more patches failed validation: " + json.dumps(patch_report, ensure_ascii=False))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(bytes(data))
        result = {"output_path": str(output_path), "patches": patch_report, "hash": hash_file(output_path)}
        if verify:
            v = VerifyService().run(source, output_path, output_path.parent)
            # Keep canonical report name for repack, not only verify.
            (output_path.parent / "repack_report.txt").write_text(v.report_text, encoding="utf-8")
            result["verify"] = {"original": v.original, "rebuilt": v.rebuilt, "result": v.result}
        return result
