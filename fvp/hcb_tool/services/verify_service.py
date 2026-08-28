from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from hcb_tool.core.hashcheck import hash_file
from hcb_tool.core.hexdiff import first_diff


@dataclass
class VerifyResult:
    original: dict
    rebuilt: dict
    result: dict
    report_text: str


class VerifyService:
    def run(self, original_path: str | Path, rebuilt_path: str | Path, output_dir: str | Path | None = None) -> VerifyResult:
        original_path = Path(original_path)
        rebuilt_path = Path(rebuilt_path)
        original_data = original_path.read_bytes()
        rebuilt_data = rebuilt_path.read_bytes()
        original = hash_file(original_path)
        rebuilt = hash_file(rebuilt_path)
        diff = first_diff(original_data, rebuilt_data)
        result = {
            "size_equal": original["size"] == rebuilt["size"],
            "bytes_equal": diff.equal,
            "sha256_equal": original["sha256"] == rebuilt["sha256"],
            "status": "PASS" if diff.equal and original["sha256"] == rebuilt["sha256"] else "FAIL",
            "diff": diff.to_dict(),
        }
        report = self._format_report(original, rebuilt, result)
        if output_dir is not None:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / "verify_report.txt").write_text(report, encoding="utf-8")
            (out / "verify_report.json").write_text(json.dumps({"original": original, "rebuilt": rebuilt, "result": result}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return VerifyResult(original, rebuilt, result, report)

    def _format_report(self, original: dict, rebuilt: dict, result: dict) -> str:
        identical_cn = "与原文件字节完全一致，SHA256/MD5/CRC32 一样" if result.get("status") == "PASS" else "与原文件不一致，见差异信息"
        lines = [
            "[SUMMARY]",
            f"原地回封校验 = {identical_cn}",
            "",
            "[ORIGINAL]",
            f"path = {original['path']}",
            f"size = {original['size']}",
            f"crc32 = {original['crc32']}",
            f"md5 = {original['md5']}",
            f"sha256 = {original['sha256']}",
            "",
            "[REPACKED]",
            f"path = {rebuilt['path']}",
            f"size = {rebuilt['size']}",
            f"crc32 = {rebuilt['crc32']}",
            f"md5 = {rebuilt['md5']}",
            f"sha256 = {rebuilt['sha256']}",
            "",
            "[RESULT]",
            f"size_equal = {str(result['size_equal']).lower()}",
            f"bytes_equal = {str(result['bytes_equal']).lower()}",
            f"sha256_equal = {str(result['sha256_equal']).lower()}",
            f"status = {result['status']}",
        ]
        diff = result.get("diff", {})
        if result["status"] != "PASS":
            lines.extend([
                f"reason = hash mismatch" if not result["sha256_equal"] else "reason = byte mismatch",
                f"first_diff_offset = {('0x%08X' % diff['first_diff_offset']) if diff.get('first_diff_offset') is not None else '<size-only>'}",
                f"original_bytes = {diff.get('original_bytes', '')}",
                f"rebuilt_bytes  = {diff.get('rebuilt_bytes', '')}",
                "possible_causes = " + " / ".join(diff.get("possible_causes") or []),
            ])
        return "\n".join(lines) + "\n"
