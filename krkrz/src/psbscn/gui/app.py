"""拖拽式图形界面（PySide6）。

只有三个按钮：反汇编、提取文本、回封，加上两个编码下拉框。拖入根目录即可，工具
自己按签名递归找出所有 PSB 剧本文件。

UI 线程不解析二进制；所有工作都在工作线程的 JobRunner/StageService 中完成。
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (QApplication, QComboBox, QFileDialog,
                               QCheckBox, QHBoxLayout, QLabel,
                               QMainWindow, QMessageBox,
                               QPlainTextEdit, QProgressBar, QPushButton,
                               QVBoxLayout, QWidget)

from ..services import encodings
from ..services.jobs import JobRunner
from ..services.stages import StageService
from ..services.toolchain import TOOL_VERSION
from ..services.workspace import Workspace, find_scenario_files
from .worker import Event, StageWorker

HINT = ("将存放 .scn 的文件夹拖到这里\n"
        "（也可以拖单个文件，或点击此处浏览）")


class DropArea(QLabel):
    """整块可拖放、可点击的输入区。"""

    def __init__(self, on_drop: Callable[[list[str]], None],
                 on_click: Callable[[], None]) -> None:
        super().__init__()
        self._on_drop = on_drop
        self._on_click = on_click
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumHeight(120)
        self.setWordWrap(True)
        self.setText(HINT)
        self.setStyleSheet(
            "QLabel { border: 2px dashed #888; border-radius: 10px;"
            " color: #444; font-size: 14px; padding: 12px; }")

    def dragEnterEvent(self, event) -> None:  # noqa: N802 —— Qt 命名风格
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:  # noqa: N802
        paths = [u.toLocalFile() for u in event.mimeData().urls()
                 if u.toLocalFile()]
        if paths:
            self._on_drop(paths)
            event.acceptProposedAction()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        self._on_click()


class MainWindow(QMainWindow):
    """单窗口三按钮外壳。"""

    def __init__(self) -> None:
        super().__init__()
        self.inputs: list[str] = []
        self.files: list[Path] = []
        self.worker = StageWorker()

        self.setWindowTitle(f"PSB/SCN 反汇编与回封工具 {TOOL_VERSION}")
        self.resize(840, 600)
        self._build()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._pump)
        self.timer.start(80)

    def _build(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setSpacing(10)

        self.drop = DropArea(self._set_inputs, self._browse)
        layout.addWidget(self.drop)

        self.status = QLabel("尚未选择输入")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        enc = QHBoxLayout()
        enc.addWidget(QLabel("源编码："))
        self.src_enc = QComboBox()
        self.src_enc.setEditable(True)
        self.src_enc.addItems(encodings.SOURCE_ENCODINGS)
        self.src_enc.setToolTip("原文用什么编码解码。本作实测是 utf-8")
        enc.addWidget(self.src_enc)
        enc.addSpacing(16)
        enc.addWidget(QLabel("目标编码："))
        self.dst_enc = QComboBox()
        self.dst_enc.setEditable(True)
        self.dst_enc.addItems(encodings.TARGET_ENCODINGS)
        self.dst_enc.setToolTip(
            "译文写回时用什么编码。改成更窄的编码会让无法表示的字符被拒绝，"
            "而不是被静默替换")
        enc.addWidget(self.dst_enc)
        enc.addStretch(1)
        layout.addLayout(enc)

        # 两个可选项，只影响①。默认与不勾时的行为完全一致。
        opts = QHBoxLayout()
        self.chk_no_asm = QCheckBox("跳过 ASM 清单（更快、省几百 MB）")
        self.chk_no_asm.setToolTip(
            "只想抽文本时勾上：不生成 ASM 审计清单，本作可省约 570 MB 与两成时间；\n"
            "零编辑往返自检与覆盖证书照常执行")
        opts.addWidget(self.chk_no_asm)
        self.chk_with_ir = QCheckBox("同时导出 IR")
        self.chk_with_ir.setToolTip(
            "额外写一份合库 IR 到 _psbscn/ir/：\n"
            "manifest.jsonl 记录每个源在各流中的行区间，可直接定位单个源的记录")
        opts.addWidget(self.chk_with_ir)
        opts.addStretch(1)
        layout.addLayout(opts)

        row = QHBoxLayout()
        self.btn_disasm = QPushButton("① 反汇编")
        self.btn_disasm.setToolTip(
            "全量反汇编：输出一份合并的 反汇编.asm.txt，"
            "并对每个文件做零编辑往返自检")
        self.btn_disasm.clicked.connect(self._run_disasm)
        self.btn_text = QPushButton("② 提取文本")
        self.btn_text.setToolTip(
            "逐文件导出译文到 texts/，目录结构与源目录一致；直接编辑这些 .dsat.txt")
        self.btn_text.clicked.connect(self._run_extract)
        self.btn_repack = QPushButton("③ 回封")
        self.btn_repack.setToolTip(
            "读 texts/ 里的译文，逐文件写到 rebuilt/ 并验证")
        self.btn_repack.clicked.connect(self._run_repack)
        for btn in (self.btn_disasm, self.btn_text, self.btn_repack):
            btn.setMinimumHeight(46)
            row.addWidget(btn)
        layout.addLayout(row)

        row2 = QHBoxLayout()
        self.btn_open = QPushButton("打开输出目录")
        self.btn_open.clicked.connect(self._open_output)
        self.btn_cancel = QPushButton("取消")
        self.btn_cancel.clicked.connect(self._cancel)
        self.btn_cancel.setEnabled(False)
        row2.addWidget(self.btn_open)
        row2.addWidget(self.btn_cancel)
        row2.addStretch(1)
        layout.addLayout(row2)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        layout.addWidget(self.progress)

        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.log = QPlainTextEdit(readOnly=True)
        self.log.setFont(mono)
        layout.addWidget(self.log, 1)

        self.setCentralWidget(root)

    # -- 输入 -----------------------------------------------------------
    def _browse(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "选择存放 .scn 的文件夹")
        if folder:
            self._set_inputs([folder])

    def _set_inputs(self, paths: list[str]) -> None:
        self.inputs = paths
        self.files = find_scenario_files(paths)
        if not self.files:
            self.status.setText(
                f"在所选位置未找到 PSB 剧本文件（已按 PSB\\0 签名递归检查）：\n"
                + "\n".join(paths[:3]))
            self._log("未找到任何 PSB 文件")
            return
        ws = Workspace.beside(paths[0])
        self.status.setText(
            f"已找到 {len(self.files)} 个 .scn 文件\n"
            f"输入：{paths[0]}\n输出：{ws.root}")
        self._log(f"已找到 {len(self.files)} 个文件，输出目录 {ws.root}")

    def _output_dir(self) -> Path | None:
        return Workspace.beside(self.inputs[0]).root if self.inputs else None

    def _open_output(self) -> None:
        out = self._output_dir()
        if out is None:
            QMessageBox.information(self, "提示", "请先选择输入。")
            return
        if not out.exists():
            QMessageBox.information(self, "提示",
                                    f"输出目录还不存在：\n{out}\n"
                                    "请先运行任意一个操作。")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(out)))

    # -- 操作 -----------------------------------------------------------
    def _ready(self) -> bool:
        if self.worker.busy:
            QMessageBox.information(self, "忙碌中", "已有任务正在运行。")
            return False
        if not self.files:
            QMessageBox.warning(self, "没有输入",
                                "请先拖入存放 .scn 的文件夹。")
            return False
        return True

    def _start(self, label: str, method: str) -> None:
        if not self._ready():
            return
        try:
            src = encodings.check(self.src_enc.currentText().strip())
            dst = encodings.check(self.dst_enc.currentText().strip())
        except ValueError as exc:
            QMessageBox.warning(self, "编码无效", str(exc))
            return
        inputs = list(self.inputs)

        extra: dict[str, bool] = {}
        if method == "disassemble":
            extra = {"write_asm": not self.chk_no_asm.isChecked(),
                     "write_ir": self.chk_with_ir.isChecked()}

        def job(svc: StageService, cancelled):
            runner = JobRunner(svc)
            return getattr(runner, method)(
                inputs, encoding=src, target_encoding=dst,
                cancel=cancelled, **extra).as_stage_result()

        if self.worker.submit(label, job):
            self.btn_cancel.setEnabled(True)
            self.progress.setValue(0)
            self._log(f"开始{label}：{len(self.files)} 个文件"
                      f"（源编码 {src} → 目标编码 {dst}）")

    def _run_disasm(self) -> None:
        self._start("反汇编", "disassemble")

    def _run_extract(self) -> None:
        self._start("提取文本", "extract_text")

    def _run_repack(self) -> None:
        self._start("回封", "repack_text")

    def _cancel(self) -> None:
        self.worker.cancel()
        self._log("已请求取消；将在当前文件结束后停止")

    # -- 事件泵 ---------------------------------------------------------
    def _pump(self) -> None:
        for event in self.worker.drain():
            self._handle(event)
        if not self.worker.busy:
            self.btn_cancel.setEnabled(False)

    def _handle(self, event: Event) -> None:
        if event.kind == "progress":
            self.progress.setValue(int(event.fraction * 100))
            return
        if event.kind == "started":
            return
        if event.kind == "failed":
            self.progress.setValue(100)
            self._log(f"任务出错：{event.message}")
            QMessageBox.critical(self, "任务失败", event.message)
            return
        if event.kind in ("finished", "cancelled"):
            self.progress.setValue(100)
            self._report(event)

    def _report(self, event: Event) -> None:
        data = event.payload.get("data", {})
        rows = data.get("rows", [])          # 只含失败/跳过行
        total = data.get("row_count", data.get("total", 0))
        ok = data.get("succeeded", 0)
        failed = data.get("failed", 0)
        skipped = data.get("skipped", 0) or sum(
            1 for r in rows if r.get("status") == "skipped")
        parts = [f"{event.stage}完成：{total} 个文件，成功 {ok}"]
        if skipped:
            parts.append(f"跳过 {skipped}")
        if failed:
            parts.append(f"失败 {failed}")
        if data.get("cancelled"):
            parts.append("（已取消，未处理完全部文件）")
        self._log("，".join(parts))

        if event.stage == "反汇编" and ok:
            self._log(
                f"零编辑往返：{'全部逐字节一致' if data.get('all_zero_edit_identical') else '存在不一致'}"
                f"；最低覆盖率 {data.get('min_byte_coverage', 0):.4f}")
            self._log(f"值节点 {data.get('value_nodes', 0):,}，"
                      f"可翻译条目 {data.get('text_entries', 0):,}")
        elif event.stage == "提取文本" and ok:
            self._log(f"共 {data.get('units', 0):,} 条文本，"
                      f"目标编码 {data.get('target_encoding', '?')}")
        elif event.stage == "回封":
            if data.get("error"):
                self._log(data["error"])
            elif ok:
                self._log(f"应用译文 {data.get('changed_entries', 0):,} 条，"
                          f"合计长度变化 {data.get('total_delta_bytes', 0):+,} 字节")

        for r in rows:
            if r.get("status") == "failed":
                self._log(f"  失败 {r['sample']}：{r['error']}")
            elif r.get("status") == "skipped":
                self._log(f"  跳过 {r['sample']}：{r['skipped']}")
        if failed + skipped > len(rows):
            self._log(f"  （还有更多，详见报告文件）")

        for name, path in event.payload.get("artifacts", {}).items():
            self._log(f"{name}：{path}")

    def _log(self, message: str) -> None:
        self.log.appendPlainText(message)


def run() -> int:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()
