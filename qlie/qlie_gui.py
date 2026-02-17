"""
QLIE Engine Tool — 整合版（单文件）
包含 .b 格式解包/封回核心逻辑 + PyQt6 GUI
"""

import sys, os, struct, json, hashlib, threading, datetime, subprocess, traceback
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit,
                             QFileDialog, QProgressBar, QMessageBox, QFrame,
                             QComboBox, QTabWidget)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QThread
from PyQt6.QtGui import QDropEvent, QDragEnterEvent

# Try to import darkdetect for system theme detection
try:
    import darkdetect
    HAS_DARKDETECT = True
except ImportError:
    HAS_DARKDETECT = False

# ══════════════════════════════════════════════════════════════════════════
#  核心引擎 —— 原 qlie_tool.py
# ══════════════════════════════════════════════════════════════════════════

def pad_marker(name, size=16):
    b = name.encode("ascii")
    return b + b"\x00" * (size - len(b))

def read_marker(data, pos):
    raw = data[pos:pos + 16]
    return raw.rstrip(b"\x00").decode("ascii", errors="replace"), pos + 16

def r_u8(data, pos):  return data[pos], pos + 1
def r_u16(data, pos): return struct.unpack_from("<H", data, pos)[0], pos + 2
def r_u32(data, pos): return struct.unpack_from("<I", data, pos)[0], pos + 4
def w_u8(v):  return struct.pack("<B", v)
def w_u16(v): return struct.pack("<H", v)
def w_u32(v): return struct.pack("<I", v)

def detect_ext(payload):
    if payload[:4] == b"\x89PNG": return ".png"
    if payload[:2] == b"\xff\xd8": return ".jpg"
    if payload[:4] == b"OggS":    return ".ogg"
    if payload[:4] == b"RIFF":    return ".wav"
    if payload[:4] == b"abmp" or payload[:4] == b"ABMP": return ".b"
    return ".bin"

def smart_decode(raw: bytes) -> str:
    """尝试多种编码解码原始字节，返回最佳结果。
    优先级: utf-8 > cp932(Shift-JIS) > gbk > euc-kr > latin-1(兜底，永不失败)"""
    if not raw:
        return ""
    for enc in ("utf-8", "cp932", "gbk", "euc-kr"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
    return raw.decode("latin-1")  # latin-1 兜底，1:1 映射永不失败

def safe_filename(name):
    for ch in '\\/:*?"<>|':
        name = name.replace(ch, "_")
    return name.strip() or "unnamed"

def parse_entry(data, pos, is_image=True):
    """Parse one entry. Handles abimgdat10/13/14/15 and absnddat10/11/12 tag formats
    based on the C# reference implementation (ArcABMP.cs)."""
    marker, pos = read_marker(data, pos)
    entry = {"marker": marker}

    if marker == "abimgdat15":
        # abimgdat15: version(u32), name_len(u16), name(utf16), hash_len(u16), hash(ascii),
        #             type_byte(u8), skip(0x1D if version==2 else 0x11)
        entry["version"], pos = r_u32(data, pos)
        name_len, pos = r_u16(data, pos)
        raw_name = b""
        if name_len > 0:
            raw_name = data[pos:pos + name_len * 2]
            pos += name_len * 2
        entry["name_hex"] = raw_name.hex()
        entry["name_encoding"] = "utf-16-le"
        entry["name"] = raw_name.decode("utf-16-le", errors="replace") if raw_name else ""
        hash_len, pos = r_u16(data, pos)
        raw_hash = data[pos:pos + hash_len] if hash_len > 0 else b""
        entry["hash_hex"] = raw_hash.hex()
        entry["hash"] = raw_hash.decode("ascii", errors="replace") if raw_hash else ""
        pos += hash_len
        entry["type_byte"], pos = r_u8(data, pos)
        skip = 0x1D if entry["version"] == 2 else 0x11
        entry["skip_size"] = skip
        entry["padding_hex"] = data[pos:pos + skip].hex()
        pos += skip

    elif marker == "absnddat12":
        # absnddat12: version(u32), name_len(u16), name(utf16), skip 7 (if enough data)
        entry["version"], pos = r_u32(data, pos)
        name_len, pos = r_u16(data, pos)
        raw_name = b""
        if name_len > 0:
            raw_name = data[pos:pos + name_len * 2]
            pos += name_len * 2
        entry["name_hex"] = raw_name.hex()
        entry["name_encoding"] = "utf-16-le"
        entry["name"] = raw_name.decode("utf-16-le", errors="replace") if raw_name else ""
        entry["hash"] = ""
        entry["hash_hex"] = ""
        remaining = len(data) - pos
        if remaining <= 7:
            # At EOF: no data_size field, just trailing padding bytes
            entry["padding_hex"] = data[pos:].hex()
            entry["data_size"] = 0
            entry["eof_entry"] = True
            return entry, b"", len(data)
        entry["padding_hex"] = data[pos:pos + 7].hex()
        pos += 7

    elif marker in ("abimgdat10", "absnddat10"):
        # Old format: name_len(u16), name(cstring/ascii), type_byte(u8)
        name_len, pos = r_u16(data, pos)
        raw_name = b""
        if name_len > 0:
            raw_name = data[pos:pos + name_len]
            pos += name_len
        entry["name_hex"] = raw_name.hex()
        entry["name_encoding"] = "bytes"
        entry["name"] = smart_decode(raw_name)
        entry["hash"] = ""
        entry["hash_hex"] = ""
        entry["type_byte"], pos = r_u8(data, pos)

    elif marker in ("abimgdat13", "abimgdat14"):
        # Intermediate format: name_len(u16), name(cstring), hash_len(u16), hash(ascii),
        #   skip(0x0C for 13, 0x4C for 14), type_byte(u8)
        name_len, pos = r_u16(data, pos)
        raw_name = b""
        if name_len > 0:
            raw_name = data[pos:pos + name_len]
            pos += name_len
        entry["name_hex"] = raw_name.hex()
        entry["name_encoding"] = "bytes"
        entry["name"] = smart_decode(raw_name)
        hash_len, pos = r_u16(data, pos)
        raw_hash = data[pos:pos + hash_len] if hash_len > 0 else b""
        entry["hash_hex"] = raw_hash.hex()
        entry["hash"] = raw_hash.decode("ascii", errors="replace") if raw_hash else ""
        pos += hash_len
        skip = 0x0C if marker == "abimgdat13" else 0x4C
        entry["skip_size"] = skip
        entry["padding_hex"] = data[pos:pos + skip].hex()
        pos += skip
        entry["type_byte"], pos = r_u8(data, pos)

    else:
        # Fallback (e.g. absnddat11, etc.): name_len(u16), name(cstring),
        # hash_len(u16), hash(ascii), type_byte(u8)
        name_len, pos = r_u16(data, pos)
        raw_name = b""
        if name_len > 0:
            raw_name = data[pos:pos + name_len]
            pos += name_len
        entry["name_hex"] = raw_name.hex()
        entry["name_encoding"] = "bytes"
        entry["name"] = smart_decode(raw_name)
        hash_len, pos = r_u16(data, pos)
        raw_hash = data[pos:pos + hash_len] if hash_len > 0 else b""
        entry["hash_hex"] = raw_hash.hex()
        entry["hash"] = raw_hash.decode("ascii", errors="replace") if raw_hash else ""
        pos += hash_len
        entry["type_byte"], pos = r_u8(data, pos)

    data_size, pos = r_u32(data, pos)
    entry["data_size"] = data_size
    payload = b""
    if data_size > 0 and pos + data_size <= len(data):
        payload = data[pos:pos + data_size]
        pos += data_size
    return entry, payload, pos

def unpack(filepath, output_dir, log_fn=None):
    def log(t):
        if log_fn: log_fn(t)
    with open(filepath, "rb") as f:
        data = f.read()
    log(f"输入: {os.path.basename(filepath)} ({len(data):,} 字节)")
    os.makedirs(output_dir, exist_ok=True)
    meta = {"source_file": os.path.basename(filepath), "file_size": len(data)}
    pos = 0
    marker, pos = read_marker(data, pos)
    meta["header_marker"] = marker
    marker, pos = read_marker(data, pos)
    meta["abdata_marker"] = marker
    payload_size, pos = r_u32(data, pos)
    meta["abdata_size"] = payload_size
    op_data = data[pos:pos + payload_size]
    pos += payload_size
    op_file = "abdata_ops.bin"
    with open(os.path.join(output_dir, op_file), "wb") as f:
        f.write(op_data)
    meta["abdata_file"] = op_file
    if len(op_data) >= 12 and op_data[:3] == b"1PC":
        meta["1pc_version"] = op_data[3]
        meta["1pc_val1"] = struct.unpack_from("<I", op_data, 4)[0]
        meta["1pc_val2"] = struct.unpack_from("<I", op_data, 8)[0]
        log(f"1PC 脚本: {len(op_data)-12} 字节操作码")
    meta["sections"] = []
    file_index = 0
    while pos < len(data):
        marker, new_pos = read_marker(data, pos)
        if marker.startswith("abimage") or marker.startswith("absound"):
            pos = new_pos
            is_image = marker.startswith("abimage")
            section = {"marker": marker, "entries": []}
            count, pos = r_u8(data, pos)
            section["count"] = count
            kind = "图片" if is_image else "音频"
            log(f"{kind}区段: {count} 个条目")
            for i in range(count):
                entry, payload, pos = parse_entry(data, pos)
                if payload:
                    ext = detect_ext(payload)
                    fname = safe_filename(entry["name"]) + ext
                    with open(os.path.join(output_dir, fname), "wb") as f:
                        f.write(payload)
                    entry["file"] = fname
                    file_index += 1
                    log(f"  [{i+1}/{count}] {fname} ({len(payload):,} 字节)")
                else:
                    entry["file"] = None
                    log(f"  [{i+1}/{count}] {entry['name']} (空)")
                del entry["data_size"]
                section["entries"].append(entry)
            meta["sections"].append(section)
        else:
            pos += 1
    meta_path = os.path.join(output_dir, "metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    log(f"共提取 {file_index} 个文件 -> {os.path.basename(output_dir)}")

def repack(input_dir, output_file, log_fn=None):
    def log(t):
        if log_fn: log_fn(t)
    meta_path = os.path.join(input_dir, "metadata.json")
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    log(f"来源: {os.path.basename(input_dir)}")
    out = bytearray()
    out += pad_marker(meta["header_marker"])
    out += pad_marker(meta["abdata_marker"])
    op_path = os.path.join(input_dir, meta["abdata_file"])
    with open(op_path, "rb") as f:
        op_data = f.read()
    out += w_u32(len(op_data))
    out += op_data
    total_files = 0
    for section in meta["sections"]:
        out += pad_marker(section["marker"])
        out += w_u8(section["count"])
        for entry in section["entries"]:
            marker = entry["marker"]
            out += pad_marker(marker)

            if marker == "abimgdat15":
                out += w_u32(entry["version"])
                name_raw = bytes.fromhex(entry["name_hex"]) if entry.get("name_hex") else entry["name"].encode("utf-16-le")
                out += w_u16(len(name_raw) // 2)
                out += name_raw
                hash_raw = bytes.fromhex(entry["hash_hex"]) if entry.get("hash_hex") else entry["hash"].encode("ascii")
                out += w_u16(len(hash_raw))
                out += hash_raw
                out += w_u8(entry.get("type_byte", 0))
                out += bytes.fromhex(entry.get("padding_hex", "00" * entry.get("skip_size", 0x11)))

            elif marker == "absnddat12":
                out += w_u32(entry["version"])
                name_raw = bytes.fromhex(entry["name_hex"]) if entry.get("name_hex") else entry["name"].encode("utf-16-le")
                out += w_u16(len(name_raw) // 2)
                out += name_raw
                out += bytes.fromhex(entry.get("padding_hex", "00" * 7))
                if entry.get("eof_entry"):
                    continue  # no data_size field at EOF

            elif marker in ("abimgdat10", "absnddat10"):
                name_raw = bytes.fromhex(entry["name_hex"]) if entry.get("name_hex") else entry["name"].encode("utf-8")
                out += w_u16(len(name_raw))
                out += name_raw
                out += w_u8(entry.get("type_byte", 0))

            elif marker in ("abimgdat13", "abimgdat14"):
                name_raw = bytes.fromhex(entry["name_hex"]) if entry.get("name_hex") else entry["name"].encode("utf-8")
                out += w_u16(len(name_raw))
                out += name_raw
                hash_raw = bytes.fromhex(entry["hash_hex"]) if entry.get("hash_hex") else entry["hash"].encode("ascii")
                out += w_u16(len(hash_raw))
                out += hash_raw
                skip = entry.get("skip_size", 0x0C if marker == "abimgdat13" else 0x4C)
                out += bytes.fromhex(entry.get("padding_hex", "00" * skip))
                out += w_u8(entry.get("type_byte", 0))

            else:
                # Fallback generic (e.g. absnddat11)
                name_raw = bytes.fromhex(entry["name_hex"]) if entry.get("name_hex") else entry["name"].encode("utf-8")
                out += w_u16(len(name_raw))
                out += name_raw
                hash_raw = bytes.fromhex(entry["hash_hex"]) if entry.get("hash_hex") else entry.get("hash", "").encode("ascii")
                out += w_u16(len(hash_raw))
                out += hash_raw
                out += w_u8(entry.get("type_byte", 0))

            if entry.get("file"):
                fpath = os.path.join(input_dir, entry["file"])
                with open(fpath, "rb") as f:
                    payload = f.read()
                out += w_u32(len(payload))
                out += payload
                total_files += 1
            else:
                out += w_u32(0)
    with open(output_file, "wb") as f:
        f.write(out)
    log(f"已封回 {total_files} 个文件 -> {os.path.basename(output_file)} ({len(out):,} 字节)")

def cli_main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python qlie_gui.py unpack <input.b> [output_dir]")
        print("  python qlie_gui.py repack <input_dir> [output.b]")
        sys.exit(1)
    cmd = sys.argv[1].lower()
    if cmd == "unpack":
        inp = sys.argv[2]
        out = sys.argv[3] if len(sys.argv) > 3 else os.path.splitext(inp)[0] + "_out"
        unpack(inp, out, log_fn=print)
    elif cmd == "repack":
        inp = sys.argv[2]
        out = sys.argv[3] if len(sys.argv) > 3 else "repacked.b"
        repack(inp, out, log_fn=print)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════
#  GUI — PyQt6
# ══════════════════════════════════════════════════════════════════════════

class WorkerThread(QObject):
    finished = pyqtSignal(bool, str, list, str, str)  # ok, err_msg, logs, out, mode
    log_signal = pyqtSignal(str)

    def __init__(self, mode, input_path, output_path):
        super().__init__()
        self.mode = mode
        self.input_path = input_path
        self.output_path = output_path

    def run(self):
        logs = []
        ok, err_msg = True, ""
        try:
            if self.mode == 'unpack':
                self._run_unpack(logs)
            elif self.mode == 'repack':
                self._run_repack(logs)
        except Exception as e:
            ok, err_msg = False, str(e)
            logs.append(traceback.format_exc())
        self.finished.emit(ok, err_msg, logs, self.output_path, self.mode)

    def _run_unpack(self, logs):
        input_path = self.input_path
        output_path = self.output_path
        files = []
        if os.path.isfile(input_path):
            files = [input_path]
        elif os.path.isdir(input_path):
            for root, _, filenames in os.walk(input_path):
                for name in filenames:
                    if name.lower().endswith(".b"):
                        files.append(os.path.join(root, name))
        if not files:
            logs.append(f"未找到 .b 文件: {input_path}")
            return
        total = len(files)
        logs.append(f"找到 {total} 个 .b 文件，开始解包...")
        for i, file_path in enumerate(files):
            logs.append(f"[{i+1}/{total}] 解包: {os.path.basename(file_path)}")
            fname = os.path.basename(file_path)
            folder_name = os.path.splitext(fname)[0]
            if output_path:
                current_out = os.path.join(output_path, folder_name)
            else:
                current_out = os.path.splitext(file_path)[0]
            try:
                unpack(file_path, current_out, log_fn=lambda t: logs.append(t))
                logs.append(f"  -> 输出: {current_out}")
            except Exception as e:
                logs.append(f"  -> 失败: {str(e)}")
                logs.append(traceback.format_exc())

    def _run_repack(self, logs):
        input_path = self.input_path
        output_path = self.output_path
        tasks = []
        if os.path.isfile(input_path):
            logs.append("错误: 打包模式需要输入目录")
            return
        if os.path.exists(os.path.join(input_path, "metadata.json")):
            dir_name = os.path.basename(input_path.rstrip(os.sep))
            out_name = (dir_name[:-4] if dir_name.endswith("_out") else dir_name) + ".b"
            if output_path:
                if os.path.isdir(output_path) or not os.path.splitext(output_path)[1]:
                    final_out = os.path.join(output_path, out_name)
                else:
                    final_out = output_path
            else:
                final_out = input_path + ".b"
            tasks.append((input_path, final_out))
        else:
            with os.scandir(input_path) as it:
                for entry in it:
                    if entry.is_dir() and os.path.exists(os.path.join(entry.path, "metadata.json")):
                        dir_name = entry.name
                        out_name = (dir_name[:-4] if dir_name.endswith("_out") else dir_name) + ".b"
                        if output_path:
                            final_out = os.path.join(output_path, out_name)
                        else:
                            final_out = os.path.join(input_path, out_name)
                        tasks.append((entry.path, final_out))
        if not tasks:
            logs.append(f"在 {input_path} 未找到包含 metadata.json 的目录")
            return
        total = len(tasks)
        logs.append(f"找到 {total} 个待打包目录，开始打包...")
        if output_path:
            os.makedirs(output_path, exist_ok=True)
        for i, (in_dir, out_file) in enumerate(tasks):
            logs.append(f"[{i+1}/{total}] 打包: {os.path.basename(in_dir)}")
            try:
                repack(in_dir, out_file, log_fn=lambda t: logs.append(t))
                logs.append(f"  -> 生成: {out_file}")
            except Exception as e:
                logs.append(f"  -> 失败: {str(e)}")
                logs.append(traceback.format_exc())


class DragDropLineEdit(QLineEdit):
    file_dropped = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self.setText(path)
            self.file_dropped.emit(path)


class ModernButton(QPushButton):
    def __init__(self, text, is_primary=False):
        super().__init__(text)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setObjectName("PrimaryButton" if is_primary else "SecondaryButton")
        self.setMinimumHeight(35)


class QLIEGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QLIE .B Toolkit GUI")
        self.resize(700, 650)
        self.setObjectName("MainBackground")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        self.init_ui()
        self.detect_system_theme()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        self.setLayout(main_layout)

        # --- Header ---
        header_layout = QHBoxLayout()
        title_label = QLabel("QLIE .B Toolkit")
        title_label.setObjectName("AppTitle")
        title_label.setStyleSheet("font-size: 18pt; font-weight: bold;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        # Theme Selector
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["跟随系统", "现代浅色", "现代深色", "赛博朋克"])
        self.theme_combo.currentTextChanged.connect(self.apply_theme)
        header_layout.addWidget(QLabel("主题:"))
        header_layout.addWidget(self.theme_combo)

        main_layout.addLayout(header_layout)

        # --- Tabs ---
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # --- Unpack Tab ---
        unpack_tab = QWidget()
        self.setup_unpack_tab(unpack_tab)
        self.tabs.addTab(unpack_tab, "解包 (Unpack)")

        # --- Repack Tab ---
        repack_tab = QWidget()
        self.setup_repack_tab(repack_tab)
        self.tabs.addTab(repack_tab, "打包 (Repack)")

        # --- Log ---
        log_label = QLabel("日志:")
        main_layout.addWidget(log_label)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setObjectName("LogConsole")
        main_layout.addWidget(self.log_text)

        # Status
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.hide()
        main_layout.addWidget(self.progress_bar)

    def setup_unpack_tab(self, tab):
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        tab.setLayout(layout)

        # Input
        self.unpack_input_edit = self.create_file_selector(
            layout,
            "输入文件/目录 (.b):",
            is_input=True,
            on_change=lambda: self.auto_fill_output('unpack')
        )

        # Output
        self.unpack_output_edit = self.create_file_selector(layout, "输出目录 (可选):", is_input=False)

        layout.addSpacing(20)

        # Action Button
        btn_layout = QHBoxLayout()
        self.btn_unpack = ModernButton("执行解包", is_primary=True)
        self.btn_unpack.clicked.connect(self.run_unpack)
        btn_layout.addWidget(self.btn_unpack)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        layout.addStretch()

    def setup_repack_tab(self, tab):
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        tab.setLayout(layout)

        # Input
        self.repack_input_edit = self.create_file_selector(
            layout,
            "输入目录 (包含 metadata.json):",
            is_input=True,
            on_change=lambda: self.auto_fill_output('repack')
        )

        # Output
        self.repack_output_edit = self.create_file_selector(layout, "输出目录 (可选):", is_input=False)

        layout.addSpacing(20)

        # Action Button
        btn_layout = QHBoxLayout()
        self.btn_repack = ModernButton("执行打包", is_primary=True)
        self.btn_repack.clicked.connect(self.run_repack)
        btn_layout.addWidget(self.btn_repack)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        layout.addStretch()

    def create_file_selector(self, parent_layout, label_text, is_input=True, on_change=None):
        container = QVBoxLayout()
        container.setSpacing(5)

        label = QLabel(label_text)
        container.addWidget(label)

        row = QHBoxLayout()
        row.setSpacing(8)

        edit = DragDropLineEdit()
        edit.setPlaceholderText("拖拽文件/文件夹到此处...")
        if on_change:
            edit.file_dropped.connect(on_change)
        row.addWidget(edit)

        if is_input:
            btn_file = ModernButton("文件", is_primary=False)
            btn_file.clicked.connect(lambda: self.browse_file(edit, on_change))
            row.addWidget(btn_file)

            btn_folder = ModernButton("目录", is_primary=False)
            btn_folder.clicked.connect(lambda: self.browse_folder(edit, on_change))
            row.addWidget(btn_folder)
        else:
            btn_folder = ModernButton("目录", is_primary=False)
            btn_folder.clicked.connect(lambda: self.browse_folder(edit))
            row.addWidget(btn_folder)

        container.addLayout(row)
        parent_layout.addLayout(container)
        return edit

    def browse_folder(self, line_edit, on_change=None):
        path = QFileDialog.getExistingDirectory(self, "选择目录")
        if path:
            line_edit.setText(os.path.normpath(path))
            if on_change:
                on_change()

    def browse_file(self, line_edit, on_change=None):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if path:
            line_edit.setText(os.path.normpath(path))
            if on_change:
                on_change()

    def auto_fill_output(self, mode):
        if mode == 'unpack':
            input_path = self.unpack_input_edit.text().strip()
            if input_path:
                base_path = os.path.splitext(input_path)[0]
                self.unpack_output_edit.setText(f"{base_path}_out")
        elif mode == 'repack':
            input_path = self.repack_input_edit.text().strip()
            if input_path:
                if input_path.endswith("/") or input_path.endswith("\\"):
                    input_path = input_path[:-1]
                self.repack_output_edit.setText(f"{input_path}_repack")

    def run_unpack(self):
        input_path = self.unpack_input_edit.text().strip()
        output_path = self.unpack_output_edit.text().strip()
        if not input_path:
            QMessageBox.warning(self, "提示", "请选择输入文件或目录")
            return
        self.start_worker('unpack', input_path, output_path)

    def run_repack(self):
        input_path = self.repack_input_edit.text().strip()
        output_path = self.repack_output_edit.text().strip()
        if not input_path:
            QMessageBox.warning(self, "提示", "请选择输入目录")
            return
        self.start_worker('repack', input_path, output_path)

    def start_worker(self, mode, input_path, output_path):
        self.set_ui_enabled(False)
        self.progress_bar.show()
        self.log_text.clear()

        self.worker_thread = QThread()
        self.worker = WorkerThread(mode, input_path, output_path)
        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)

        self.worker_thread.start()

    def on_worker_finished(self, ok, err_msg, logs, output_path, mode):
        self.progress_bar.hide()
        self.set_ui_enabled(True)
        for line in logs:
            self.log_text.append(line)
        if ok:
            self.log_text.append("任务完成！")
            if mode == 'repack' and os.path.isfile(output_path):
                self._verify_hash(output_path)
        else:
            self.log_text.append(f"任务失败: {err_msg}")

    def _verify_hash(self, repacked_path):
        """封回后自动与原始文件做 MD5 校验"""
        # 尝试找到原始文件
        base = repacked_path
        for suffix in ["_repack", "_repacked"]:
            if suffix in base:
                base = base.split(suffix)[0]
                break
        candidates = []
        # 如果 repacked_path 在输出目录中，尝试匹配同名 .b
        rname = os.path.basename(repacked_path)
        parent = os.path.dirname(repacked_path)
        # 往上一层找
        grandparent = os.path.dirname(parent) if parent else ""
        for d in [parent, grandparent]:
            if d:
                cand = os.path.join(d, rname)
                if cand not in candidates:
                    candidates.append(cand)
        # 通过 metadata 找原始文件
        input_path = self.repack_input_edit.text().strip() if hasattr(self, 'repack_input_edit') else ""
        if input_path:
            meta_path = os.path.join(input_path, "metadata.json")
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    src = meta.get("source_file", "")
                    if src:
                        src_dir = os.path.dirname(input_path)
                        candidates.insert(0, os.path.join(src_dir, src))
                except Exception:
                    pass

        for orig in candidates:
            if os.path.isfile(orig) and os.path.abspath(orig) != os.path.abspath(repacked_path):
                h1 = self._md5(orig)
                h2 = self._md5(repacked_path)
                if h1 == h2:
                    self.log_text.append(f"MD5 校验: 与原始文件完全一致 ({h1[:16]}...)")
                else:
                    self.log_text.append(f"MD5 校验: 与原始文件不同")
                    self.log_text.append(f"  原始: {h1}")
                    self.log_text.append(f"  封回: {h2}")
                return

    @staticmethod
    def _md5(path):
        h = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def set_ui_enabled(self, enabled):
        self.btn_unpack.setEnabled(enabled)
        self.btn_repack.setEnabled(enabled)
        self.unpack_input_edit.setEnabled(enabled)
        self.unpack_output_edit.setEnabled(enabled)
        self.repack_input_edit.setEnabled(enabled)
        self.repack_output_edit.setEnabled(enabled)

    def detect_system_theme(self):
        self.theme_combo.setCurrentText("跟随系统")
        self.apply_theme("跟随系统")

    def apply_theme(self, theme_name):
        real_theme = theme_name
        if theme_name == "跟随系统":
            if HAS_DARKDETECT and darkdetect.isDark():
                real_theme = "现代深色"
            else:
                real_theme = "现代浅色"

        light_qss = """
        QWidget { font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; font-size: 10pt; color: #333333; }
        QWidget#MainBackground { background-color: #f5f7fa; }
        QFrame#CardFrame { background-color: #ffffff; border: 1px solid #e1e4e8; border-radius: 8px; }
        QLabel#AppTitle { font-size: 18pt; font-weight: bold; color: #2c3e50; }
        QLineEdit { padding: 8px; border: 1px solid #ced4da; border-radius: 4px; background: #ffffff; color: #333; }
        QLineEdit:focus { border: 1px solid #3498db; }
        QPushButton#SecondaryButton { background-color: #ffffff; border: 1px solid #dcdfe6; border-radius: 4px; color: #606266; padding: 6px 12px; }
        QPushButton#SecondaryButton:hover { border-color: #c6e2ff; color: #409eff; background-color: #ecf5ff; }
        QPushButton#PrimaryButton { background-color: #3498db; border: 1px solid #3498db; border-radius: 4px; color: #ffffff; font-weight: bold; padding: 8px 16px; }
        QPushButton#PrimaryButton:hover { background-color: #5dade2; border-color: #5dade2; }
        QTabWidget::pane { border: 1px solid #e1e4e8; background: #fff; border-radius: 5px; }
        QTabBar::tab { background: #e8ebf0; color: #666; padding: 10px 20px; margin-right: 2px; border-top-left-radius: 4px; border-top-right-radius: 4px; }
        QTabBar::tab:selected { background: #ffffff; color: #3498db; font-weight: bold; }
        QTextEdit#LogConsole { background-color: #fcfcfc; color: #333333; border: 1px solid #e1e4e8; font-family: 'Consolas', monospace; font-size: 9pt; }
        QComboBox { padding: 4px; color: #333; background: #fff; border: 1px solid #ced4da; border-radius: 4px; }
        """

        dark_qss = """
        QWidget { font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; font-size: 10pt; color: #e0e0e0; }
        QWidget#MainBackground { background-color: #1e1e1e; }
        QFrame#CardFrame { background-color: #2d2d2d; border: 1px solid #444; border-radius: 8px; }
        QLabel { color: #e0e0e0; }
        QLabel#AppTitle { color: #ffffff; font-size: 18pt; font-weight: bold; }
        QLineEdit { background: #1a1a1a; border: 1px solid #555; border-radius: 4px; color: #ffffff; padding: 8px; }
        QLineEdit:focus { border: 1px solid #bb86fc; }
        QPushButton#SecondaryButton { background: #333; border: 1px solid #555; color: #ddd; border-radius: 4px; }
        QPushButton#SecondaryButton:hover { background: #444; border-color: #777; }
        QPushButton#PrimaryButton { background: #bb86fc; border: 1px solid #bb86fc; color: #121212; border-radius: 4px; font-weight:bold; }
        QPushButton#PrimaryButton:hover { background: #d0aaff; }
        QTabWidget::pane { border: 1px solid #444; background: #2d2d2d; }
        QTabBar::tab { background: #1e1e1e; color: #999; padding: 10px 20px; border-top-left-radius: 4px; border-top-right-radius: 4px; margin-right:2px;}
        QTabBar::tab:selected { background: #2d2d2d; color: #bb86fc; font-weight:bold; }
        QTextEdit#LogConsole { background-color: #1a1a1a; color: #e0e0e0; border: 1px solid #444; font-family: 'Consolas', monospace; font-size: 9pt; }
        QComboBox { padding: 4px; color: #e0e0e0; background: #333; border: 1px solid #555; border-radius: 4px; }
        QComboBox QAbstractItemView { background-color: #2d2d2d; color: #e0e0e0; selection-background-color: #bb86fc; selection-color: #121212; }
        """

        cyber_qss = """
        QWidget { font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; font-size: 10pt; color: #00ffcc; }
        QWidget#MainBackground { background-color: #0d0d15; }
        QFrame#CardFrame { background-color: #1a1a2e; border: 1px solid #00ffcc; border-radius: 8px; }
        QLabel { color: #00ffcc; }
        QLabel#AppTitle { color: #ff00ff; font-size: 18pt; font-weight: bold; }
        QLineEdit { background: #0f0f1a; border: 1px solid #ff00ff; border-radius: 4px; color: #00ffcc; padding: 8px; }
        QPushButton#SecondaryButton { background: #0b0b19; border: 1px solid #00ffcc; color: #00ffcc; }
        QPushButton#PrimaryButton { background: #ff0055; border: 1px solid #ff0055; color: #ffffff; font-weight: bold; }
        QTabWidget::pane { border: 1px solid #00ffcc; background: #0d0d15; }
        QTabBar::tab { background: #0d0d15; color: #008888; border: 1px solid #004444; padding: 10px; }
        QTabBar::tab:selected { color: #00ffcc; border: 1px solid #00ffcc; }
        QTextEdit#LogConsole { background-color: #0f0f1f; color: #00ffcc; border: 1px solid #00ffcc; }
        QComboBox { background: #0d0d15; color: #00ffcc; border: 1px solid #00ffcc; }
        QComboBox QAbstractItemView { background-color: #0d0d15; color: #00ffcc; selection-background-color: #ff0055; }
        """

        if real_theme == "现代深色":
            self.setStyleSheet(dark_qss)
        elif real_theme == "赛博朋克":
            self.setStyleSheet(cyber_qss)
        else:
            self.setStyleSheet(light_qss)


# ══════════════════════════════════════════════════════════════════════════
#  入口
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1].lower() in ("unpack", "repack"):
        cli_main()
    else:
        app = QApplication(sys.argv)
        window = QLIEGUI()
        window.show()
        sys.exit(app.exec())
