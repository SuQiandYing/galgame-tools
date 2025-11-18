# -*- coding:utf-8 -*-
import os
import re
import struct
import sys
import json
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QFileDialog,
                             QTextEdit, QProgressBar, QFrame, QLineEdit,
                             QGraphicsDropShadowEffect, QStackedWidget, QMessageBox, QComboBox,
                             QCheckBox)
from PyQt6.QtCore import (Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve, 
                          QPoint, QRectF, QUrl, QSettings, pyqtProperty)
from PyQt6.QtGui import (QFont, QColor, QPainter, QPainterPath, QDragEnterEvent, 
                         QDropEvent, QDesktopServices, QPen, QCloseEvent, QLinearGradient)

# ==========================================
# 配色方案配置 (主题引擎)
# ==========================================
THEMES = {
    "🌸 樱花 (Sakura)": {
        "bg_grad": ["#Fce4ec", "#F3E5F5", "#E1BEE7"],
        "accent": "#ff80ab",
        "btn_hover": "#ff4081",
        "text_main": "#333333",
        "text_dim": "#555555",
        "card_bg": "rgba(255, 255, 255, 0.65)",
        "input_bg": "rgba(255,255,255,0.5)",
        "input_focus": "rgba(255,255,255,0.9)",
        "border": "rgba(255, 255, 255, 0.8)"
    },
    "🌊 深海 (Ocean)": {
        "bg_grad": ["#E3F2FD", "#BBDEFB", "#90CAF9"],
        "accent": "#2196F3",
        "btn_hover": "#1976D2",
        "text_main": "#0D47A1",
        "text_dim": "#1565C0",
        "card_bg": "rgba(255, 255, 255, 0.75)",
        "input_bg": "rgba(255,255,255,0.6)",
        "input_focus": "#FFFFFF",
        "border": "rgba(255, 255, 255, 0.8)"
    },
    "🍃 薄荷 (Mint)": {
        "bg_grad": ["#E0F2F1", "#B2DFDB", "#80CBC4"],
        "accent": "#009688",
        "btn_hover": "#00796B",
        "text_main": "#004D40",
        "text_dim": "#00695C",
        "card_bg": "rgba(255, 255, 255, 0.7)",
        "input_bg": "rgba(255,255,255,0.5)",
        "input_focus": "#FFFFFF",
        "border": "rgba(255, 255, 255, 0.8)"
    },
    "🌙 暗夜 (Night)": {
        "bg_grad": ["#232526", "#414345", "#232526"],
        "accent": "#BB86FC",
        "btn_hover": "#985EFF",
        "text_main": "#E0E0E0",
        "text_dim": "#B0B0B0",
        "card_bg": "rgba(30, 30, 30, 0.75)",
        "input_bg": "rgba(60, 60, 60, 0.5)",
        "input_focus": "rgba(80, 80, 80, 0.9)",
        "border": "rgba(80, 80, 80, 0.8)"
    },
    "🍊 活力 (Sunset)": {
        "bg_grad": ["#FFF3E0", "#FFE0B2", "#FFCC80"],
        "accent": "#FF9800",
        "btn_hover": "#F57C00",
        "text_main": "#E65100",
        "text_dim": "#EF6C00",
        "card_bg": "rgba(255, 255, 255, 0.7)",
        "input_bg": "rgba(255,255,255,0.5)",
        "input_focus": "#FFFFFF",
        "border": "rgba(255, 255, 255, 0.8)"
    }
}

# ==========================================
# 增强版 UI 组件 (支持 update_theme)
# ==========================================
class AnimButton(QPushButton):
    def __init__(self, btn_type, func, parent=None):
        super().__init__(parent)
        self.setFixedSize(45, 30)
        self.clicked.connect(func)
        self.btn_type = btn_type
        self._hover_progress = 0.0
        self.parent_win = parent
        self.anim = QPropertyAnimation(self, b"hoverProgress")
        self.anim.setDuration(200)
        self.anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        self.icon_color = QColor(0,0,0)

    @pyqtProperty(float)
    def hoverProgress(self): return self._hover_progress
    @hoverProgress.setter
    def hoverProgress(self, val): self._hover_progress = val; self.update()

    def enterEvent(self, e):
        self.anim.setStartValue(self.hoverProgress); self.anim.setEndValue(1.0); self.anim.start()
        super().enterEvent(e)
    def leaveEvent(self, e):
        self.anim.setStartValue(self.hoverProgress); self.anim.setEndValue(0.0); self.anim.start()
        super().leaveEvent(e)
    
    def update_icon_color(self, c):
        self.icon_color = QColor(c)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self.btn_type == "close":
            bg_col = QColor(232, 17, 35, int(255 * self._hover_progress))
            icon_col = self.icon_color if self._hover_progress < 0.5 else QColor(255, 255, 255)
        else:
            bg_col = QColor(0, 0, 0, int(20 * self._hover_progress))
            icon_col = self.icon_color
        p.fillRect(self.rect(), bg_col)
        pen = QPen(icon_col); pen.setWidthF(1.2); p.setPen(pen)
        w, h = self.width(), self.height(); cx, cy = w/2, h/2
        if self.btn_type == "close":
            p.drawLine(QPoint(int(cx-4), int(cy-4)), QPoint(int(cx+4), int(cy+4)))
            p.drawLine(QPoint(int(cx+4), int(cy-4)), QPoint(int(cx-4), int(cy+4)))
        elif self.btn_type == "max":
            is_max = False
            if self.parent_win and hasattr(self.parent_win, 'is_max'): is_max = self.parent_win.is_max
            if is_max:
                p.drawRect(QRectF(cx-2, cy-4, 6, 6))
                p.drawLine(QPoint(int(cx-4), int(cy-2)), QPoint(int(cx-4), int(cy+4))) 
                p.drawLine(QPoint(int(cx-4), int(cy+4)), QPoint(int(cx+2), int(cy+4))) 
                p.drawLine(QPoint(int(cx+2), int(cy+4)), QPoint(int(cx+2), int(cy+2))) 
            else: p.drawRect(QRectF(cx-4, cy-4, 8, 8))
        elif self.btn_type == "min":
            p.drawLine(QPoint(int(cx-4), int(cy)), QPoint(int(cx+4), int(cy)))

class IOSButton(QPushButton):
    def __init__(self, text, color="#007AFF", parent=None):
        super().__init__(text, parent); self.base_color = color
        self.setFont(QFont("Microsoft YaHei", 10, QFont.Weight.Bold)); self.setCursor(Qt.CursorShape.PointingHandCursor); self.setFixedHeight(45)
        self._anim = QPropertyAnimation(self, b"geometry"); self._anim.setDuration(100); self._anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        self.shadow = QGraphicsDropShadowEffect(); self.shadow.setBlurRadius(15); self.shadow.setColor(QColor(0,0,0,40)); self.shadow.setOffset(0, 4); self.setGraphicsEffect(self.shadow)
        self.update_style()
    
    def set_theme_color(self, c):
        self.base_color = c
        self.update_style()

    def update_style(self, pressed=False):
        self.setStyleSheet(f"QPushButton {{background-color: {self.base_color}; color: white; border-radius: 12px; border: none; padding: 10px; font-family: 'Microsoft YaHei';}} QPushButton:hover {{background-color: {QColor(self.base_color).lighter(110).name()};}}")
    def enterEvent(self, e): self.shadow.setBlurRadius(25); self.shadow.setOffset(0, 6); super().enterEvent(e)
    def leaveEvent(self, e): self.shadow.setBlurRadius(15); self.shadow.setOffset(0, 4); super().leaveEvent(e)
    def mousePressEvent(self, e): self.update_style(True); super().mousePressEvent(e)
    def mouseReleaseEvent(self, e): self.update_style(False); super().mouseReleaseEvent(e)

class IOSCard(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent); self.setStyleSheet("IOSCard {background-color: rgba(255, 255, 255, 0.65); border-radius: 20px; border: 1px solid rgba(255, 255, 255, 0.8);}")
        s = QGraphicsDropShadowEffect(); s.setBlurRadius(30); s.setColor(QColor(0,0,0,20)); s.setOffset(0,8); self.setGraphicsEffect(s)
    
    def update_theme(self, bg, border):
        self.setStyleSheet(f"IOSCard {{background-color: {bg}; border-radius: 20px; border: 1px solid {border};}}")

class IOSInput(QLineEdit):
    def __init__(self, ph, parent=None):
        super().__init__(parent); self.setPlaceholderText(ph); self.setFixedHeight(40)
        self.setStyleSheet("QLineEdit {background-color: rgba(255,255,255,0.5); border: 1px solid rgba(0,0,0,0.1); border-radius: 10px; padding: 0 15px; font-size: 13px; color: #333;} QLineEdit:focus {border: 1px solid #007AFF; background-color: rgba(255,255,255,0.9);}")
    
    def update_theme(self, bg, focus_bg, accent, text):
        self.setStyleSheet(f"""
            QLineEdit {{background-color: {bg}; border: 1px solid rgba(128,128,128,0.2); border-radius: 10px; padding: 0 15px; font-size: 13px; color: {text};}} 
            QLineEdit:focus {{border: 1px solid {accent}; background-color: {focus_bg};}}
        """)

class IOSLog(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent); self.setReadOnly(True)
        self.setStyleSheet("QTextEdit {background-color: rgba(0,0,0,0.03); border: none; border-radius: 15px; padding: 15px; font-family: 'Consolas'; font-size: 12px; color: #333;}")
    def mouseReleaseEvent(self, e):
        super().mouseReleaseEvent(e)
        anchor = self.anchorAt(e.pos())
        if anchor: QDesktopServices.openUrl(QUrl.fromLocalFile(anchor))
    def update_theme(self, text, bg):
        self.setStyleSheet(f"QTextEdit {{background-color: {bg}; border: none; border-radius: 15px; padding: 15px; font-family: 'Consolas'; font-size: 12px; color: {text};}}")

# ==========================================
# 核心逻辑 (GameEngine & Worker) - 保持不变
# ==========================================
class GameEngine:
    def __init__(self):
        self.STARTPOSITION = 0
        self.ENDPOSITION = 0
        self.STARTPOSITION2 = 0xc
        self.STARTPOSITION3 = 0x6C450
        
        self.text_path = ""
        self.script_path = ""
        self.encoding_read = '932'
        self.encoding_write = '936'
        self.name_mode = 0

    def byte2int(self, byte): return struct.unpack('L', byte)[0]
    def int2byte(self, num): return struct.pack('L', num)
    def ror(self, val, n): return ((val >> (n % 8)) | (val << (8 - (n % 8)))) & 0xFF

    def format_string(self, string, count):
        return "○%08d○%s\n●%08d●%s\n\n"%(count, string, count, string)

    def dumpstr(self, src):
        bstr = b''; c = src.read(1)
        while c != b'\x00': bstr += c; c = src.read(1)
        try: return bstr.decode(self.encoding_read)
        except: return bstr.decode(self.encoding_read, errors='ignore')

    def encrypt(self, data: bytearray):
        if data[0] != 0x24: return
        size = len(data); count = (size - 0x10) // 4
        p = 0x10; key1, key2, c = 0x084DF873, 0xFF987DEE, 0x04
        for _ in range(count):
            d = int.from_bytes(data[p:p+4], 'little')
            d ^= key2; d ^= key1
            data[p:p+4] = d.to_bytes(4, 'little')
            data[p] = self.ror(data[p], c)
            c = (c + 1) & 0xFF; p += 4

    def try_find_start_position(self, log_cb):
        if not os.path.exists(self.script_path) or not os.path.exists(self.text_path): raise FileNotFoundError("请先选择游戏文件！")
        log_cb("🔍 正在分析文件结构以定位指针...")
        with open(self.script_path, 'rb') as f: SCRIPT = f.read()
        with open(self.text_path, 'rb') as f: TEXT = f.read()
        pos1 = re.search(b'\x00\x00\x00\x00\x00\x00', TEXT)
        if pos1: self.STARTPOSITION2 = pos1.span()[0] - 2; log_cb(f"✅ 找到 TEXT.DAT 数据起始点 (STARTPOSITION2): {hex(self.STARTPOSITION2)}")
        else: log_cb("⚠️ 未能在 TEXT.DAT 中找到 6字节的 null 序列。")

        k = 0; pos3 = [1, 2, 3]; log_cb("⏳ 正在搜索主指针表 (最多 10000 次尝试)...")
        limit = 0
        while len(pos3) != 1:
            limit += 1
            if limit > 10000: raise Exception("自动探测超时。请尝试手动指定指针。")
            target_val = self.STARTPOSITION - k
            Q = re.escape(b'\x00' + struct.pack('L', target_val))
            posQ = list(re.finditer(Q, TEXT))
            if len(posQ) == 1:
                p_val = posQ[0].span()[0] + 1
                p_packed = re.escape(struct.pack('L', p_val))
                pos3 = list(re.finditer(p_packed, SCRIPT))
                if len(pos3) == 1:
                    self.STARTPOSITION3 = pos3[0].span()[0] - 8
                    log_cb(f"🎯 匹配成功! 文本ID: {target_val} -> SCRIPT.SRC 指针表 (STARTPOSITION3): {hex(self.STARTPOSITION3)}")
                    break
                else: pos3 = [1, 2]
            else: pos3 = [1, 2]
            k -= 1
        log_cb("✅ 指针分析完成。")
        return self.STARTPOSITION2, self.STARTPOSITION3

    def action_dump(self, log_cb, prog_cb):
        base = os.path.dirname(self.text_path)
        dst_path = os.path.join(base, 'text.txt')
        scr_path = os.path.join(base, 'script.txt')
        log_cb(f"🚀 开始提取脚本... 起始行ID: {self.STARTPOSITION}")
        
        src = open(self.text_path, 'rb'); dst = open(dst_path, 'w', encoding='utf16')
        ofp = open(self.script_path, 'rb'); dfp = open(scr_path, 'w', encoding='utf16')
        try:
            ofp.seek(self.STARTPOSITION3); src.seek(self.STARTPOSITION2)
            count = self.byte2int(src.read(4))
            for i in range(0, count):
                if i % 500 == 0: prog_cb(int((i/count)*100))
                if i >= self.STARTPOSITION:
                    off = src.tell()
                    while True:
                        read_bytes = ofp.read(4)
                        if not read_bytes: break
                        if self.byte2int(read_bytes) == off:
                            dfp.write("○%08d○%X\n" % (i, ofp.tell() - 4)); break
                num = self.byte2int(src.read(4))
                dst.write(self.format_string(self.dumpstr(src), num))
            prog_cb(100); log_cb(f"✨ 提取完成。已生成文件:\n- {dst_path}\n- {scr_path}")
        finally: src.close(); dst.close(); ofp.close(); dfp.close()
        return dst_path

    def action_pack(self, log_cb, prog_cb):
        base = os.path.dirname(self.text_path)
        text_txt = os.path.join(base, 'text.txt')
        script_txt = os.path.join(base, 'script.txt')
        if not os.path.exists(text_txt): raise FileNotFoundError("text.txt 不存在，无法进行封包。")
        
        dst_path = os.path.join(base, 'TEXT.DAT_NEW'); ofp_path = os.path.join(base, 'SCRIPT.SRC_NEW')
        log_cb(f"📦 开始封包流程..."); src = open(self.text_path, 'rb'); fin = open(text_txt, 'r', encoding='utf16')
        dst = open(dst_path, 'wb'); fp = open(self.script_path, 'rb'); ofp = open(ofp_path, 'wb')
        dfp = open(script_txt, 'r', encoding='utf16')
        try:
            ofp.write(fp.read(os.path.getsize(self.script_path)))
            offset_dict = {}
            for rows in dfp:
                row = rows[1:].rstrip('\r\n').split('○')
                if len(row) >= 2: offset_dict[str(int(row[0]))] = int(row[1], 16)
            src.seek(0); dst.write(src.read(0x10))
            fin.seek(0); all_lines = fin.readlines(); total_lines = len(all_lines); fin.seek(0)
            current_line_idx = 0
            for rows in fin:
                current_line_idx += 1
                if current_line_idx % 1000 == 0: prog_cb(int((current_line_idx/total_lines)*100))
                if not rows.startswith('●'): continue
                row = rows[1:].rstrip('\r\n').split('●')
                if len(row) < 2: continue
                line_id = int(row[0]); line_text = row[1]
                if line_id >= self.STARTPOSITION:
                    if str(line_id) in offset_dict:
                        ofp.seek(offset_dict[str(line_id)]); ofp.write(self.int2byte(dst.tell()))
                line_encoded = line_text.encode(self.encoding_write, errors='ignore')
                dst.write(self.int2byte(line_id)); dst.write(line_encoded); dst.write(struct.pack('B', 0))
            dst.close(); ofp.close()
            log_cb("正在加密新文件...")
            for p in [dst_path, ofp_path]:
                with open(p, 'rb') as f: buff = bytearray(f.read())
                self.encrypt(buff)
                with open(p + '.en', 'wb') as f: f.write(buff)
            prog_cb(100); log_cb(f"🎉 封包完成！已生成加密文件:\n- {dst_path}.en\n- {ofp_path}.en")
        finally: src.close(); fin.close(); fp.close(); dfp.close(); dst.close() if not dst.closed else None; ofp.close() if not ofp.closed else None

    def action_format_script(self, text_file, log_cb, prog_cb, dialogue_starters):
        if not os.path.exists(text_file): raise FileNotFoundError("text.txt 不存在，请先执行提取操作。")
        out_file = text_file.replace('text.txt', 'scenario.txt')
        name_file = text_file.replace('text.txt', 'names.txt')
        limit_end = self.ENDPOSITION if self.ENDPOSITION > 0 else float('inf')
        log_cb(f"📖 正在生成脚本文件... 范围: {self.STARTPOSITION} 到 {'无限制' if limit_end == float('inf') else limit_end}")
        if not dialogue_starters: log_cb("⚠️ 警告: 未选择任何对话起始符，将不会合并人名和对话。")
        starters_tuple = tuple(dialogue_starters)
        with open(text_file, 'r', encoding='utf-16') as f: content = f.read()
        blocks = content.split('\n\n'); lines_data = []
        for blk in blocks:
            t_line = next((l for l in blk.strip().split('\n') if l.startswith('●')), None)
            if not t_line: continue
            parts = t_line.split('●')
            if len(parts) >= 3: 
                rid = int(parts[1])
                if self.STARTPOSITION <= rid <= limit_end:
                    lines_data.append({'id': rid, 'text': parts[2]})
        final_script = []; names_set = set(); i = 0; total = len(lines_data)
        def is_name(t): return len(t) < 15
        while i < total:
            prog_cb(int((i/total)*100))
            curr = lines_data[i]; txt = curr['text']
            if starters_tuple and i + 1 < total:
                nxt = lines_data[i+1]; nxt_txt = nxt['text']
                if self.name_mode == 0:
                    if txt.startswith(starters_tuple) and is_name(nxt_txt):
                        names_set.add(nxt_txt); final_script.append(f"{nxt_txt}\t{txt}"); i += 2; continue
                else: 
                    if is_name(txt) and nxt_txt.startswith(starters_tuple):
                        names_set.add(txt); final_script.append(f"{txt}\t{nxt_txt}"); i += 2; continue
            final_script.append(txt); i += 1
        with open(out_file, 'w', encoding='utf-8') as f: f.write('\n'.join(final_script))
        with open(name_file, 'w', encoding='utf-8') as f: f.write('\n'.join(sorted(list(names_set))))
        prog_cb(100); log_cb(f"✅ 脚本生成完毕。已生成文件:\n- {out_file}\n- {name_file}")

    def action_import_scenario(self, text_file, log_cb, prog_cb):
        scen_file = text_file.replace('text.txt', 'scenario.txt')
        if not os.path.exists(scen_file): raise FileNotFoundError("scenario.txt 不存在，无法导入。")
        log_cb("🔄 正在将翻译脚本导回 text.txt...")
        limit_end = self.ENDPOSITION if self.ENDPOSITION > 0 else float('inf')
        with open(text_file, 'r', encoding='utf-16') as f: lines = f.readlines()
        with open(scen_file, 'r', encoding='utf-8') as f: new_lines = [l.strip() for l in f if l.strip()]
        indices = []
        for i, l in enumerate(lines):
            if l.startswith('●'):
                try:
                    rid = int(l.split('●')[1])
                    if self.STARTPOSITION <= rid <= limit_end: indices.append(i)
                except (IndexError, ValueError): pass
        s_ptr = 0; l_ptr = 0
        while s_ptr < len(new_lines) and l_ptr < len(indices):
            prog_cb(int((s_ptr/len(new_lines))*100))
            new_txt = new_lines[s_ptr]; parts = new_txt.split('\t'); is_merged = len(parts) >= 2
            if is_merged and self.name_mode in [0, 1]:
                name, dialog = parts[0], parts[1]
                if l_ptr + 1 >= len(indices): break
                idx1, idx2 = indices[l_ptr], indices[l_ptr+1]
                h1, h2 = lines[idx1].split('●')[1], lines[idx2].split('●')[1]
                if self.name_mode == 0: lines[idx1] = f"●{h1}●{dialog}\n"; lines[idx2] = f"●{h2}●{name}\n"
                else: lines[idx1] = f"●{h1}●{name}\n"; lines[idx2] = f"●{h2}●{dialog}\n"
                l_ptr += 2
            else:
                idx = indices[l_ptr]; h = lines[idx].split('●')[1]; lines[idx] = f"●{h}●{new_txt}\n"; l_ptr += 1
            s_ptr += 1
        with open(text_file, 'w', encoding='utf-16') as f: f.writelines(lines)
        prog_cb(100); log_cb("✅ 导入完成，text.txt 已更新。")

class Worker(QThread):
    log = pyqtSignal(str); prog = pyqtSignal(int); done = pyqtSignal(str); err = pyqtSignal(str)
    def __init__(self, engine, mode, start, end_line, name_mode, extra_arg=None, encoding='cp936', dialogue_starters=()):
        super().__init__()
        self.e = engine; self.m = mode
        self.e.STARTPOSITION = int(start); self.e.ENDPOSITION = int(end_line)
        self.e.name_mode = name_mode; self.arg = extra_arg; self.e.encoding_write = encoding; self.dialogue_starters = dialogue_starters
    def run(self):
        try:
            res = ""
            if self.m == 'find': self.e.try_find_start_position(self.log.emit)
            elif self.m == 'dump': res = self.e.action_dump(self.log.emit, self.prog.emit)
            elif self.m == 'pack': res = self.e.action_pack(self.log.emit, self.prog.emit)
            elif self.m == 'format': res = self.e.action_format_script(self.arg, self.log.emit, self.prog.emit, self.dialogue_starters)
            elif self.m == 'import': res = self.e.action_import_scenario(self.arg, self.log.emit, self.prog.emit)
            self.done.emit(str(res))
        except Exception as e: self.err.emit(str(e))

# ==========================================
# 主窗口
# ==========================================
class NiflheimApp(QMainWindow):
    EDGE_NONE   = 0; EDGE_LEFT   = 1; EDGE_TOP    = 2
    EDGE_RIGHT  = 4; EDGE_BOTTOM = 8; EDGE_MARGIN = 6

    def __init__(self):
        super().__init__()
        self.engine = GameEngine(); self.settings = QSettings("SoftPalWorkshop", "NiflheimApp")
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint); self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMouseTracking(True); self.resize(1000, 720); self.setMinimumSize(850, 600)
        self.is_dragging = False; self.is_resizing = False; self.resize_edge = self.EDGE_NONE
        self.drag_start_pos = QPoint(); self.old_geometry = QRectF()
        
        self.current_theme_name = "🌊 深海 (Ocean)"
        self.theme = THEMES[self.current_theme_name]

        self.setup_ui(); self.setAcceptDrops(True); self.is_max = False
        self.load_settings(); self.apply_theme(self.current_theme_name)

    def paintEvent(self, event):
        painter = QPainter(self); painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        grad_colors = self.theme["bg_grad"]
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0.0, QColor(grad_colors[0]))
        gradient.setColorAt(0.6, QColor(grad_colors[1]))
        gradient.setColorAt(1.0, QColor(grad_colors[2]))
        path = QPainterPath(); path.addRoundedRect(QRectF(self.rect()), 24, 24); painter.fillPath(path, gradient)
        pen = QPen(QColor(0, 0, 0, 20)); pen.setWidth(1); painter.strokePath(path, pen)

    def setup_ui(self):
        central = QWidget(); self.setCentralWidget(central); central.setMouseTracking(True) 
        main_layout = QVBoxLayout(central); main_layout.setContentsMargins(20, 20, 20, 20); main_layout.setSpacing(15)
        
        # 标题栏
        title_bar = QHBoxLayout()
        self.title_label = QLabel("SoftPal引擎脚本处理工具")
        self.title_label.setFont(QFont("Microsoft YaHei", 12, QFont.Weight.Bold))
        
        self.btn_min = AnimButton("min", self.showMinimized, self); self.btn_max = AnimButton("max", self.toggle_max, self); self.btn_close = AnimButton("close", self.close, self)
        title_bar.addWidget(self.title_label); title_bar.addStretch(); title_bar.addWidget(self.btn_min); title_bar.addWidget(self.btn_max); title_bar.addWidget(self.btn_close)
        main_layout.addLayout(title_bar)
        
        # 内容区域
        content_layout = QHBoxLayout()
        
        # 左侧设置区
        self.left_card = IOSCard()
        left_layout = QVBoxLayout(self.left_card); left_layout.setContentsMargins(25, 25, 25, 25); left_layout.setSpacing(20)
        
        # 主题选择
        theme_layout = QHBoxLayout()
        self.lbl_theme = self.create_label("🎨 界面风格")
        self.combo_theme = QComboBox(); self.combo_theme.addItems(THEMES.keys())
        self.combo_theme.currentTextChanged.connect(self.apply_theme)
        self.combo_theme.setFixedHeight(30); self.combo_theme.setCursor(Qt.CursorShape.PointingHandCursor)
        theme_layout.addWidget(self.lbl_theme); theme_layout.addWidget(self.combo_theme); left_layout.addLayout(theme_layout)
        line = QFrame(); line.setFrameShape(QFrame.Shape.HLine); line.setStyleSheet("background: rgba(0,0,0,0.1);"); left_layout.addWidget(line)

        self.lbl_files = self.create_label("文件设置")
        left_layout.addWidget(self.lbl_files)
        self.in_text = IOSInput("请拖入或选择 TEXT.DAT..."); self.in_script = IOSInput("请拖入或选择 SCRIPT.SRC...")
        self.btn_browse_text = QPushButton("📂"); self.btn_browse_text.setFixedSize(40,40); self.btn_browse_script = QPushButton("📂"); self.btn_browse_script.setFixedSize(40,40)
        left_layout.addLayout(self.create_file_row(self.in_text, self.btn_browse_text)); left_layout.addLayout(self.create_file_row(self.in_script, self.btn_browse_script))
        left_layout.addSpacing(10)
        
        self.lbl_params = self.create_label("高级参数")
        left_layout.addWidget(self.lbl_params)
        param_layout = QHBoxLayout(); self.spin_start = IOSInput(""); self.spin_start.setPlaceholderText("起始ID"); self.spin_end = IOSInput(""); self.spin_end.setPlaceholderText("结束ID (0=全部)")
        self.btn_auto = IOSButton("自动分析指针"); self.btn_auto.clicked.connect(self.do_auto_find)
        param_layout.addWidget(self.spin_start); param_layout.addWidget(self.spin_end); param_layout.addWidget(self.btn_auto); left_layout.addLayout(param_layout)
        
        self.lbl_help = QLabel("起始ID: 从指定的文本行号开始处理。\n结束ID: 生成脚本时的截止行号，0为不限制。"); left_layout.addWidget(self.lbl_help)
        
        enc_layout = QHBoxLayout(); self.lbl_enc = QLabel("封包编码:")
        self.combo_enc = QComboBox(); self.combo_enc.addItems(["cp936 (简体中文)", "cp932 (日文)", "Big5 (繁体中文)", "UTF-8"])
        enc_layout.addWidget(self.lbl_enc); enc_layout.addWidget(self.combo_enc); left_layout.addLayout(enc_layout); left_layout.addStretch()
        
        self.btn_reset = IOSButton("重置所有设置"); self.btn_reset.clicked.connect(self.reset_all); left_layout.addWidget(self.btn_reset)
        
        # 右侧操作区
        self.right_card = IOSCard()
        right_layout = QVBoxLayout(self.right_card); right_layout.setContentsMargins(25, 25, 25, 25)
        self.stack = QStackedWidget()
        
        # 页面1: 提取
        v_dump = QWidget(); l_d = QVBoxLayout(v_dump)
        self.lbl_step1 = QLabel("第一步：提取脚本"); self.lbl_step1.setAlignment(Qt.AlignmentFlag.AlignCenter); self.lbl_step1.setFont(QFont("Microsoft YaHei", 14, QFont.Weight.Bold))
        self.btn_d = IOSButton("开始提取"); self.btn_d.clicked.connect(self.do_dump)
        l_d.addStretch(); l_d.addWidget(self.lbl_step1); l_d.addWidget(self.btn_d); l_d.addStretch()
        
        # 页面2: 格式化
        v_fmt = QWidget(); l_f = QVBoxLayout(v_fmt)
        self.lbl_step2 = QLabel("第二步：处理脚本"); self.lbl_step2.setAlignment(Qt.AlignmentFlag.AlignCenter); self.lbl_step2.setFont(QFont("Microsoft YaHei", 14, QFont.Weight.Bold))
        self.lbl_desc = QLabel("将对话与人名合并为一行，便于翻译。\n请根据游戏原文结构选择正确的人名位置。"); self.lbl_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        quote_box = QWidget(); quote_layout = QHBoxLayout(quote_box); quote_layout.setContentsMargins(0,0,0,0)
        self.lbl_quote = QLabel("对话起始符:")
        self.chk_quote1 = QCheckBox("「"); self.chk_quote2 = QCheckBox("『"); self.chk_quote3 = QCheckBox("（"); self.chk_quote4 = QCheckBox("<s")
        for chk in [self.chk_quote1, self.chk_quote2, self.chk_quote3, self.chk_quote4]: chk.setChecked(True); quote_layout.addWidget(chk)
        quote_layout.insertWidget(0, self.lbl_quote); quote_layout.addStretch()

        self.combo_name_pos = QComboBox(); self.combo_name_pos.addItems(["👤 人名在对话下方", "👤 人名在对话上方"])
        self.btn_f_export = IOSButton("导出未译脚本"); self.btn_f_export.clicked.connect(self.do_format)
        self.btn_f_import = IOSButton("导入已译脚本"); self.btn_f_import.clicked.connect(self.do_import)
        
        l_f.addStretch(); l_f.addWidget(self.lbl_step2); l_f.addWidget(self.lbl_desc); l_f.addSpacing(10)
        l_f.addWidget(quote_box); l_f.addWidget(self.combo_name_pos); l_f.addSpacing(10)
        l_f.addWidget(self.btn_f_export); l_f.addSpacing(10); l_f.addWidget(self.btn_f_import); l_f.addStretch()

        # 页面3: 封包
        v_pack = QWidget(); l_p = QVBoxLayout(v_pack)
        self.lbl_step3 = QLabel("第三步：封包脚本"); self.lbl_step3.setAlignment(Qt.AlignmentFlag.AlignCenter); self.lbl_step3.setFont(QFont("Microsoft YaHei", 14, QFont.Weight.Bold))
        self.btn_p = IOSButton("封包加密"); self.btn_p.clicked.connect(self.do_pack)
        l_p.addStretch(); l_p.addWidget(self.lbl_step3); l_p.addWidget(self.btn_p); l_p.addStretch()
        
        self.stack.addWidget(v_dump); self.stack.addWidget(v_fmt); self.stack.addWidget(v_pack)
        
        # 顶部 Tab 按钮
        self.tab_container = QWidget(); tc_layout = QHBoxLayout(self.tab_container); tc_layout.setContentsMargins(5,5,5,5); tc_layout.setSpacing(5)
        self.btn_tab_d = QPushButton("1. 提取"); self.btn_tab_f = QPushButton("2. 脚本"); self.btn_tab_p = QPushButton("3. 封包")
        self.tabs = [self.btn_tab_d, self.btn_tab_f, self.btn_tab_p]
        for i, b in enumerate(self.tabs): b.setCheckable(True); b.setFixedSize(90, 30); b.clicked.connect(lambda checked, idx=i: self.switch_tab(idx)); tc_layout.addWidget(b)
        
        right_layout.addWidget(self.tab_container, alignment=Qt.AlignmentFlag.AlignCenter)
        right_layout.addWidget(self.stack)
        self.log_area = IOSLog(); right_layout.addWidget(self.log_area)
        self.progress = QProgressBar(); self.progress.setFixedHeight(6); self.progress.setTextVisible(False); right_layout.addWidget(self.progress)
        
        content_layout.addWidget(self.left_card, 45); content_layout.addWidget(self.right_card, 55)
        main_layout.addLayout(content_layout)

    def create_label(self, t): return QLabel(t)
    def create_file_row(self, inp, btn):
        l = QHBoxLayout(); btn.clicked.connect(lambda: self.browse(inp)); l.addWidget(inp); l.addWidget(btn); return l

    # ==================== 主题逻辑 ====================
    def apply_theme(self, theme_name):
        if theme_name not in THEMES: return
        self.current_theme_name = theme_name
        self.theme = THEMES[theme_name]
        t = self.theme
        
        self.update() # 刷新背景
        
        # 文字颜色
        main_labels = [self.title_label, self.lbl_step1, self.lbl_step2, self.lbl_step3]
        dim_labels = [self.lbl_files, self.lbl_params, self.lbl_theme, self.lbl_help, self.lbl_desc, self.lbl_enc, self.lbl_quote]
        
        for l in main_labels: l.setStyleSheet(f"color: {t['text_main']}; padding-left: 5px;")
        for l in dim_labels: l.setStyleSheet(f"color: {t['text_dim']}; font-weight:bold; font-size:12px; font-family:'Microsoft YaHei';")
        
        # 复选框颜色
        chk_style = f"QCheckBox {{ color: {t['text_main']}; spacing: 5px; }}"
        for chk in [self.chk_quote1, self.chk_quote2, self.chk_quote3, self.chk_quote4]: chk.setStyleSheet(chk_style)

        # 按钮与组件
        for btn in [self.btn_min, self.btn_max, self.btn_close]: btn.update_icon_color(t['text_main'])
        
        self.left_card.update_theme(t['card_bg'], t['border'])
        self.right_card.update_theme(t['card_bg'], t['border'])
        
        inputs = [self.in_text, self.in_script, self.spin_start, self.spin_end]
        for i in inputs: i.update_theme(t['input_bg'], t['input_focus'], t['accent'], t['text_main'])
        
        # 小按钮样式
        small_btn_style = f"QPushButton {{background-color: rgba(255,255,255,0.8); color: {t['text_main']}; border-radius: 10px; border: 1px solid {t['accent']}; font-size: 14px;}} QPushButton:hover {{background-color: {t['accent']}; color: white;}}"
        self.btn_browse_text.setStyleSheet(small_btn_style)
        self.btn_browse_script.setStyleSheet(small_btn_style)
        
        # 大按钮
        action_btns = [self.btn_auto, self.btn_reset, self.btn_d, self.btn_f_export, self.btn_f_import, self.btn_p]
        for b in action_btns: b.set_theme_color(t['accent'])
        
        # 组合框
        combo_style = f"""
            QComboBox {{ border: 1px solid rgba(128,128,128,0.3); border-radius: 8px; padding: 1px 10px; background: {t['input_bg']}; color: {t['text_main']}; }}
            QComboBox::drop-down {{ border:none; }}
            QComboBox QAbstractItemView {{ background: {t['card_bg']}; selection-background-color: {t['accent']}; color: {t['text_main']}; }}
        """
        self.combo_theme.setStyleSheet(combo_style)
        self.combo_enc.setStyleSheet(combo_style)
        self.combo_name_pos.setStyleSheet(combo_style)
        
        # Tab 容器背景
        self.tab_container.setStyleSheet(f"background: {t['input_bg']}; border-radius: 15px;")
        self.switch_tab(self.stack.currentIndex()) # 刷新 Tab 样式

        # 日志与进度条
        bg_log = "rgba(255,255,255,0.1)" if "Night" in theme_name else "rgba(0,0,0,0.03)"
        self.log_area.update_theme(t['text_main'], bg_log)
        self.progress.setStyleSheet(f"QProgressBar {{border:none; background:rgba(0,0,0,0.1); border-radius:3px;}} QProgressBar::chunk {{background: {t['accent']}; border-radius:3px;}}")

    def switch_tab(self, idx):
        self.stack.setCurrentIndex(idx)
        t = self.theme
        base = "border:none; border-radius: 12px; font-weight: bold; font-family: 'Microsoft YaHei';"
        active = f"{base} background-color: {t['accent']}; color: white;"
        inactive = f"{base} background-color: transparent; color: {t['text_dim']};"
        for i, b in enumerate(self.tabs): b.setChecked(i == idx); b.setStyleSheet(active if i == idx else inactive)

    # ==================== 业务与交互逻辑 ====================
    def toggle_max(self):
        if self.is_max: self.showNormal(); self.is_max = False
        else: self.showMaximized(); self.is_max = True
    def log(self, m): self.log_area.append(m); self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())
    def browse(self, target_input):
        file, _ = QFileDialog.getOpenFileName(self, "选择游戏文件", "", "数据文件 (TEXT.DAT SCRIPT.SRC);;所有文件 (*.*)"); 
        if file: target_input.setText(file); self.smart_fill(file)
    def smart_fill(self, path):
        d, n = os.path.dirname(path), os.path.basename(path).upper()
        if "TEXT.DAT" in n: target = os.path.join(d, "SCRIPT.SRC"); 
        elif "SCRIPT.SRC" in n: target = os.path.join(d, "TEXT.DAT")
        else: return
        if os.path.exists(target) and not (self.in_script.text() if "TEXT.DAT" in n else self.in_text.text()):
            (self.in_script if "TEXT.DAT" in n else self.in_text).setText(target)   
    def check_files(self):
        if not os.path.exists(self.in_text.text()) or not os.path.exists(self.in_script.text()): self.log("❌ 错误：必需的游戏文件缺失！"); return False
        self.engine.text_path = self.in_text.text(); self.engine.script_path = self.in_script.text(); return True
    def run_worker(self, mode, arg=None):
        if mode not in ['format', 'import'] and not self.check_files(): return
        if (mode == 'format' or mode == 'import') and not self.in_text.text(): self.log("❌ 错误：请先选择 TEXT.DAT"); return
        try: start = int(self.spin_start.text().strip() or '0'); end_line = int(self.spin_end.text().strip() or '0')
        except ValueError: self.log("❌ 错误：“起始/结束ID”无效。请输入数字。"); QMessageBox.warning(self, "输入错误", "ID必须是有效的数字。"); return
        enc = self.combo_enc.currentText().split(' ')[0].lower(); name_mode = self.combo_name_pos.currentIndex()
        starters = []
        if mode == 'format':
            if self.chk_quote1.isChecked(): starters.append("「")
            if self.chk_quote2.isChecked(): starters.append("『")
            if self.chk_quote3.isChecked(): starters.append("（")
            if self.chk_quote4.isChecked(): starters.append("<s")
        self.setEnabled(False); self.progress.setValue(0)
        self.worker = Worker(self.engine, mode, start, end_line, name_mode, arg, enc, dialogue_starters=starters)
        self.worker.log.connect(self.log); self.worker.prog.connect(self.progress.setValue); self.worker.done.connect(self.on_done); self.worker.err.connect(self.on_err); self.worker.start()

    def do_auto_find(self): self.run_worker('find')
    def do_dump(self): self.run_worker('dump')
    def do_pack(self): self.run_worker('pack')
    def do_format(self): txt = os.path.join(os.path.dirname(self.in_text.text()), 'text.txt'); self.run_worker('format', txt)
    def do_import(self): txt = os.path.join(os.path.dirname(self.in_text.text()), 'text.txt'); self.run_worker('import', txt)
    def on_done(self, res): self.setEnabled(True)
    def on_err(self, m): self.setEnabled(True); self.log(f"❌ 发生错误: {m}")
    
    def load_settings(self):
        self.in_text.setText(self.settings.value("text_path", "")); self.in_script.setText(self.settings.value("script_path", ""))
        self.spin_start.setText(self.settings.value("start_line", "0")); self.spin_end.setText(self.settings.value("end_line", "0"))
        self.combo_enc.setCurrentIndex(self.settings.value("encoding_idx", 0, type=int)); self.combo_name_pos.setCurrentIndex(self.settings.value("name_pos_idx", 0, type=int))
        self.current_theme_name = self.settings.value("theme", "🌊 深海 (Ocean)")
        idx = self.combo_theme.findText(self.current_theme_name)
        if idx >= 0: self.combo_theme.setCurrentIndex(idx)
        else: self.combo_theme.setCurrentIndex(0)

    def save_settings(self):
        self.settings.setValue("text_path", self.in_text.text()); self.settings.setValue("script_path", self.in_script.text())
        self.settings.setValue("start_line", self.spin_start.text()); self.settings.setValue("end_line", self.spin_end.text())
        self.settings.setValue("encoding_idx", self.combo_enc.currentIndex()); self.settings.setValue("name_pos_idx", self.combo_name_pos.currentIndex())
        self.settings.setValue("theme", self.current_theme_name)
    
    def reset_all(self):
        self.in_text.clear(); self.in_script.clear(); self.spin_start.setText("0"); self.spin_end.setText("0")
        self.combo_enc.setCurrentIndex(0); self.combo_name_pos.setCurrentIndex(0); self.log_area.clear(); self.progress.setValue(0)
        self.log("🧹 已重置。")

    def closeEvent(self, event: QCloseEvent): self.save_settings(); event.accept()

    def _calc_cursor_pos(self, p):
        r = self.rect(); m = self.EDGE_MARGIN; edge = self.EDGE_NONE
        if p.x() <= m: edge |= self.EDGE_LEFT
        if p.x() >= r.width() - m: edge |= self.EDGE_RIGHT
        if p.y() <= m: edge |= self.EDGE_TOP
        if p.y() >= r.height() - m: edge |= self.EDGE_BOTTOM
        return edge

    def _set_cursor_shape(self, edge):
        if edge == self.EDGE_LEFT | self.EDGE_TOP or edge == self.EDGE_RIGHT | self.EDGE_BOTTOM: self.setCursor(Qt.CursorShape.SizeFDiagCursor)
        elif edge == self.EDGE_RIGHT | self.EDGE_TOP or edge == self.EDGE_LEFT | self.EDGE_BOTTOM: self.setCursor(Qt.CursorShape.SizeBDiagCursor)
        elif edge & self.EDGE_LEFT or edge & self.EDGE_RIGHT: self.setCursor(Qt.CursorShape.SizeHorCursor)
        elif edge & self.EDGE_TOP or edge & self.EDGE_BOTTOM: self.setCursor(Qt.CursorShape.SizeVerCursor)
        else: self.setCursor(Qt.CursorShape.ArrowCursor)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            edge = self._calc_cursor_pos(e.position().toPoint())
            if edge != self.EDGE_NONE: self.is_resizing = True; self.resize_edge = edge; self.drag_start_pos = e.globalPosition().toPoint(); self.old_geometry = QRectF(self.geometry())
            else: self.is_dragging = True; self.drag_start_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()
            e.accept()

    def mouseMoveEvent(self, e):
        if self.is_resizing:
            delta = e.globalPosition().toPoint() - self.drag_start_pos; new_geo = self.old_geometry.toRect()
            if self.resize_edge & self.EDGE_LEFT: new_geo.setLeft(new_geo.left() + delta.x())
            if self.resize_edge & self.EDGE_RIGHT: new_geo.setRight(new_geo.right() + delta.x())
            if self.resize_edge & self.EDGE_TOP: new_geo.setTop(new_geo.top() + delta.y())
            if self.resize_edge & self.EDGE_BOTTOM: new_geo.setBottom(new_geo.bottom() + delta.y())
            if new_geo.width() < self.minimumWidth():
                if self.resize_edge & self.EDGE_LEFT: new_geo.setLeft(new_geo.right() - self.minimumWidth())
                else: new_geo.setRight(new_geo.left() + self.minimumWidth())
            if new_geo.height() < self.minimumHeight():
                if self.resize_edge & self.EDGE_TOP: new_geo.setTop(new_geo.bottom() - self.minimumHeight())
                else: new_geo.setBottom(new_geo.top() + self.minimumHeight())
            self.setGeometry(new_geo); e.accept()
        elif self.is_dragging: self.move(e.globalPosition().toPoint() - self.drag_start_pos); e.accept()
        else: self._set_cursor_shape(self._calc_cursor_pos(e.position().toPoint()))
            
    def mouseReleaseEvent(self, e):
        self.is_dragging = False; self.is_resizing = False; self.resize_edge = self.EDGE_NONE; self.setCursor(Qt.CursorShape.ArrowCursor)

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls(): e.acceptProposedAction()
    def dropEvent(self, e: QDropEvent):
        for u in e.mimeData().urls():
            p = u.toLocalFile()
            if "TEXT.DAT" in p.upper(): self.in_text.setText(p); self.smart_fill(p)
            elif "SCRIPT.SRC" in p.upper(): self.in_script.setText(p); self.smart_fill(p)

if __name__ == "__main__":
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    app = QApplication(sys.argv)
    font = QFont("Microsoft YaHei", 10); font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias); app.setFont(font)
    w = NiflheimApp(); w.show(); sys.exit(app.exec())
