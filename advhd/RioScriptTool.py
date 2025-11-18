# -*- coding: utf-8 -*-
import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                             QTextEdit, QProgressBar, QRadioButton, QButtonGroup,
                             QLineEdit, QMessageBox, QGraphicsDropShadowEffect, 
                             QFrame, QComboBox)
from PyQt6.QtCore import (Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve, 
                          QPoint, QRectF, pyqtProperty)
from PyQt6.QtGui import (QFont, QDragEnterEvent, QDropEvent, QColor, QPainter, 
                         QPainterPath, QPen, QLinearGradient)

# ==========================================
# 配色方案配置
# ==========================================
THEMES = {
    "🌸 樱花 (Sakura)": {
        "bg_grad": ["#Fce4ec", "#F3E5F5", "#E1BEE7"], # 背景渐变起/中/止
        "accent": "#ff80ab",                          # 主要强调色
        "btn_hover": "#ff4081",                       # 按钮悬停色
        "text_main": "#333333",                       # 主要文字色
        "text_dim": "#555555",                        # 次要文字色
        "card_bg": "rgba(255, 255, 255, 0.65)",       # 卡片背景
        "input_bg": "rgba(255,255,255,0.5)",          # 输入框背景
        "input_focus": "rgba(255,255,255,0.9)",       # 输入框聚焦背景
        "border": "rgba(255, 255, 255, 0.8)"          # 边框色
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
        "bg_grad": ["#232526", "#414345", "#232526"], # 深色渐变
        "accent": "#BB86FC",                          # 紫色霓虹
        "btn_hover": "#985EFF",
        "text_main": "#E0E0E0",                       # 浅色文字
        "text_dim": "#B0B0B0",
        "card_bg": "rgba(30, 30, 30, 0.75)",          # 深色半透明卡片
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
# 核心逻辑 (保持不变)
# ==========================================
class CryptoWorker(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(str)

    def __init__(self, mode, input_path, output_path):
        super().__init__()
        self.mode = mode
        self.input_path = input_path
        self.output_path = output_path
        self.is_running = True

    def run(self):
        try:
            if os.path.isdir(self.input_path):
                self.process_folder()
            elif os.path.isfile(self.input_path):
                self.process_file(self.input_path, self.output_path)
            self.finished_signal.emit("搞定啦！所有任务都完成咯~")
        except Exception as e:
            self.log_signal.emit(f"呜呜，出错了... {str(e)}")
            self.finished_signal.emit("任务失败惹...")

    def process_file(self, in_path, out_path):
        if not self.is_running: return
        try:
            self.log_signal.emit(f"正在处理: {os.path.basename(in_path)} ...")
            with open(in_path, 'rb') as infile:
                data = infile.read()
            
            result = bytearray()
            if self.mode == 'decrypt':
                for b in data: result.append(((b << 6) & 0xFF) | (b >> 2))
            else:
                for b in data: result.append(((b << 2) & 0xFF) | (b >> 6))
            
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'wb') as outfile:
                outfile.write(result)
            
            self.progress_signal.emit(100)
        except Exception as e:
            self.log_signal.emit(f"  [失败] {os.path.basename(in_path)}: {str(e)}")

    def process_folder(self):
        files = [f for f in os.listdir(self.input_path) if f.endswith(('.ws2', '.wsc'))]
        total = len(files)
        if total == 0:
            self.log_signal.emit("诶？文件夹里没有找到脚本文件哦...")
            return
        
        self.log_signal.emit(f"发现 {total} 个文件，开始努力干活！")
        for i, f in enumerate(files):
            if not self.is_running: break
            self.process_file(os.path.join(self.input_path, f), os.path.join(self.output_path, f))
            self.progress_signal.emit(int(((i + 1) / total) * 100))

# ==========================================
# UI 组件 (增强版，支持动态换色)
# ==========================================
class AnimButton(QPushButton):
    """窗口控制按钮 (最小化/最大化/关闭)"""
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
        # 默认深色图标
        self.icon_color_idle = QColor(0, 0, 0)
        self.icon_color_hover = QColor(0, 0, 0)

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

    def update_icon_color(self, color_hex):
        self.icon_color_idle = QColor(color_hex)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self.btn_type == "close":
            bg_col = QColor(232, 17, 35, int(255 * self._hover_progress))
            icon_col = self.icon_color_idle if self._hover_progress < 0.5 else QColor(255, 255, 255)
        else:
            bg_col = QColor(0, 0, 0, int(20 * self._hover_progress))
            icon_col = self.icon_color_idle
        
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
    """普通功能按钮"""
    def __init__(self, text, color="#007AFF", parent=None):
        super().__init__(text, parent)
        self.base_color = color
        self.setFont(QFont("Microsoft YaHei", 10, QFont.Weight.Bold))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(45)
        self._anim = QPropertyAnimation(self, b"geometry")
        self._anim.setDuration(100)
        self._anim.setEasingCurve(QEasingCurve.Type.OutQuad)
        self.shadow = QGraphicsDropShadowEffect()
        self.shadow.setBlurRadius(15)
        self.shadow.setColor(QColor(0,0,0,40))
        self.shadow.setOffset(0, 4)
        self.setGraphicsEffect(self.shadow)
        self.update_style()

    def set_theme_color(self, color):
        self.base_color = color
        self.update_style()

    def update_style(self, pressed=False):
        hover_color = QColor(self.base_color).lighter(110).name()
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {self.base_color}; 
                color: white; 
                border-radius: 12px; 
                border: none; 
                padding: 10px; 
                font-family: 'Microsoft YaHei';
            }} 
            QPushButton:hover {{
                background-color: {hover_color};
            }}
        """)
    
    def enterEvent(self, e): self.shadow.setBlurRadius(25); self.shadow.setOffset(0, 6); super().enterEvent(e)
    def leaveEvent(self, e): self.shadow.setBlurRadius(15); self.shadow.setOffset(0, 4); super().leaveEvent(e)
    def mousePressEvent(self, e): self.update_style(True); super().mousePressEvent(e)
    def mouseReleaseEvent(self, e): self.update_style(False); super().mouseReleaseEvent(e)

class FileButton(QPushButton):
    """文件选择的小按钮"""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFixedSize(40, 40)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
    
    def set_theme(self, accent_color, text_color):
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: rgba(255,255,255,0.8); 
                color: {text_color}; 
                border-radius: 10px; 
                border: 1px solid {accent_color}; 
                font-size: 14px;
            }} 
            QPushButton:hover {{
                background-color: {accent_color};
                color: white;
            }}
        """)

class IOSCard(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("IOSCard {background-color: rgba(255, 255, 255, 0.65); border-radius: 20px; border: 1px solid rgba(255, 255, 255, 0.8);}")
        s = QGraphicsDropShadowEffect()
        s.setBlurRadius(30)
        s.setColor(QColor(0,0,0,20))
        s.setOffset(0,8)
        self.setGraphicsEffect(s)
    
    def update_theme(self, bg_col, border_col):
        self.setStyleSheet(f"IOSCard {{background-color: {bg_col}; border-radius: 20px; border: 1px solid {border_col};}}")

class IOSInput(QLineEdit):
    def __init__(self, ph, parent=None):
        super().__init__(parent)
        self.setPlaceholderText(ph)
        self.setFixedHeight(40)
    
    def update_theme(self, bg, focus_bg, accent, text_col):
        self.setStyleSheet(f"""
            QLineEdit {{
                background-color: {bg}; 
                border: 1px solid rgba(128,128,128,0.2); 
                border-radius: 10px; 
                padding: 0 15px; 
                font-size: 13px; 
                color: {text_col};
            }} 
            QLineEdit:focus {{
                border: 1px solid {accent}; 
                background-color: {focus_bg};
            }}
        """)

class IOSLog(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setStyleSheet("QTextEdit {background-color: rgba(0,0,0,0.03); border: none; border-radius: 15px; padding: 15px; font-family: 'Consolas'; font-size: 12px; color: #333;}")
    
    def update_theme(self, text_col, bg_col):
         self.setStyleSheet(f"QTextEdit {{background-color: {bg_col}; border: none; border-radius: 15px; padding: 15px; font-family: 'Consolas'; font-size: 12px; color: {text_col};}}")

# ==========================================
# 新主窗口
# ==========================================
class RioApp(QMainWindow):
    EDGE_NONE   = 0; EDGE_LEFT   = 1; EDGE_TOP    = 2
    EDGE_RIGHT  = 4; EDGE_BOTTOM = 8; EDGE_MARGIN = 6

    def __init__(self):
        super().__init__()
        self.setWindowTitle("WS2 脚本工具")
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMouseTracking(True)
        self.resize(850, 580)
        self.setMinimumSize(750, 480)
        
        self.current_theme_name = "🌸 樱花 (Sakura)"
        self.theme = THEMES[self.current_theme_name]

        # 窗口拖拽变量
        self.is_dragging = False; self.is_resizing = False; self.resize_edge = self.EDGE_NONE
        self.drag_start_pos = QPoint(); self.old_geometry = QRectF()
        self.is_max = False

        self.setup_ui()
        self.setAcceptDrops(True) 
        self.apply_theme(self.current_theme_name) # 初始化应用主题

    def paintEvent(self, event):
        # 根据当前主题绘制背景
        painter = QPainter(self); painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        grad_colors = self.theme["bg_grad"]
        gradient = QLinearGradient(0, 0, self.width(), self.height())
        gradient.setColorAt(0.0, QColor(grad_colors[0]))
        gradient.setColorAt(0.6, QColor(grad_colors[1]))
        gradient.setColorAt(1.0, QColor(grad_colors[2]))
        
        path = QPainterPath(); path.addRoundedRect(QRectF(self.rect()), 24, 24)
        painter.fillPath(path, gradient)
        
        # 边框稍微深一点
        pen = QPen(QColor(0, 0, 0, 30)); pen.setWidth(1)
        painter.strokePath(path, pen)

    def setup_ui(self):
        central = QWidget(); self.setCentralWidget(central); central.setMouseTracking(True)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(20, 20, 20, 20); main_layout.setSpacing(15)

        # 1. 标题栏
        title_bar = QHBoxLayout()
        self.title_label = QLabel("WS2 脚本魔法工坊 ✨")
        self.title_label.setFont(QFont("Microsoft YaHei", 12, QFont.Weight.Bold))
        self.title_label.setStyleSheet("padding-left: 10px;")
        
        self.btn_min = AnimButton("min", self.showMinimized, self)
        self.btn_max = AnimButton("max", self.toggle_max, self)
        self.btn_close = AnimButton("close", self.close, self)
        
        title_bar.addWidget(self.title_label)
        title_bar.addStretch()
        title_bar.addWidget(self.btn_min)
        title_bar.addWidget(self.btn_max)
        title_bar.addWidget(self.btn_close)
        main_layout.addLayout(title_bar)

        # 2. 内容区域 (左右布局)
        content_layout = QHBoxLayout()

        # --- 左侧：设置区域 ---
        self.left_card = IOSCard()
        left_layout = QVBoxLayout(self.left_card)
        left_layout.setContentsMargins(25, 25, 25, 25); left_layout.setSpacing(20)

        # 主题选择
        theme_layout = QHBoxLayout()
        self.lbl_theme = self.create_label("🎨 界面风格")
        self.combo_theme = QComboBox()
        self.combo_theme.addItems(THEMES.keys())
        self.combo_theme.currentTextChanged.connect(self.apply_theme)
        self.combo_theme.setFixedHeight(30)
        self.combo_theme.setCursor(Qt.CursorShape.PointingHandCursor)
        theme_layout.addWidget(self.lbl_theme)
        theme_layout.addWidget(self.combo_theme)
        left_layout.addLayout(theme_layout)
        
        line = QFrame(); line.setFrameShape(QFrame.Shape.HLine); line.setStyleSheet("background: rgba(0,0,0,0.1);")
        left_layout.addWidget(line)

        self.lbl_input = self.create_label("输入文件")
        left_layout.addWidget(self.lbl_input)
        self.input_edit = IOSInput("请拖入 .ws2/.wsc 文件或文件夹...")
        self.btn_browse_in = FileButton("📂")
        left_layout.addLayout(self.create_file_row(self.input_edit, self.btn_browse_in, self.browse_input))

        self.lbl_output = self.create_label("输出位置")
        left_layout.addWidget(self.lbl_output)
        self.output_edit = IOSInput("生成的文件存放于...")
        self.btn_browse_out = FileButton("📂")
        left_layout.addLayout(self.create_file_row(self.output_edit, self.btn_browse_out, self.browse_output))

        self.lbl_mode = self.create_label("魔法类型")
        left_layout.addWidget(self.lbl_mode)
        
        # 模式选择
        mode_layout = QHBoxLayout()
        self.mode_group = QButtonGroup()
        self.rad_decrypt = QRadioButton("🔓 解密 (Decrypt)")
        self.rad_encrypt = QRadioButton("🔒 加密 (Encrypt)")
        self.rad_decrypt.setChecked(True)
        self.mode_group.addButton(self.rad_decrypt)
        self.mode_group.addButton(self.rad_encrypt)
        self.rad_decrypt.toggled.connect(lambda: self.auto_output(self.input_edit.text()))
        self.rad_encrypt.toggled.connect(lambda: self.auto_output(self.input_edit.text()))

        mode_layout.addWidget(self.rad_decrypt)
        mode_layout.addWidget(self.rad_encrypt)
        mode_layout.addStretch()
        left_layout.addLayout(mode_layout)
        left_layout.addStretch()
        
        # --- 右侧：执行与日志 ---
        self.right_card = IOSCard()
        right_layout = QVBoxLayout(self.right_card)
        right_layout.setContentsMargins(25, 25, 25, 25); right_layout.setSpacing(15)

        self.start_btn = IOSButton("★ 开始施法 ★")
        self.start_btn.setMinimumHeight(60)
        self.start_btn.clicked.connect(self.start_task)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setTextVisible(False)
        
        self.log_box = IOSLog()
        
        right_layout.addWidget(self.start_btn)
        right_layout.addWidget(self.progress_bar)
        right_layout.addWidget(self.log_box)

        content_layout.addWidget(self.left_card, 45)
        content_layout.addWidget(self.right_card, 55)
        main_layout.addLayout(content_layout)

        self.log("欢迎光临！请投喂 .ws2 文件开始工作喵~ (o゜▽゜)o☆")

    def create_label(self, t):
        l = QLabel(t)
        l.setFont(QFont("Microsoft YaHei", 10, QFont.Weight.Bold))
        return l

    def create_file_row(self, inp_widget, btn, func):
        l = QHBoxLayout()
        btn.clicked.connect(func)
        l.addWidget(inp_widget)
        l.addWidget(btn)
        return l
    
    # ==================== 主题切换逻辑 ====================
    def apply_theme(self, theme_name):
        if theme_name not in THEMES: return
        self.current_theme_name = theme_name
        self.theme = THEMES[theme_name]
        t = self.theme
        
        # 1. 刷新窗口背景 (paintEvent)
        self.update()
        
        # 2. 文字颜色
        self.title_label.setStyleSheet(f"color: {t['text_main']}; padding-left: 10px;")
        labels = [self.lbl_input, self.lbl_output, self.lbl_mode, self.lbl_theme]
        for l in labels:
            l.setStyleSheet(f"color: {t['text_dim']}; font-weight:bold; font-size:13px; letter-spacing:1px;")

        # 3. 窗口控制按钮图标颜色
        for btn in [self.btn_min, self.btn_max, self.btn_close]:
            btn.update_icon_color(t['text_main'])
            
        # 4. 卡片样式
        self.left_card.update_theme(t['card_bg'], t['border'])
        self.right_card.update_theme(t['card_bg'], t['border'])
        
        # 5. 输入框样式
        self.input_edit.update_theme(t['input_bg'], t['input_focus'], t['accent'], t['text_main'])
        self.output_edit.update_theme(t['input_bg'], t['input_focus'], t['accent'], t['text_main'])
        
        # 6. 文件选择小按钮
        self.btn_browse_in.set_theme(t['accent'], t['text_main'])
        self.btn_browse_out.set_theme(t['accent'], t['text_main'])
        
        # 7. 单选框样式
        radio_style = f"""
            QRadioButton {{ font-family: 'Microsoft YaHei'; font-size: 13px; color: {t['text_dim']}; spacing: 8px; }}
            QRadioButton::indicator {{ width: 16px; height: 16px; border-radius: 9px; border: 2px solid {t['text_dim']}; background: {t['input_bg']}; }}
            QRadioButton::indicator:checked {{ border-color: {t['accent']}; background: {t['accent']}; }}
        """
        self.rad_decrypt.setStyleSheet(radio_style)
        self.rad_encrypt.setStyleSheet(radio_style)
        
        # 8. 下拉框样式
        self.combo_theme.setStyleSheet(f"""
            QComboBox {{
                border: 1px solid rgba(128,128,128,0.3); border-radius: 8px; padding: 1px 10px;
                background: {t['input_bg']}; color: {t['text_main']};
            }}
            QComboBox::drop-down {{ border:none; }}
            QComboBox QAbstractItemView {{
                background: {t['card_bg']}; selection-background-color: {t['accent']}; color: {t['text_main']};
            }}
        """)

        # 9. 启动大按钮
        self.start_btn.set_theme_color(t['accent'])
        
        # 10. 进度条
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{border:none; background:rgba(0,0,0,0.1); border-radius:4px;}} 
            QProgressBar::chunk {{background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {t['accent']}, stop:1 {t['btn_hover']}); border-radius:4px;}}
        """)
        
        # 11. 日志框
        bg_log = "rgba(255,255,255,0.1)" if "Night" in theme_name else "rgba(0,0,0,0.03)"
        self.log_box.update_theme(t['text_main'], bg_log)

    # ==================== 其他逻辑保持不变 ====================
    def toggle_max(self):
        if self.is_max: self.showNormal(); self.is_max = False
        else: self.showMaximized(); self.is_max = True

    def log(self, msg):
        self.log_box.append(msg)
        self.log_box.verticalScrollBar().setValue(self.log_box.verticalScrollBar().maximum())

    def browse_input(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("选择")
        msg.setText("请问主人是要处理单个文件还是整个文件夹呢？")
        t = self.theme
        msg.setStyleSheet(f"""
            QMessageBox {{background-color: #fefefe;}} 
            QLabel{{color:{t['text_main']}; font-weight:bold; font-family:'Microsoft YaHei';}} 
            QPushButton{{background:#fff; color:#333; border:1px solid {t['accent']}; border-radius:5px; padding:5px 15px; min-width:60px;}}
            QPushButton:hover{{background:{t['accent']}; color:white;}}
        """)
        b_file = msg.addButton("📄 单个文件", QMessageBox.ButtonRole.AcceptRole)
        b_folder = msg.addButton("📁 文件夹", QMessageBox.ButtonRole.AcceptRole)
        msg.exec()
        
        path = ""
        if msg.clickedButton() == b_file:
            path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "Script (*.ws2 *.wsc);;All (*.*)")
        elif msg.clickedButton() == b_folder:
            path = QFileDialog.getExistingDirectory(self, "选择文件夹")
        
        if path:
            self.input_edit.setText(path)
            self.auto_output(path)

    def browse_output(self):
        path = QFileDialog.getExistingDirectory(self, "选择输出文件夹")
        if path: self.output_edit.setText(path)

    def auto_output(self, in_path):
        if not in_path: return
        if self.rad_decrypt.isChecked(): suffix = "_dec"
        else: suffix = "_enc"

        if os.path.isdir(in_path):
            clean_path = in_path.rstrip(os.sep).rstrip('/')
            self.output_edit.setText(clean_path + suffix)
        else:
            d, n = os.path.split(in_path)
            name, ext = os.path.splitext(n)
            self.output_edit.setText(os.path.join(d, f"{name}{suffix}{ext}"))

    def start_task(self):
        inp = self.input_edit.text()
        outp = self.output_edit.text()
        
        if not inp or not os.path.exists(inp):
            self.log("QAQ 找不到输入文件，请检查路径！")
            return
        if not outp:
            self.log("QAQ 请告诉我要输出到哪里！")
            return

        mode = 'decrypt' if self.rad_decrypt.isChecked() else 'encrypt'
        self.worker = CryptoWorker(mode, inp, outp)
        self.worker.log_signal.connect(self.log)
        self.worker.progress_signal.connect(self.progress_bar.setValue)
        self.worker.finished_signal.connect(self.on_finish)
        
        self.start_btn.setEnabled(False)
        self.start_btn.setText("✨ 施法中... ✨")
        self.log_box.clear()
        self.log(f">>> 魔法阵启动！当前模式：{mode}")
        self.worker.start()

    def on_finish(self, msg):
        self.log(msg)
        self.start_btn.setEnabled(True)
        self.start_btn.setText("★ 开始施法 ★")
        self.progress_bar.setValue(100)

    # ==================== 窗口拖拽与缩放 ====================
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls(): event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        path = event.mimeData().urls()[0].toLocalFile()
        self.input_edit.setText(path)
        self.auto_output(path)
        self.log(f"已捕获路径: {path}")

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
        self.is_dragging = False; self.is_resizing = False
        self.resize_edge = self.EDGE_NONE
        self.setCursor(Qt.CursorShape.ArrowCursor)

if __name__ == "__main__":
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    app = QApplication(sys.argv)
    font = QFont("Microsoft YaHei", 10)
    app.setFont(font)
    
    w = RioApp()
    w.show()
    sys.exit(app.exec())
