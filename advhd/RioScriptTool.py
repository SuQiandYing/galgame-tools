# -*- coding: utf-8 -*-
import sys
import os
import time
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                             QTextEdit, QProgressBar, QRadioButton, QButtonGroup,
                             QGroupBox, QFormLayout, QLineEdit, QMessageBox, QGraphicsOpacityEffect)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QDragEnterEvent, QDropEvent, QPalette, QBrush, QPixmap

# ==========================================
# 核心逻辑
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
            self.finished_signal.emit("搞定啦！所有任务都完成咯~ (≧∇≦)ﾉ")
        except Exception as e:
            self.log_signal.emit(f"呜呜，出错了... {str(e)}")
            self.finished_signal.emit("任务失败惹... (T_T)")

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
# 萌系 GUI 主窗口
# ==========================================
class AnimeWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WS2 魔法工坊 ✨")
        self.resize(800, 600)
        self.setAcceptDrops(True)
        
        self.setup_background()
        self.setup_ui()
        self.apply_anime_style()

    def setup_background(self):
        # 优先加载 bg.png，否则用渐变
        bg_path = "bg.png" 
        if os.path.exists(bg_path):
            oImage = QPixmap(bg_path)
            oImage = oImage.scaled(self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding, Qt.TransformationMode.SmoothTransformation)
            palette = QPalette()
            palette.setBrush(QPalette.ColorRole.Window, QBrush(oImage))
            self.setPalette(palette)
        else:
            self.setStyleSheet("QMainWindow { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #fce4ec, stop:1 #e1bee7); }")

    def apply_anime_style(self):
        # 定义颜色变量
        COLOR_PRIMARY = "#ff80ab"  # 樱花粉
        COLOR_HOVER = "#ff4081"    # 深粉红
        COLOR_BG_SEMI = "rgba(255, 255, 255, 0.85)"
        
        self.central_widget.setStyleSheet(f"""
            QWidget {{
                font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
                font-size: 14px;
                color: #4a4a4a; 
            }}
            QGroupBox {{
                background-color: {COLOR_BG_SEMI};
                border: 2px solid #fff;
                border-radius: 15px;
                margin-top: 20px;
                font-weight: bold;
                color: {COLOR_HOVER};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 5px 10px;
                background-color: #fff;
                border-radius: 10px;
                color: {COLOR_HOVER};
            }}
            QLineEdit {{
                background-color: rgba(255, 255, 255, 0.9);
                border: 2px solid #f8bbd0;
                border-radius: 10px;
                padding: 8px 12px;
                color: #555;
                font-weight: 500;
            }}
            QLineEdit:focus {{
                border: 2px solid {COLOR_PRIMARY};
            }}
            QPushButton {{
                background-color: #fff;
                border: 2px solid {COLOR_PRIMARY};
                border-radius: 12px;
                color: {COLOR_HOVER};
                padding: 6px 15px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_PRIMARY};
                color: #fff;
            }}
            QPushButton#BigBtn {{
                background-color: {COLOR_PRIMARY};
                color: white;
                border: none;
                border-radius: 20px;
                font-size: 18px;
                padding: 10px;
            }}
            QPushButton#BigBtn:hover {{
                background-color: {COLOR_HOVER};
                padding-bottom: 8px;
            }}
            QTextEdit {{
                background-color: rgba(255, 255, 255, 0.7);
                border: 2px dashed {COLOR_PRIMARY};
                border-radius: 10px;
                font-family: "Consolas";
                color: #333;
                padding: 10px;
            }}
            QProgressBar {{
                border: 2px solid #fff;
                border-radius: 8px;
                background-color: rgba(255, 255, 255, 0.6);
                text-align: center;
                color: {COLOR_HOVER};
                font-weight: bold;
            }}
            QProgressBar::chunk {{
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f8bbd0, stop:1 {COLOR_HOVER});
                border-radius: 6px;
            }}
            QLabel {{
                font-weight: bold;
                color: #333; 
                background-color: transparent;
            }}
            QLabel#Title {{
                color: #fff;
                font-size: 28px;
                font-family: "Comic Sans MS", "Microsoft YaHei";
                qproperty-alignment: AlignCenter;
            }}
        """)

    def setup_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        main_layout = QVBoxLayout(self.central_widget)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(40, 30, 40, 30)

        # 1. 标题
        title_lbl = QLabel("✨ WS2 脚本魔法工坊 ✨")
        title_lbl.setObjectName("Title")
        title_bg = QWidget()
        title_bg.setStyleSheet("background-color: rgba(255, 128, 171, 0.8); border-radius: 15px; padding: 5px;")
        title_layout = QVBoxLayout(title_bg)
        title_layout.addWidget(title_lbl)
        main_layout.addWidget(title_bg)

        # 2. 设置面板
        settings_group = QGroupBox("✧ 魔法配置 ✧")
        form_layout = QFormLayout()
        form_layout.setVerticalSpacing(15)
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        # 输入
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("把 .ws2 文件或者文件夹拖进来哟~")
        self.input_edit.setReadOnly(True)
        input_btn = QPushButton("📂 选择...")
        input_btn.clicked.connect(self.browse_input)
        
        row1 = QHBoxLayout()
        row1.addWidget(self.input_edit)
        row1.addWidget(input_btn)

        # 输出
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("魔法生成的地方...")
        output_btn = QPushButton("📂 更改...")
        output_btn.clicked.connect(self.browse_output)
        
        row2 = QHBoxLayout()
        row2.addWidget(self.output_edit)
        row2.addWidget(output_btn)

        # 模式
        mode_layout = QHBoxLayout()
        self.mode_group = QButtonGroup()
        self.rad_decrypt = QRadioButton("🔓 解密 (Decrypt)")
        self.rad_encrypt = QRadioButton("🔒 加密 (Encrypt)")
        self.rad_decrypt.setChecked(True) # 默认解密
        self.mode_group.addButton(self.rad_decrypt)
        self.mode_group.addButton(self.rad_encrypt)
        
        # 【关键修改】切换模式时，实时更新输出路径
        self.rad_decrypt.toggled.connect(lambda: self.auto_output(self.input_edit.text()))
        self.rad_encrypt.toggled.connect(lambda: self.auto_output(self.input_edit.text()))

        mode_layout.addWidget(self.rad_decrypt)
        mode_layout.addWidget(self.rad_encrypt)
        mode_layout.addStretch()

        lbl_in = QLabel("魔法素材:")
        lbl_out = QLabel("生成位置:")
        lbl_mode = QLabel("魔法类型:")
        
        form_layout.addRow(lbl_in, row1)
        form_layout.addRow(lbl_out, row2)
        form_layout.addRow(lbl_mode, mode_layout)
        settings_group.setLayout(form_layout)
        main_layout.addWidget(settings_group)

        # 3. 启动按钮
        self.start_btn = QPushButton("★ 开始施法 ★")
        self.start_btn.setObjectName("BigBtn")
        self.start_btn.setMinimumHeight(60)
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_btn.clicked.connect(self.start_task)
        main_layout.addWidget(self.start_btn)

        # 4. 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(16)
        main_layout.addWidget(self.progress_bar)

        # 5. 日志
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        main_layout.addWidget(self.log_box)
        
        self.log("欢迎光临！请投喂文件开始工作喵~ (o゜▽゜)o☆")

    # ==================== 功能逻辑 ====================
    def log(self, msg):
        self.log_box.append(msg)
        self.log_box.verticalScrollBar().setValue(self.log_box.verticalScrollBar().maximum())

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls(): event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        path = event.mimeData().urls()[0].toLocalFile()
        self.input_edit.setText(path)
        self.auto_output(path)
        self.log(f"已捕获路径: {path}")

    def browse_input(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("选择")
        msg.setText("请问主人是要处理单个文件还是整个文件夹呢？")
        msg.setStyleSheet("QLabel{color:#333; font-weight:bold;} QPushButton{background:#fff; border:1px solid #ff80ab; padding:5px;}")
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
        """
        根据输入路径和当前模式（解密/加密）自动生成带后缀的输出路径
        """
        if not in_path: return

        # 根据单选框状态决定后缀
        if self.rad_decrypt.isChecked():
            suffix = "_dec"  # 解密后缀
        else:
            suffix = "_enc"  # 加密后缀

        if os.path.isdir(in_path):
            # 文件夹模式: InputFolder -> InputFolder_dec
            # 去除可能存在的末尾斜杠，避免路径错误
            clean_path = in_path.rstrip(os.sep).rstrip('/')
            self.output_edit.setText(clean_path + suffix)
        else:
            # 文件模式: script.ws2 -> script_dec.ws2
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
        QMessageBox.information(self, "完成", msg)

if __name__ == "__main__":
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    app = QApplication(sys.argv)
    font = QFont("Microsoft YaHei", 10)
    app.setFont(font)
    
    w = AnimeWindow()
    w.show()
    sys.exit(app.exec())