import os
import shutil
import threading
import time
import subprocess
import re
from pathlib import Path

class KeyFinderManager:
    def __init__(self, base_dir, log_queue, status_cb, log_cb, process_cb=None):
        self.base_dir = base_dir
        self.log_queue = log_queue
        self.status_cb = status_cb
        self.log_cb = log_cb
        self.process_cb = process_cb  # Used to track if a process is running

    def clean_game_key_files(self, game_exe):
        if not game_exe:
            return False, "请先选择游戏 EXE"

        game_dir = Path(game_exe).parent
        target_files = ["key.bin", "key_def.bin", "key.txt", "key_def.txt"]
        removed = []
        failed = []

        for name in target_files:
            path = game_dir / name
            if not path.exists():
                continue
            try:
                os.remove(path)
                removed.append(name)
            except Exception as exc:
                failed.append((name, str(exc)))

        if removed:
            self.log_cb(f"已清理游戏目录 key 文件: {', '.join(removed)}")
        if failed:
            self.log_cb("以下文件清理失败（通常是游戏还没关闭）:")
            for name, err in failed:
                self.log_cb(f"  {name}: {err}")
            return False, "部分 key 文件删除失败，通常是游戏进程仍在占用，请关闭游戏后重试。"
        elif not removed:
            self.log_cb("游戏目录中未发现需要清理的 key 文件。")
        
        return True, ""

    def start_game_normal(self, game_exe):
        if not game_exe or not Path(game_exe).exists():
            return False, "请先选择有效的游戏 EXE"
        
        self.log_cb("正在以普通模式启动游戏 (不会生成密钥文件)...")
        try:
            subprocess.Popen([game_exe], cwd=str(Path(game_exe).parent))
            return True, ""
        except Exception as e:
            return False, f"启动失败: {e}"

    def post_process_keys(self, game_dir, xor_key_var_setter, def_xor_key_var_setter, auto_fill_paths_cb):
        target_files = ["key.bin", "key_def.bin", "key.txt", "key_def.txt"]
        xor_from_txt = {}

        for txt_name in ("key.txt", "key_def.txt"):
            src = self.base_dir / txt_name
            if not src.exists():
                src = game_dir / txt_name
            if not src.exists():
                continue
            try:
                with open(src, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                match = re.search(r"([0-9A-Fa-f]{8})", content)
                if match:
                    xor_from_txt[txt_name] = match.group(1).upper()
            except Exception:
                pass

        main_xor = xor_from_txt.get("key.txt")
        def_xor = xor_from_txt.get("key_def.txt")

        if main_xor:
            xor_key_var_setter(main_xor)
        if def_xor:
            def_xor_key_var_setter(def_xor)

        auto_fill_paths_cb(game_dir)

        def background_cleanup():
            for kf in target_files:
                src = game_dir / kf
                if src.exists() and game_dir != self.base_dir:
                    try:
                        shutil.copy2(str(src), str(self.base_dir / kf))
                    except Exception:
                        pass

            if (self.base_dir / "key.bin").exists() or (self.base_dir / "key.txt").exists():
                self.log_queue.put("key 文件已同步到工具目录；不会自动删除任何 key 文件，如需删除请手动操作或使用清理按钮。")

        threading.Thread(target=background_cleanup, daemon=True).start()

    def run_loader_process(self, command, cwd, game_dir, xor_setter, def_xor_setter, auto_fill_cb):
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if self.process_cb:
                self.process_cb(process)
            
            self.log_queue.put("进程已启动，请等待游戏加载并导出 key 文件。")

            if process.stdout is not None:
                for line in process.stdout:
                    self.log_queue.put(line.rstrip())

            return_code = process.wait()
            self.log_queue.put(f"进程已结束，返回码: {return_code}")
            if return_code == 0:
                self.post_process_keys(game_dir, xor_setter, def_xor_setter, auto_fill_cb)
            else:
                self.log_queue.put("KeyFinder 执行失败，请检查位数、依赖和工作目录。")
        except Exception as exc:
            self.log_queue.put(f"启动失败: {exc}")
        finally:
            if self.process_cb:
                self.process_cb(None)
            self.status_cb("就绪")

    def watch_key_files(self, game_dir, get_process_cb, xor_setter, def_xor_setter, auto_fill_cb):
        target_files = ["key.bin", "key_def.bin", "key.txt", "key_def.txt"]
        seen_any = False

        for _ in range(300):
            found_now = False
            for name in target_files:
                src = game_dir / name
                dst = self.base_dir / name
                if not src.exists():
                    continue

                found_now = True
                try:
                    if (not dst.exists()) or src.stat().st_mtime > dst.stat().st_mtime:
                        shutil.copy2(str(src), str(dst))
                except Exception:
                    pass

            if found_now:
                if not seen_any:
                    self.log_queue.put("检测到游戏目录已生成 key 文件，正在同步到工具目录...")
                    seen_any = True
                
                self.post_process_keys(game_dir, xor_setter, def_xor_setter, auto_fill_cb)

            process = get_process_cb() if get_process_cb else None
            if process is None and seen_any:
                break

            time.sleep(1)

