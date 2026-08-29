"""后台阶段 Worker。

UI 线程从不解析二进制：它提交任务，然后从队列消费结构化事件。取消是协作式的，
检查点位于样本之间，因此被取消的批处理会保留已完成的样本，并报告停在何处。
"""
from __future__ import annotations

import queue
import threading
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

from ..core.errors import PsbError
from ..services.stages import StageResult, StageService


@dataclass(slots=True)
class Event:
    """Worker 发给 UI 的结构化消息。"""

    kind: str            # started | progress | log | finished | failed | cancelled（机器枚举）
    stage: str = ""
    fraction: float = 0.0
    message: str = ""
    payload: dict[str, Any] = field(default_factory=dict)


class StageWorker:
    """在守护线程上执行一次 StageService 调用。"""

    def __init__(self) -> None:
        self.events: queue.Queue[Event] = queue.Queue()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def cancel(self) -> None:
        self._cancel.set()

    def is_cancelled(self) -> bool:
        return self._cancel.is_set()

    def submit(self, stage: str,
               job: Callable[[StageService, Callable[[], bool]], StageResult],
               ) -> bool:
        """启动 `job`；若已有任务在运行则返回 False。"""
        if self.busy:
            return False
        self._cancel.clear()

        def progress(name: str, fraction: float, message: str) -> None:
            self.events.put(Event("progress", name, fraction, message))

        def run() -> None:
            self.events.put(Event("started", stage, 0.0, f"{stage} 已启动"))
            svc = StageService(progress=progress)
            try:
                result = job(svc, self.is_cancelled)
            except PsbError as exc:
                self.events.put(Event(
                    "failed", stage, 1.0, f"{type(exc).__name__}: {exc}",
                    {"error_type": type(exc).__name__, "error": str(exc)}))
                return
            except Exception as exc:  # noqa: BLE001 —— 交由 UI 呈现
                self.events.put(Event(
                    "failed", stage, 1.0, f"{type(exc).__name__}: {exc}",
                    {"error_type": type(exc).__name__, "error": str(exc),
                     "traceback": traceback.format_exc()}))
                return
            if self.is_cancelled():
                self.events.put(Event("cancelled", stage, 1.0,
                                      f"{stage} 已取消",
                                      result.to_json()))
                return
            self.events.put(Event(
                "finished", stage, 1.0,
                f"{stage} {'成功' if result.ok else '未通过'}",
                result.to_json()))

        self._thread = threading.Thread(target=run, name=f"stage-{stage}",
                                        daemon=True)
        self._thread.start()
        return True

    def drain(self, limit: int = 200) -> list[Event]:
        """非阻塞：最多取出 `limit` 条待处理事件。"""
        out: list[Event] = []
        for _ in range(limit):
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                break
        return out
