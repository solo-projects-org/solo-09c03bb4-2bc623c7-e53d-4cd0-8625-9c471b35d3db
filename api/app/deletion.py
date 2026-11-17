"""原片撤下（删除）清退后台线程。

受理（DELETE /images/{id}：ready -> deleting，同事务登记 deletions 行）之后，
本线程把清退推进到终态。步骤幂等、可断点续作：

  1) 抹除可解包信封（images.wrapped_dek 清空）——此后该原片密码学不可读，
     且轮换迁移因状态守卫绝不会把信封写回；
  2) 删除密文 blob 文件，回收密文空间（已开始下载持有的 fd 在 POSIX 语义下
     不受 unlink 影响，可完整读完）；
  3) 两项都落库后：images.status -> deleted，deletions.state -> completed。

保证：
  * 受理即持久化——清退中进程崩溃/重启，重启后由本线程接续，原片一直不可供数；
  * 步骤失败（文件删除/元数据更新异常）记录 attempts/error 并持续重试，
    只有文件与信封都清除才会报 completed；
  * 撤下行不计入轮换销毁的阻塞统计，绝不拖住旧主密钥销毁。
"""
from __future__ import annotations

import asyncio
import os
import threading
import traceback

from .metadata import MetadataDB

POLL_INTERVAL = float(os.environ.get("DELETION_POLL_INTERVAL", "0.5"))


class DeletionWorker:
    def __init__(self, db: MetadataDB, loop: asyncio.AbstractEventLoop):
        self._db = db
        self._loop = loop
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._thread_main, daemon=True,
                                        name="deletion-worker")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _thread_main(self):
        try:
            fut = asyncio.run_coroutine_threadsafe(self._run(), self._loop)
            fut.result()
        except Exception:
            traceback.print_exc()

    async def _run(self):
        """常驻协程：发现未完成清退就驱动到终态，然后继续轮询。"""
        while not self._stop.is_set():
            try:
                pendings = self._db.list_pending_deletions()
            except Exception:
                traceback.print_exc()
                pendings = []
            for rec in pendings:
                if self._stop.is_set():
                    return
                await self._drive(rec["image_id"])
            await asyncio.sleep(POLL_INTERVAL)

    async def _drive(self, image_id: str):
        rec = self._db.get_deletion(image_id)
        if rec is None or rec["state"] == "completed":
            return
        try:
            envelope_erased = bool(rec["envelope_erased"])
            blob_removed = bool(rec["blob_removed"])
            if not envelope_erased:
                # 先抹信封：即使此刻崩溃，残留密文也永远不可解包
                self._db.erase_envelope(image_id)
                envelope_erased = True
            if not blob_removed:
                meta = self._db.get_image(image_id)
                path = meta["blob_path"] if meta else None
                if path:
                    try:
                        os.remove(path)
                    except FileNotFoundError:
                        pass  # 文件本就不在，视同已清除（幂等）
                self._db.mark_blob_removed(image_id)
                blob_removed = True
            if envelope_erased and blob_removed:
                self._db.complete_deletion(image_id)
        except Exception as exc:  # 文件/元数据步骤失败：记录并下轮重试
            self._db.bump_deletion_attempt(image_id, f"{exc!r}")
