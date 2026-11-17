"""API 元数据库（SQLite，WAL）。

只存：原片元数据、密文 blob 路径、信封 DEK（密文）、主密钥 id、状态。
绝不存：明文 DEK、明文原片、主密钥材料。
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Iterator

# images 表结构（v2：status 增加 deleting/deleted 两个撤下态）。
# 单独抽成常量：旧库迁移需要按同一结构重建表（SQLite 无法 ALTER CHECK）。
IMAGES_DDL = """
CREATE TABLE IF NOT EXISTS images (
    image_id        TEXT PRIMARY KEY,
    filename        TEXT,
    content_type    TEXT,
    status          TEXT NOT NULL CHECK (status IN
                        ('receiving','ready','failed','deleting','deleted')),
    master_key_id   TEXT NOT NULL,
    wrapped_dek     TEXT NOT NULL,           -- 十六进制信封，始终为密文；撤下后清空
    blob_path       TEXT NOT NULL,
    plain_size      INTEGER,
    enc_size        INTEGER,
    sha256          TEXT,
    idem_token      TEXT UNIQUE,
    error           TEXT,
    created_at      REAL NOT NULL,
    finalized_at    REAL
);
"""

SCHEMA = IMAGES_DDL + """
CREATE INDEX IF NOT EXISTS idx_images_mk ON images(master_key_id);
CREATE INDEX IF NOT EXISTS idx_images_status ON images(status);

-- 撤下（删除）作业：受理即持久化，清退步骤幂等可续作；
-- 行保留即"删除进度"，供同编号重试查询，且墓碑行使旧编号永不可再入仓。
CREATE TABLE IF NOT EXISTS deletions (
    image_id         TEXT PRIMARY KEY,
    state            TEXT NOT NULL CHECK (state IN
                         ('pending','clearing','completed')),
    envelope_erased  INTEGER NOT NULL DEFAULT 0,   -- 可解包信封已抹除
    blob_removed     INTEGER NOT NULL DEFAULT 0,   -- 密文文件已删除
    attempts         INTEGER NOT NULL DEFAULT 0,   -- 清退步骤失败重试次数
    error            TEXT,
    requested_at     REAL NOT NULL,
    updated_at       REAL NOT NULL,
    finished_at      REAL
);

CREATE TABLE IF NOT EXISTS rotation_jobs (
    job_id          TEXT PRIMARY KEY,
    state           TEXT NOT NULL CHECK (state IN
                        ('migrating','destroying','completed','failed')),
    old_key_id      TEXT NOT NULL,
    new_key_id      TEXT NOT NULL,
    total           INTEGER NOT NULL DEFAULT 0,
    migrated        INTEGER NOT NULL DEFAULT 0,
    failed          INTEGER NOT NULL DEFAULT 0,
    error           TEXT,
    started_at      REAL NOT NULL,
    updated_at      REAL NOT NULL,
    finished_at     REAL
);
"""

TERMINAL_STATES = ("completed", "failed")


class MetadataDB:
    """每线程独立连接（SQLite 连接不跨线程复用），写操作串行化。"""

    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._write_lock = threading.RLock()
        self._local = threading.local()
        conn = self._connect()
        self._migrate_images_status_check(conn)
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

    def _migrate_images_status_check(self, conn: sqlite3.Connection) -> None:
        """旧库 images.status 的 CHECK 不含撤下态：重建表迁移（列结构不变）。

        SQLite 不能修改 CHECK 约束；数据量小（元数据行），重建代价可忽略。
        """
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='images'"
        ).fetchone()
        if row is None or "'deleting'" in row["sql"]:
            return  # 新库（尚未建表）或已是新结构
        with self._write_lock:
            conn.executescript(
                "BEGIN;\n"
                + IMAGES_DDL.replace("IF NOT EXISTS images", "IF NOT EXISTS images_mig")
                + """
INSERT INTO images_mig SELECT image_id, filename, content_type, status,
    master_key_id, wrapped_dek, blob_path, plain_size, enc_size, sha256,
    idem_token, error, created_at, finalized_at FROM images;
DROP TABLE images;
ALTER TABLE images_mig RENAME TO images;
COMMIT;
""")
        print("[startup] migrated images table schema for deletion states")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._connect()
            self._local.conn = c
        return c

    # ---- 原片 -----------------------------------------------------------
    def create_image(self, image_id: str, filename: str | None,
                     content_type: str | None, master_key_id: str,
                     wrapped_dek: str, blob_path: str,
                     idem_token: str | None) -> str:
        with self._write_lock:
            if idem_token:
                existing = self.conn.execute(
                    "SELECT image_id FROM images WHERE idem_token=?",
                    (idem_token,)).fetchone()
                if existing:
                    return existing["image_id"]
            now = time.time()
            try:
                self.conn.execute(
                    "INSERT INTO images (image_id, filename, content_type, status, "
                    "master_key_id, wrapped_dek, blob_path, idem_token, created_at) "
                    "VALUES (?,?,?, 'receiving', ?,?,?,?,?)",
                    (image_id, filename, content_type, master_key_id,
                     wrapped_dek, blob_path, idem_token, now))
                self.conn.commit()
            except Exception:
                self.conn.rollback()  # 失败 INSERT 不留悬挂事务
                raise
            return image_id

    def get_image(self, image_id: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM images WHERE image_id=?", (image_id,)).fetchone()
        return dict(row) if row else None

    def get_by_token(self, idem_token: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM images WHERE idem_token=?", (idem_token,)).fetchone()
        return dict(row) if row else None

    def finalize_image(self, image_id: str, plain_size: int, enc_size: int,
                       sha256: str) -> None:
        with self._write_lock:
            self.conn.execute(
                "UPDATE images SET status='ready', plain_size=?, enc_size=?, "
                "sha256=?, finalized_at=?, error=NULL WHERE image_id=?",
                (plain_size, enc_size, sha256, time.time(), image_id))
            self.conn.commit()

    def fail_image(self, image_id: str, error: str) -> None:
        with self._write_lock:
            # 失败行释放幂等令牌，允许客户端用同一令牌重新发起上传
            self.conn.execute(
                "UPDATE images SET status='failed', error=?, finalized_at=?, "
                "idem_token=NULL WHERE image_id=?",
                (error[:500], time.time(), image_id))
            self.conn.commit()

    def list_images(self, limit: int = 100, offset: int = 0) -> list[dict]:
        rows = self.conn.execute(
            "SELECT image_id, filename, status, master_key_id, plain_size, "
            "sha256, created_at, finalized_at FROM images "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [dict(r) for r in rows]

    def distinct_key_ids(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT master_key_id FROM images").fetchall()
        return [r["master_key_id"] for r in rows]

    def count_under_key(self, key_id: str,
                        only_migratable: bool = False) -> int:
        sql = "SELECT COUNT(*) AS n FROM images WHERE master_key_id=?"
        if only_migratable:
            # 仅统计会阻塞销毁的行：ready（必须 rewrap）与在途 receiving；
            # failed 行永不会被下载，无需有效信封，不阻塞销毁。
            sql += " AND status IN ('ready','receiving')"
        return self.conn.execute(sql, (key_id,)).fetchone()["n"]

    def iter_under_key(self, key_id: str) -> Iterator[dict]:
        rows = self.conn.execute(
            "SELECT * FROM images WHERE master_key_id=? "
            "AND status IN ('ready','receiving') ORDER BY created_at",
            (key_id,)).fetchall()
        for r in rows:
            yield dict(r)

    def rewrap_row(self, image_id: str, expect_old_key: str,
                   new_key_id: str, new_wrapped: str) -> bool:
        """条件更新：仅当该行仍绑定旧 MK 且仍在供数状态时改包，返回是否实际更新。

        这样迁移与"迟到的在途上传最终化"互不覆盖：后者若已自行改绑新 MK，
        迁移跳过它即可。状态守卫保证：已撤下（deleting/deleted）的行绝不会
        被轮换迁移写回信封——撤下后的信封只能被删除清退抹除。
        """
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE images SET master_key_id=?, wrapped_dek=? "
                "WHERE image_id=? AND master_key_id=? "
                "AND status IN ('ready','receiving')",
                (new_key_id, new_wrapped, image_id, expect_old_key))
            self.conn.commit()
            return cur.rowcount > 0

    def mark_stale_receiving_failed(self) -> int:
        """进程重启后，所有 receiving 都是上次崩溃的在途上传，
        不允许晚发布（防止它依赖已销毁的旧 MK 才完成）。"""
        with self._write_lock:
            cur = self.conn.execute(
                "UPDATE images SET status='failed', "
                "error='interrupted by service restart', finalized_at=? "
                "WHERE status='receiving'", (time.time(),))
            self.conn.commit()
            return cur.rowcount

    # ---- 撤下（删除） ---------------------------------------------------
    def accept_deletion(self, image_id: str) -> bool:
        """受理撤下：ready -> deleting 并同事务登记删除作业。

        条件 UPDATE 保证只有已发布（ready）行被受理；受理一旦落库，
        下载门（status=='ready'）立即关闭，且重启后清退可接续。
        返回是否本次受理成功（并发重复受理时只有一个成功）。
        """
        with self._write_lock:
            now = time.time()
            cur = self.conn.execute(
                "UPDATE images SET status='deleting' "
                "WHERE image_id=? AND status='ready'", (image_id,))
            if cur.rowcount == 0:
                self.conn.rollback()
                return False
            self.conn.execute(
                "INSERT INTO deletions (image_id, state, requested_at, "
                "updated_at) VALUES (?, 'pending', ?, ?)",
                (image_id, now, now))
            self.conn.commit()
            return True

    def get_deletion(self, image_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM deletions WHERE image_id=?", (image_id,)).fetchone()
        return dict(row) if row else None

    def list_pending_deletions(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM deletions WHERE state != 'completed' "
            "ORDER BY requested_at").fetchall()
        return [dict(r) for r in rows]

    def erase_envelope(self, image_id: str) -> None:
        """抹除可解包信封（wrapped_dek 清空）并同事务标记进度。

        此后该原片在密码学上不可再被解包（即使旧 MK 仍存活）；
        行仍保留为墓碑，旧编号不可再入仓。
        """
        with self._write_lock:
            now = time.time()
            self.conn.execute(
                "UPDATE images SET wrapped_dek='' "
                "WHERE image_id=? AND status='deleting'", (image_id,))
            self.conn.execute(
                "UPDATE deletions SET envelope_erased=1, state='clearing', "
                "updated_at=? WHERE image_id=?", (now, image_id))
            self.conn.commit()

    def mark_blob_removed(self, image_id: str) -> None:
        with self._write_lock:
            self.conn.execute(
                "UPDATE deletions SET blob_removed=1, state='clearing', "
                "updated_at=? WHERE image_id=?", (time.time(), image_id))
            self.conn.commit()

    def complete_deletion(self, image_id: str) -> None:
        """信封与密文文件都已清除后才置终态：行转 deleted，作业 completed。"""
        with self._write_lock:
            now = time.time()
            self.conn.execute(
                "UPDATE images SET status='deleted' "
                "WHERE image_id=? AND status='deleting'", (image_id,))
            self.conn.execute(
                "UPDATE deletions SET state='completed', updated_at=?, "
                "finished_at=? WHERE image_id=?", (now, now, image_id))
            self.conn.commit()

    def bump_deletion_attempt(self, image_id: str, error: str) -> None:
        with self._write_lock:
            self.conn.execute(
                "UPDATE deletions SET attempts=attempts+1, error=?, "
                "updated_at=? WHERE image_id=?",
                (error[:500], time.time(), image_id))
            self.conn.commit()

    # ---- 轮换作业 -------------------------------------------------------
    def active_rotation(self) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs WHERE state NOT IN ('completed','failed')"
        ).fetchone()
        return dict(row) if row else None

    def create_rotation(self, old_key_id: str, new_key_id: str,
                        total: int) -> str:
        with self._write_lock:
            if self.active_rotation() is not None:
                raise RuntimeError("rotation already in progress")
            job_id = "rot-" + uuid.uuid4().hex
            now = time.time()
            self.conn.execute(
                "INSERT INTO rotation_jobs (job_id, state, old_key_id, "
                "new_key_id, total, migrated, failed, started_at, updated_at) "
                "VALUES (?, 'migrating', ?,?,?, 0, 0, ?, ?)",
                (job_id, old_key_id, new_key_id, total, now, now))
            self.conn.commit()
            return job_id

    def has_rotation_for(self, old_key_id: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM rotation_jobs WHERE old_key_id=? LIMIT 1",
            (old_key_id,)).fetchone() is not None

    def get_rotation(self, job_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs WHERE job_id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def latest_rotation(self) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM rotation_jobs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def bump_rotation(self, job_id: str, migrated: int = 0, failed: int = 0,
                      state: str | None = None, error: str | None = None) -> None:
        with self._write_lock:
            sets = ["updated_at=?"]
            params: list[Any] = [time.time()]
            if migrated:
                sets.append("migrated = migrated + ?")
                params.append(migrated)
            if failed:
                sets.append("failed = failed + ?")
                params.append(failed)
            if state:
                sets.append("state=?")
                params.append(state)
            if error is not None:
                sets.append("error=?")
                params.append(error[:500])
            if state in TERMINAL_STATES:
                sets.append("finished_at=?")
                params.append(time.time())
            params.append(job_id)
            self.conn.execute(
                f"UPDATE rotation_jobs SET {', '.join(sets)} WHERE job_id=?",
                params)
            self.conn.commit()

    def close(self):
        c = getattr(self._local, "conn", None)
        if c:
            c.close()
