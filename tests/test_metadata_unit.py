"""元数据库离线单测（不起服务）：删除状态机、rewrap 状态守卫、旧库结构迁移。"""
import importlib
import sqlite3
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def metadata():
    """隔离加载 api 侧的 app.metadata（与密钥服务同名包不互相污染）。"""
    saved_path = list(sys.path)
    saved_mods = {n: m for n, m in sys.modules.items()
                  if n == "app" or n.startswith("app.")}
    for n in list(saved_mods):
        del sys.modules[n]
    sys.path.insert(0, str(ROOT / "api"))
    try:
        module = importlib.import_module("app.metadata")
        yield module
    finally:
        for n in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
            del sys.modules[n]
        sys.modules.update(saved_mods)
        sys.path[:] = saved_path


def _make_image(mdb, image_id, mk="mk-old", status_ready=True):
    mdb.create_image(image_id, None, None, mk, "ab" * 64,
                     f"/nonexistent/{image_id}.msef", None)
    if status_ready:
        mdb.finalize_image(image_id, 10, 10, "00" * 32)


def test_deletion_state_machine(metadata, tmp_path):
    mdb = metadata.MetadataDB(str(tmp_path / "m.db"))
    _make_image(mdb, "img-a")
    # 受理：ready -> deleting，登记作业
    assert mdb.accept_deletion("img-a") is True
    assert mdb.accept_deletion("img-a") is False  # 重复受理幂等拒绝
    rec = mdb.get_deletion("img-a")
    assert rec["state"] == "pending"
    assert mdb.get_image("img-a")["status"] == "deleting"
    assert [r["image_id"] for r in mdb.list_pending_deletions()] == ["img-a"]
    # 抹信封 -> 删文件 -> 完成
    mdb.erase_envelope("img-a")
    assert mdb.get_image("img-a")["wrapped_dek"] == ""
    assert mdb.get_deletion("img-a")["envelope_erased"] == 1
    mdb.mark_blob_removed("img-a")
    mdb.complete_deletion("img-a")
    assert mdb.get_image("img-a")["status"] == "deleted"
    rec = mdb.get_deletion("img-a")
    assert rec["state"] == "completed" and rec["finished_at"] is not None
    assert mdb.list_pending_deletions() == []
    mdb.close()


def test_rewrap_never_writes_back_withdrawn_envelope(metadata, tmp_path):
    """已撤下行的信封不得被轮换迁移写回（状态守卫）。"""
    mdb = metadata.MetadataDB(str(tmp_path / "m.db"))
    _make_image(mdb, "img-b")
    assert mdb.accept_deletion("img-b") is True
    mdb.erase_envelope("img-b")
    # 轮换迁移尝试改包已撤下行：必须被拒绝且信封保持已抹除
    changed = mdb.rewrap_row("img-b", "mk-old", "mk-new", "cd" * 64)
    assert changed is False
    row = mdb.get_image("img-b")
    assert row["master_key_id"] == "mk-old"
    assert row["wrapped_dek"] == ""
    # 对照：正常 ready 行仍可被迁移
    _make_image(mdb, "img-c")
    assert mdb.rewrap_row("img-c", "mk-old", "mk-new", "cd" * 64) is True
    assert mdb.get_image("img-c")["master_key_id"] == "mk-new"
    # 撤下行不计入销毁阻塞统计、不出现在迁移扫描中
    assert mdb.count_under_key("mk-old", only_migratable=True) == 0
    assert [r["image_id"] for r in mdb.iter_under_key("mk-old")] == []
    mdb.close()


# 旧版（v1）images 表结构：status CHECK 不含 deleting/deleted
V1_SCHEMA = """
CREATE TABLE images (
    image_id        TEXT PRIMARY KEY,
    filename        TEXT,
    content_type    TEXT,
    status          TEXT NOT NULL CHECK (status IN
                        ('receiving','ready','failed')),
    master_key_id   TEXT NOT NULL,
    wrapped_dek     TEXT NOT NULL,
    blob_path       TEXT NOT NULL,
    plain_size      INTEGER,
    enc_size        INTEGER,
    sha256          TEXT,
    idem_token      TEXT UNIQUE,
    error           TEXT,
    created_at      REAL NOT NULL,
    finalized_at    REAL
);
CREATE INDEX idx_images_mk ON images(master_key_id);
CREATE INDEX idx_images_status ON images(status);
"""


def test_old_schema_db_is_migrated_on_open(metadata, tmp_path):
    db_file = tmp_path / "old.db"
    conn = sqlite3.connect(db_file)
    conn.executescript(V1_SCHEMA)
    conn.execute(
        "INSERT INTO images (image_id, status, master_key_id, wrapped_dek, "
        "blob_path, created_at) VALUES ('legacy-1','ready','mk-1',?,?,?)",
        ("ef" * 64, "/nonexistent/legacy-1.msef", time.time()))
    conn.commit()
    conn.close()

    mdb = metadata.MetadataDB(str(db_file))  # 打开即触发迁移
    # 旧数据保留，新状态可用
    assert mdb.get_image("legacy-1")["status"] == "ready"
    assert mdb.accept_deletion("legacy-1") is True
    assert mdb.get_image("legacy-1")["status"] == "deleting"
    # deletions 表已建立
    assert mdb.get_deletion("legacy-1")["state"] == "pending"
    mdb.close()
    # 再打开一次：幂等，不重复迁移
    mdb2 = metadata.MetadataDB(str(db_file))
    assert mdb2.get_image("legacy-1")["status"] == "deleting"
    mdb2.close()
