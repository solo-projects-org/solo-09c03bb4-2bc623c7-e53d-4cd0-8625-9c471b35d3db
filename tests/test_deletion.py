"""T13-T17：原片撤下（删除）语义。

  T13 受理即禁新下载；最终清除密文与信封；同号重试幂等；旧编号不得再入仓
  T14 仅受理已发布原片（receiving/failed/不存在一律拒绝）
  T15 已经开始的流式下载在清退期间完整结束
  T16 删除与轮换改包交错：撤下信封不被写回、不拖住旧 MK 销毁，其余原片正常
  T17 受理后 API 重启：清退接续，文件与信封都清除后才报完成
"""
import sqlite3
import time

import httpx

from conftest import _download, _key_headers, _upload, _wait_rotation


def _wait_deletion(client: httpx.Client, image_id: str,
                   timeout: float = 20.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/images/{image_id}/deletion")
        assert r.status_code == 200, r.text
        body = r.json()
        if body["state"] == "completed":
            return body
        time.sleep(0.2)
    raise AssertionError(f"deletion of {image_id} did not complete")


def _db_row(stack, image_id: str):
    conn = sqlite3.connect(stack["data_dir"] / "metadata.db")
    try:
        return conn.execute(
            "SELECT status, wrapped_dek, master_key_id FROM images "
            "WHERE image_id=?", (image_id,)).fetchone()
    finally:
        conn.close()


def test_delete_happy_path_blocks_download_and_reclaims(stack):
    client = stack["client"]
    payload = b"withdraw-me-" + bytes(range(256)) * 100
    assert _upload(client, payload, image_id="del-1").status_code == 201
    assert _upload(client, b"keep-me", image_id="keep-1").status_code == 201
    blob_file = stack["blob_dir"] / "del-1.msef"
    assert blob_file.exists()
    # 无删除记录时查进度 -> 404
    assert client.get("/images/del-1/deletion").status_code == 404

    r = client.delete("/images/del-1")
    assert r.status_code == 202, r.text
    assert r.json()["image_id"] == "del-1"

    # 受理后立即禁止新下载（不必等清退完成）
    r = client.get("/images/del-1")
    assert r.status_code == 410
    assert r.json()["detail"]["code"] == "image_withdrawn"

    # 清退完成：文件与信封都清除后才报 completed
    done = _wait_deletion(client, "del-1")
    assert done["envelope_erased"] is True and done["blob_removed"] is True
    assert done["finished_at"] is not None
    assert not blob_file.exists()                      # 密文空间已回收
    status, wrapped, _ = _db_row(stack, "del-1")
    assert status == "deleted" and wrapped == ""       # 可解包信封已抹除
    assert client.get("/images/del-1").status_code == 410
    assert client.get("/images/del-1/meta").json()["status"] == "deleted"

    # 同号重试：幂等返回同一删除结果（200，不重复动作）
    r2 = client.delete("/images/del-1")
    assert r2.status_code == 200
    assert r2.json()["state"] == "completed"
    assert r2.json()["requested_at"] == done["requested_at"]

    # 旧编号不能再次入仓
    r3 = _upload(client, b"re-ingest", image_id="del-1")
    assert r3.status_code == 409
    assert r3.json()["detail"]["code"] == "image_id_retired"

    # 其余原片正常取数、新原片正常入仓
    assert _download(client, "keep-1") == b"keep-me"
    assert _upload(client, b"fresh", image_id="fresh-1").status_code == 201
    assert _download(client, "fresh-1") == b"fresh"


def test_delete_rejects_non_ready_and_unknown(stack):
    client = stack["client"]
    assert client.delete("/images/never-existed").status_code == 404
    # 构造 receiving / failed 行（等价上传建立后未完成/被判失败）
    conn = sqlite3.connect(stack["data_dir"] / "metadata.db")
    mk = client.get("/keys/status").json()["current_key_id"]
    for iid, st in (("del-recv", "receiving"), ("del-fail", "failed")):
        conn.execute(
            "INSERT INTO images (image_id, status, master_key_id, wrapped_dek, "
            "blob_path, created_at) VALUES (?,?,?,?,?,?)",
            (iid, st, mk, "00" * 64,
             str(stack["blob_dir"] / f"{iid}.msef"), time.time()))
    conn.commit()
    conn.close()
    for iid in ("del-recv", "del-fail"):
        r = client.delete(f"/images/{iid}")
        assert r.status_code == 409, (iid, r.text)
        assert r.json()["detail"]["code"] == "image_not_published"
        assert client.get(f"/images/{iid}/deletion").status_code == 404


def test_inflight_download_completes_during_deletion(stack):
    """已开始的流式下载：受理删除后仍完整读完；清退随后正常完成。"""
    client = stack["client"]
    payload = bytes((i * 13) % 256 for i in range(3 * 1024 * 1024))
    assert _upload(client, payload, image_id="del-inflight").status_code == 201

    with httpx.Client(base_url=stack["api"].base, timeout=30) as slow:
        with slow.stream("GET", "/images/del-inflight") as resp:
            assert resp.status_code == 200
            chunks = resp.iter_bytes(65536)
            first = next(chunks)                  # 已开始流式下载
            r = client.delete("/images/del-inflight")
            assert r.status_code == 202           # 下载进行中受理删除
            rest = b"".join(chunks)
    assert first + rest == payload                # 在途下载逐字节完整

    done = _wait_deletion(client, "del-inflight")
    assert done["state"] == "completed"
    assert not (stack["blob_dir"] / "del-inflight.msef").exists()
    assert client.get("/images/del-inflight").status_code == 410


def test_deletion_interleaved_with_rotation(stack):
    """删除与轮换改包交错：撤下信封不被迁移写回、不拖住旧 MK 销毁。"""
    client, kc = stack["client"], stack["key_client"]
    payloads = {}
    for i in range(6):
        payloads[f"rot-del-{i}"] = f"payload-{i}-".encode() * 500
        assert _upload(client, payloads[f"rot-del-{i}"],
                       image_id=f"rot-del-{i}").status_code == 201
    old_key = client.get("/images/rot-del-0/meta").json()["master_key_id"]

    # 慢密钥服务拉宽迁移窗口，使删除必然落在轮换进行中
    env = dict(stack["keys"]._env)
    env["KEY_OP_DELAY"] = "0.25"
    stack["keys"].stop()
    stack["keys"]._env = env
    stack["keys"].start()

    r = client.post("/rotations", json={"confirm": True})
    assert r.status_code == 202, r.text
    job = r.json()
    # 轮换进行中撤下 rot-del-2
    rd = client.delete("/images/rot-del-2")
    assert rd.status_code == 202, rd.text
    assert client.get("/images/rot-del-2").status_code == 410

    # 撤下行不阻塞销毁：轮换照常完成，旧 MK 被销毁
    result = _wait_rotation(client, job["job_id"], timeout=120)
    assert result["state"] == "completed", result
    ks = kc.get("/internal/master/status", headers=_key_headers()).json()
    states = {k["key_id"]: k["state"] for k in ks["keys"]}
    assert states[old_key] == "destroyed"

    # 清退完成：撤下原片的信封没有被迁移写回（最终为已抹除），密文已删
    done = _wait_deletion(client, "rot-del-2")
    assert done["envelope_erased"] is True and done["blob_removed"] is True
    status, wrapped, _ = _db_row(stack, "rot-del-2")
    assert status == "deleted" and wrapped == ""
    assert not (stack["blob_dir"] / "rot-del-2.msef").exists()
    assert client.get("/images/rot-del-2").status_code == 410

    # 其余原片信封已迁移到新 MK，逐字节可读；新原片正常入仓
    new_key = ks["current_key_id"]
    for iid, data in payloads.items():
        if iid == "rot-del-2":
            continue
        meta = client.get(f"/images/{iid}/meta").json()
        assert meta["master_key_id"] == new_key
        assert _download(client, iid) == data
    assert _upload(client, b"post-rotation", image_id="post-rot").status_code == 201
    assert _download(client, "post-rot") == b"post-rotation"


def test_deletion_resumes_after_api_restart(stack):
    """受理后清退未完成时 API 重启：原片持续不可供数，清退接续到完成。"""
    client = stack["client"]
    assert _upload(client, b"crash-pending", image_id="crash-1").status_code == 201
    assert _upload(client, b"crash-half-done", image_id="crash-2").status_code == 201
    blob1 = stack["blob_dir"] / "crash-1.msef"
    blob2 = stack["blob_dir"] / "crash-2.msef"
    assert blob1.exists() and blob2.exists()

    # 模拟"受理后、清退中进程被杀"：crash-1 一步未做；crash-2 已抹信封未删文件
    conn = sqlite3.connect(stack["data_dir"] / "metadata.db")
    now = time.time()
    conn.execute("UPDATE images SET status='deleting' WHERE image_id='crash-1'")
    conn.execute(
        "INSERT INTO deletions (image_id, state, requested_at, updated_at) "
        "VALUES ('crash-1','pending',?,?)", (now, now))
    conn.execute("UPDATE images SET status='deleting', wrapped_dek='' "
                 "WHERE image_id='crash-2'")
    conn.execute(
        "INSERT INTO deletions (image_id, state, envelope_erased, requested_at, "
        "updated_at) VALUES ('crash-2','clearing',1,?,?)", (now, now))
    conn.commit()
    conn.close()

    stack["api"].restart()

    # 重启后原片仍不可供数，且清退自动接续到完成
    assert client.get("/images/crash-1").status_code == 410
    assert client.get("/images/crash-2").status_code == 410
    for iid, blob in (("crash-1", blob1), ("crash-2", blob2)):
        done = _wait_deletion(client, iid)
        assert done["envelope_erased"] is True and done["blob_removed"] is True
        assert not blob.exists()
        status, wrapped, _ = _db_row(stack, iid)
        assert status == "deleted" and wrapped == ""
        # 旧编号不得再入仓
        assert _upload(client, b"back?", image_id=iid).status_code == 409
