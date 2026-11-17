"""显微成像原片单实例 API。

安全边界：
  * 明文原片只在请求/响应的内存流中存在，密文 blob 直接落盘；
  * 明文 DEK 只在单次请求内存中存活，元数据库只存信封密文；
  * 主密钥材料永远只在密钥服务内，本服务通过内部 HTTP 调用包裹/解包。
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

BLOB_DIR = os.environ.get("BLOB_DIR", "/data/blobs")
DB_PATH = os.environ.get("METADATA_DB", "/data/metadata.db")
KEY_SERVICE_URL = os.environ.get("KEY_SERVICE_URL", "http://keystore:8001")
KEY_SERVICE_TOKEN = os.environ.get("KEY_SERVICE_TOKEN", "dev-only-key-service-token")
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(20 * 1024 ** 3)))

# 安全约束：Starlette 的 multipart 解析器默认把 >1MiB 的表单文件假脱机到
# 磁盘临时文件，等于让明文原片落盘。将假脱机阈值提高到上传上限，使允许范围
# 内的 multipart 一律留在内存（超限请求在入口处即被 Content-Length 拒绝）。
# 首选仍是原始 application/octet-stream 流式上传，完全不经表单解析器。
from starlette.formparsers import MultiPartParser
MultiPartParser.spool_max_size = MAX_UPLOAD_BYTES

from .crypto_stream import IntegrityError, decrypt_stream, encrypt_stream
from .deletion import DeletionWorker
from .keyclient import KeyClient, KeyServiceError
from .metadata import MetadataDB
from .rotation import RotationWorker

db = MetadataDB(DB_PATH)
keys = KeyClient(KEY_SERVICE_URL, KEY_SERVICE_TOKEN)
worker: RotationWorker | None = None
deletion_worker: DeletionWorker | None = None
main_loop: asyncio.AbstractEventLoop | None = None


# --------------------------------------------------------------------------
# 生命周期：引导主密钥 -> 崩溃恢复（在途上传判失败/轮换接续）-> 启动后台线程
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global worker, deletion_worker, main_loop
    os.makedirs(BLOB_DIR, exist_ok=True)
    main_loop = asyncio.get_running_loop()
    # 等待密钥服务就绪并确保存在当前主密钥（重启幂等）
    for attempt in range(10):
        try:
            await keys.ensure_bootstrap()
            break
        except KeyServiceError:
            await asyncio.sleep(1.0)
    # 崩溃恢复：上次 receiving 的上传一律失败，禁止"晚发布"依赖旧密钥
    stale = db.mark_stale_receiving_failed()
    if stale:
        print(f"[startup] {stale} interrupted upload(s) marked failed")
    # 崩溃对账：上次可能已在密钥服务切换了 MK、却没来得及建本地作业
    try:
        key_status = await keys.master_status()
        current_mk = key_status.get("current_key_id")
        for key in key_status.get("keys", []):
            if (key["key_id"] != current_mk
                    and key["state"] == "active"
                    and not db.has_rotation_for(key["key_id"])):
                job_id = db.create_rotation(
                    key["key_id"], current_mk,
                    db.count_under_key(key["key_id"], only_migratable=True))
                print(f"[startup] reconciled missing rotation job {job_id} "
                      f"for {key['key_id']}")
    except KeyServiceError as exc:
        print(f"[startup] rotation reconciliation skipped: {exc}")
    worker = RotationWorker(db, keys, main_loop)
    worker.start()
    # 撤下清退接续：上次受理但未清退完成的删除在此续作（原片一直不可供数）
    deletion_worker = DeletionWorker(db, main_loop)
    deletion_worker.start()
    yield
    worker.stop()
    deletion_worker.stop()
    await keys.aclose()
    db.close()


app = FastAPI(
    title="Microscopy Image Warehouse API",
    version="1.0.0",
    description="原片流式加密存取，每件独立 DEK；支持主密钥在线轮换与进度查询。",
    lifespan=lifespan,
)


def _key_error(exc: KeyServiceError) -> HTTPException:
    return HTTPException(status_code=exc.status_code,
                         detail={"code": exc.code, "message": exc.message})


# --------------------------------------------------------------------------
# 上传
# --------------------------------------------------------------------------
async def _stream_to_blob(request: Request, blob_path: str,
                          dek: bytes) -> dict[str, Any]:
    """读 HTTP 请求体 -> 分帧加密 -> 密文直接写盘（无明文临时文件）。"""
    writer = open(blob_path, "wb")  # 二进制密文文件
    loop = asyncio.get_running_loop()

    async def write(data: bytes):
        await loop.run_in_executor(None, writer.write, data)
        await loop.run_in_executor(None, writer.flush)

    try:
        stats = await encrypt_stream(request.stream(), dek, write)
    finally:
        await loop.run_in_executor(None, writer.close)
    return stats


async def _finalize_with_rebind(image_id: str, stats: dict[str, Any]) -> dict[str, Any]:
    """最终化原片；若其 MK 在上传期间已被轮换切换，则先 rewrap 改绑当前 MK。

    是否需要改绑只依据本地轮换记录判断（不额外依赖密钥服务在线）：
    该行绑定的正是最近一次轮换的旧 MK 时，说明它是跨越轮换的在途上传。
    防止在途上传晚发布依赖旧（甚至已销毁）主密钥的原片。
    """
    meta = db.get_image(image_id)
    job = db.latest_rotation()
    if job and meta and meta["master_key_id"] == job["old_key_id"]:
        try:
            res = await keys.rewrap(meta["master_key_id"], meta["wrapped_dek"],
                                    f"finalize:{image_id}")
        except KeyServiceError as exc:
            if exc.status_code == 410:
                # 旧 MK 已销毁且该行信封未能提前迁移：绝不能晚发布不可读原片
                raise HTTPException(
                    status_code=409,
                    detail={"code": "old_key_destroyed",
                            "message": "upload cannot be finalized; its key was "
                                       "rotated and destroyed before completion"})
            raise
        db.rewrap_row(image_id, meta["master_key_id"],
                      res["key_id"], res["wrapped_dek"])
    db.finalize_image(image_id, stats["plain_size"], stats["enc_size"],
                      stats["sha256"])
    return db.get_image(image_id)


def _check_content_length(request: Request):
    cl = request.headers.get("content-length")
    if cl is not None and int(cl) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, detail="upload exceeds MAX_UPLOAD_BYTES")


@app.post("/images", status_code=201,
          summary="上传原片（流式加密；支持 X-Idempotency-Token 幂等）")
async def upload_image(request: Request, response: Response,
                       x_idempotency_token: str | None = Header(default=None),
                       x_filename: str | None = Header(default=None),
                       x_content_type: str | None = Header(default=None)):
    _check_content_length(request)
    # 幂等重放：直接返回既有回执，不重复入湖
    if x_idempotency_token:
        existing = db.get_by_token(x_idempotency_token)
        if existing:
            response.status_code = 200
            return {"image_id": existing["image_id"], "status": existing["status"],
                    "idempotent": True}
    try:
        dek_resp = await keys.generate_dek()
    except KeyServiceError as exc:
        raise _key_error(exc)
    master_key_id = dek_resp["key_id"]
    wrapped_dek = dek_resp["wrapped_dek"]
    dek = bytes.fromhex(dek_resp["dek"])  # 仅存于本请求内存

    image_id = "img-" + uuid.uuid4().hex
    blob_path = os.path.join(BLOB_DIR, image_id + ".msef")
    db.create_image(image_id, x_filename,
                    x_content_type or request.headers.get("content-type"),
                    master_key_id, wrapped_dek, blob_path, x_idempotency_token)
    try:
        stats = await _stream_to_blob(request, blob_path, dek)
        if stats["plain_size"] > MAX_UPLOAD_BYTES:
            raise HTTPException(413, detail="upload exceeds MAX_UPLOAD_BYTES")
        final = await _finalize_with_rebind(image_id, stats)
    except HTTPException:
        db.fail_image(image_id, "upload rejected")
        try:
            os.remove(blob_path)
        except OSError:
            pass
        raise
    except Exception as exc:  # 写入失败：判失败并清理密文残片
        db.fail_image(image_id, f"upload failed: {exc!r}")
        try:
            os.remove(blob_path)
        except OSError:
            pass
        raise HTTPException(status_code=502,
                            detail=f"upload failed: {exc!r}") from exc
    finally:
        del dek  # 尽快丢弃明文 DEK 引用
    return {"image_id": image_id, "status": "ready",
            "size": stats["plain_size"], "sha256": stats["sha256"],
            "master_key_id": final["master_key_id"]}


@app.put("/images/{image_id}", status_code=201,
         summary="按调用方指定编号上传原片")
async def upload_image_named(image_id: str, request: Request, response: Response,
                             x_idempotency_token: str | None = Header(default=None),
                             x_filename: str | None = Header(default=None),
                             x_content_type: str | None = Header(default=None)):
    if not image_id or len(image_id) > 128 or "/" in image_id or ".." in image_id:
        raise HTTPException(400, detail="invalid image_id")
    _check_content_length(request)
    if x_idempotency_token:
        existing = db.get_by_token(x_idempotency_token)
        if existing:
            response.status_code = 200
            return {"image_id": existing["image_id"], "status": existing["status"],
                    "idempotent": True}
    current = db.get_image(image_id)
    if current and current["status"] in ("receiving", "ready"):
        raise HTTPException(409, detail=f"image_id already exists ({current['status']})")
    if current and current["status"] in ("deleting", "deleted"):
        # 墓碑行永久占位：撤下过的编号不得再次入仓
        raise HTTPException(
            409, detail={"code": "image_id_retired",
                         "message": "image_id was withdrawn and cannot be re-ingested"})
    try:
        dek_resp = await keys.generate_dek()
    except KeyServiceError as exc:
        raise _key_error(exc)
    blob_path = os.path.join(BLOB_DIR, image_id + ".msef")
    try:
        db.create_image(image_id, x_filename,
                        x_content_type or request.headers.get("content-type"),
                        dek_resp["key_id"], dek_resp["wrapped_dek"],
                        blob_path, x_idempotency_token)
    except sqlite3.IntegrityError:
        # 并发同号入仓 / 历史行占位（如 failed）：一律按冲突处理，不暴露 500
        raise HTTPException(409, detail="image_id already exists")
    dek = bytes.fromhex(dek_resp["dek"])
    try:
        stats = await _stream_to_blob(request, blob_path, dek)
        final = await _finalize_with_rebind(image_id, stats)
    except HTTPException:
        db.fail_image(image_id, "upload rejected")
        try:
            os.remove(blob_path)
        except OSError:
            pass
        raise
    except Exception as exc:
        db.fail_image(image_id, f"upload failed: {exc!r}")
        try:
            os.remove(blob_path)
        except OSError:
            pass
        raise HTTPException(status_code=502,
                            detail=f"upload failed: {exc!r}") from exc
    finally:
        del dek
    return {"image_id": image_id, "status": "ready",
            "size": stats["plain_size"], "sha256": stats["sha256"],
            "master_key_id": final["master_key_id"]}


# --------------------------------------------------------------------------
# 下载 / 查询
# --------------------------------------------------------------------------
def _cipher_chunks(fd):
    """从已打开的密文 fd 流式读块；生成器结束时关闭 fd。"""
    async def gen():
        loop = asyncio.get_running_loop()
        try:
            while True:
                chunk = await loop.run_in_executor(None, fd.read, 1024 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            await loop.run_in_executor(None, fd.close)
    return gen()


def _withdrawn_error() -> HTTPException:
    return HTTPException(
        status_code=410,
        detail={"code": "image_withdrawn",
                "message": "image has been withdrawn and is no longer available"})


@app.get("/images/{image_id}", summary="按编号下载原片（流式解密，逐帧验签）")
async def download_image(image_id: str):
    meta = db.get_image(image_id)
    if meta is None:
        raise HTTPException(404, detail="image not found")
    if meta["status"] in ("deleting", "deleted"):
        raise _withdrawn_error()  # 撤下受理后立即禁止新下载
    if meta["status"] != "ready":
        raise HTTPException(409, detail=f"image is {meta['status']}")
    try:
        # 解包一次：明文 DEK 只在本次请求内存；随后即使密钥服务变慢或
        # 主密钥被销毁，已解包的慢下载也能完整读完（解密不再依赖密钥服务）。
        dek = await keys.unwrap(meta["master_key_id"], meta["wrapped_dek"])
    except KeyServiceError as exc:
        raise _key_error(exc)
    # 与撤下受理的竞态复核：解包往返期间若已被撤下，且尚未流出任何字节，
    # 则按新下载处理予以拒绝（已开始流式输出的下载不受此影响）。
    latest = db.get_image(image_id)
    if latest is None or latest["status"] != "ready":
        raise _withdrawn_error()
    # 先打开密文 fd 再开始流式响应：此后删除清退 unlink 文件不影响已打开
    # 的读取端（POSIX 语义），已经开始的下载必然完整结束。
    try:
        fd = open(meta["blob_path"], "rb")
    except FileNotFoundError:
        raise HTTPException(410, detail="encrypted blob already reclaimed")
    except OSError:
        raise HTTPException(410, detail="encrypted blob missing on storage")

    async def plain_iter():
        local_dek = dek  # 局部别名；生成器结束后随帧栈释放，不留长生命周期引用
        try:
            async for chunk in decrypt_stream(
                    _cipher_chunks(fd), local_dek,
                    expected_sha256=meta["sha256"]):
                yield chunk
        except IntegrityError as exc:
            raise HTTPException(500, detail=f"integrity check failed: {exc}")
        finally:
            del local_dek

    headers = {"X-Image-Id": image_id,
               "X-SHA256": meta["sha256"] or ""}
    if meta["filename"]:
        headers["Content-Disposition"] = (
            f'attachment; filename="{meta["filename"]}"')
    return StreamingResponse(
        plain_iter(),
        media_type=meta["content_type"] or "application/octet-stream",
        headers=headers)


@app.get("/images", summary="列出原片元数据")
async def list_images(limit: int = 100, offset: int = 0):
    return {"items": db.list_images(min(limit, 500), offset)}


@app.get("/images/{image_id}/meta", summary="单件原片元数据/状态")
async def image_meta(image_id: str):
    meta = db.get_image(image_id)
    if meta is None:
        raise HTTPException(404, detail="image not found")
    meta.pop("wrapped_dek", None)
    return meta


# --------------------------------------------------------------------------
# 撤下（删除）：仅受理已发布原片；受理即禁新下载；清退可续作、同号可重查
# --------------------------------------------------------------------------
def _deletion_view(rec: dict) -> dict:
    return {
        "image_id": rec["image_id"],
        "state": rec["state"],                       # pending/clearing/completed
        "envelope_erased": bool(rec["envelope_erased"]),
        "blob_removed": bool(rec["blob_removed"]),
        "attempts": rec["attempts"],
        "error": rec["error"],
        "requested_at": rec["requested_at"],
        "updated_at": rec["updated_at"],
        "finished_at": rec["finished_at"],
    }


@app.delete("/images/{image_id}", status_code=202,
            summary="撤下原片（仅受理已发布；最终清除密文与信封；同号重试返回进度）")
async def delete_image(image_id: str, response: Response):
    meta = db.get_image(image_id)
    if meta is None:
        raise HTTPException(404, detail="image not found")
    if meta["status"] == "ready":
        if db.accept_deletion(image_id):
            # 受理成功：状态已翻转为 deleting，新下载立即被禁；
            # 后台清退线程接续抹信封、删密文，重启后仍续作。
            return _deletion_view(db.get_deletion(image_id))
        meta = db.get_image(image_id)  # 与并发请求竞争落败，重读最新状态
    if meta["status"] in ("deleting", "deleted"):
        # 同号重试/重复撤下：幂等返回既有删除进度，不产生二次动作
        rec = db.get_deletion(image_id)
        if rec is None:  # 防御：状态与作业记录不一致（正常不会发生）
            raise HTTPException(500, detail="deletion record missing")
        if rec["state"] == "completed":
            response.status_code = 200
        return _deletion_view(rec)
    raise HTTPException(
        409, detail={"code": "image_not_published",
                     "message": f"only published (ready) images can be "
                                f"withdrawn; current status is {meta['status']}"})


@app.get("/images/{image_id}/deletion", summary="查询撤下进度（同号重试查询入口）")
async def deletion_status(image_id: str):
    rec = db.get_deletion(image_id)
    if rec is None:
        raise HTTPException(404, detail="no deletion recorded for this image")
    return _deletion_view(rec)


# --------------------------------------------------------------------------
# 轮换
# --------------------------------------------------------------------------
class RotationRequest(BaseModel):
    confirm: bool = True


@app.post("/rotations", status_code=202,
          summary="发起主密钥轮换（迁移信封后销毁旧 MK；未完拒绝新轮换）")
async def create_rotation(_: RotationRequest):
    active = db.active_rotation()
    if active is not None:
        raise HTTPException(
            409, detail={"code": "rotation_in_progress",
                         "job_id": active["job_id"], "state": active["state"]})
    try:
        rot = await keys.rotate_master()  # 新入湖立即改用新 MK
        old_key, new_key = rot["old_key_id"], rot["new_key_id"]
        total = (db.count_under_key(old_key, only_migratable=True)
                 if old_key else 0)
        job_id = db.create_rotation(old_key, new_key, total)
    except KeyServiceError as exc:
        raise _key_error(exc)
    return {"job_id": job_id, "state": "migrating", "old_key_id": old_key,
            "new_key_id": new_key, "total_to_migrate": total}


@app.get("/rotations/latest", summary="查询最近一次轮换进度")
async def latest_rotation():
    job = db.latest_rotation()
    if job is None:
        return {"message": "no rotation has ever run"}
    return _rotation_view(job)


@app.get("/rotations/{job_id}", summary="按作业号查询轮换进度")
async def rotation_status(job_id: str):
    job = db.get_rotation(job_id)
    if job is None:
        raise HTTPException(404, detail="rotation job not found")
    return _rotation_view(job)


def _rotation_view(job: dict) -> dict:
    total = max(job["total"], job["migrated"] + job["failed"], 1)
    pct = round(100.0 * (job["migrated"] + job["failed"]) / total, 2)
    return {**{k: v for k, v in job.items()}, "progress_percent": pct}


@app.get("/keys/status", summary="密钥视角状态（代理密钥服务只读接口）")
async def key_status():
    try:
        return await keys.master_status()
    except KeyServiceError as exc:
        raise _key_error(exc)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "image-api", "time": time.time()}
