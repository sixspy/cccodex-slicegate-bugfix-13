
import csv
import hashlib
import io
import secrets
import sqlite3
import threading
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = DATA / "app.db"
FRONTEND = ROOT / "frontend"
SESSIONS: dict[str, str] = {}

# ---- 凭证边界口径（全仓唯一口径，查询/详情/导出/页面共用，禁止换词） ----
NON_CREDENTIAL = "非放行凭证"
FORMAL_CREDENTIAL = "正式放行凭证"
BOUNDARY_ERR = "凭证口径偏了"
CONTENTION_KIND = "凭证争用"
BOUNDARY_NOTE = (
    "申请单仅为审批请求，属非放行凭证：申请单任何状态下均不得改变切片放行态、"
    "不得写成功流水、不得推消费水位；正式放行仅由管理员审批通过后经服务端事务写入，"
    "放行单号以 REL 开头，申请单号(REQ)不得顶替放行单号，只读令牌不得凭申请单推水位。"
)
PERMISSION_MATRIX = [
    {"role": "管理员", "can_create_request": True, "can_approve": True,
     "can_write_release": True, "can_push_watermark": True, "can_export": True},
    {"role": "只读", "can_create_request": True, "can_approve": False,
     "can_write_release": False, "can_push_watermark": False, "can_export": True},
]

# 同一申请单的裁决锁：审批入口与放行写入口抢同一申请单时在此排队，按角色裁决
_REQUEST_LOCKS: dict[int, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def request_lock(rid: int):
    with _LOCKS_GUARD:
        lk = _REQUEST_LOCKS.get(rid)
        if lk is None:
            lk = threading.Lock()
            _REQUEST_LOCKS[rid] = lk
    return lk


def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def sha(p: str) -> str:
    return hashlib.sha256(p.encode("utf-8")).hexdigest()


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def gen_no(prefix: str) -> str:
    return f"{prefix}-{datetime.now():%Y%m%d}-{secrets.token_hex(4).upper()}"


def ensure_users(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, password_sha TEXT NOT NULL, role TEXT NOT NULL)""")
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("admin", sha("123456"), "管理员"))
        conn.execute("INSERT INTO users VALUES (?,?,?)", ("viewer", sha("view123"), "只读"))


def _column_exists(conn, table: str, column: str) -> bool:
    return any(r["name"] == column for r in conn.execute(f"PRAGMA table_info({table})").fetchall())


class LoginIn(BaseModel):
    username: str
    password: str


def require_user(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    u = SESSIONS.get(authorization.removeprefix("Bearer ").strip())
    if not u:
        raise HTTPException(401, "登录已失效")
    return u


def current_user(authorization: str | None) -> sqlite3.Row:
    username = require_user(authorization)
    with connect() as c:
        row = c.execute("SELECT username, role FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        raise HTTPException(401, "登录已失效")
    return row


def require_admin(authorization: str | None) -> sqlite3.Row:
    """放行态/水位的唯一人治入口：仅管理员。只读令牌一律按凭证口径偏离拦截。"""
    user = current_user(authorization)
    if user["role"] != "管理员":
        raise HTTPException(
            403,
            f"{BOUNDARY_ERR}：{user['role']}令牌为只读身份，不得写正式放行、改放行态或推水位；"
            f"申请单属{NON_CREDENTIAL}，不构成放行依据。",
        )
    return user


PRODUCT = "日切放行"
SKELETON = "业务日分区切片登记后裁决完整度，完整才放行下游，并与消费水位对账"

app = FastAPI(title=PRODUCT)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def init_db():
    with connect() as conn:
        ensure_users(conn)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS slices(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          slice_no TEXT UNIQUE NOT NULL,
          biz_date TEXT NOT NULL,
          partition_key TEXT NOT NULL,
          row_count INTEGER NOT NULL,
          expected_count INTEGER NOT NULL,
          completeness TEXT NOT NULL,
          release_status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS releases(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          slice_id INTEGER NOT NULL,
          consumer TEXT NOT NULL,
          status TEXT NOT NULL,
          note TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS watermarks(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          consumer TEXT NOT NULL,
          biz_date TEXT NOT NULL,
          watermark TEXT NOT NULL,
          source_slice TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS release_requests(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          request_no TEXT UNIQUE NOT NULL,
          slice_id INTEGER NOT NULL,
          consumer TEXT NOT NULL,
          applicant TEXT NOT NULL,
          applicant_role TEXT NOT NULL,
          status TEXT NOT NULL,
          credential_kind TEXT NOT NULL,
          note TEXT NOT NULL,
          decided_by TEXT,
          decided_at TEXT,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS credential_contention(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          request_no TEXT NOT NULL,
          winner TEXT NOT NULL,
          loser TEXT NOT NULL,
          loser_role TEXT NOT NULL,
          loser_action TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """)
        # 既有本机库平滑升级：正式放行单号独立成列，申请单号永远无法顶替
        if not _column_exists(conn, "releases", "release_no"):
            conn.execute("ALTER TABLE releases ADD COLUMN release_no TEXT")
        conn.execute(
            "UPDATE releases SET release_no=? WHERE release_no IS NULL OR release_no=''",
            ("REL-LEGACY-" + "0000",),
        )
        rows = conn.execute("SELECT id, release_no FROM releases WHERE release_no='REL-LEGACY-0000'").fetchall()
        for r in rows:
            conn.execute("UPDATE releases SET release_no=? WHERE id=?", (f"REL-LEGACY-{r['id']:04d}", r["id"]))

        if conn.execute("SELECT COUNT(*) c FROM slices").fetchone()["c"] == 0:
            seed = [
                ("SL-2026-11-01-east", "2026-11-01", "east", 980, 1000, "部分完整", "未放行"),
                ("SL-2026-11-01-west", "2026-11-01", "west", 1000, 1000, "完整", "已放行"),
                ("SL-2026-11-02-east", "2026-11-02", "east", 0, 1000, "待检", "未放行"),
            ]
            for r in seed:
                conn.execute(
                    "INSERT INTO slices(slice_no,biz_date,partition_key,row_count,expected_count,completeness,release_status)"
                    " VALUES (?,?,?,?,?,?,?)", r)
            conn.execute(
                "INSERT INTO releases(slice_id,consumer,status,note,created_at,release_no)"
                " VALUES (2,'ads_order','成功','完整切片放行','2026-11-01T18:00:00','REL-20261101-0001')")
            conn.execute(
                "INSERT INTO watermarks(consumer,biz_date,watermark,source_slice)"
                " VALUES ('ads_order','2026-11-01','2026-11-01T18:00:00','SL-2026-11-01-west')")
        # 申请台示例：只读账号开出的申请单，恒为非放行凭证，不触碰放行态与水位
        if conn.execute("SELECT COUNT(*) c FROM release_requests").fetchone()["c"] == 0:
            conn.execute(
                "INSERT INTO release_requests(request_no,slice_id,consumer,applicant,applicant_role,status,"
                "credential_kind,note,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                ("REQ-20261117-0001", 1, "ads_order", "viewer", "只读", "待审批",
                 NON_CREDENTIAL, BOUNDARY_NOTE, "2026-11-17T09:30:00"))


@app.on_event("startup")
def _start():
    init_db()


@app.get("/api/health")
def health():
    with connect() as c:
        n = c.execute("SELECT COUNT(*) c FROM slices").fetchone()["c"]
    return {"ok": True, "product": PRODUCT, "skeleton": SKELETON, "slices": n, "db": str(DB_PATH)}


@app.post("/api/login")
def login(body: LoginIn):
    with connect() as c:
        row = c.execute("SELECT username, role FROM users WHERE username=? AND password_sha=?",
                        (body.username, sha(body.password))).fetchone()
    if not row:
        raise HTTPException(401, "账号或密码错误")
    tok = secrets.token_hex(16)
    SESSIONS[tok] = row["username"]
    return {"token": tok, "username": row["username"], "role": row["role"]}


@app.get("/api/slices")
def list_slices(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT * FROM slices ORDER BY id").fetchall()
    return {"items": [dict(r) for r in rows]}


class SliceIn(BaseModel):
    slice_no: str
    biz_date: str
    partition_key: str
    row_count: int
    expected_count: int


@app.post("/api/slices")
def add_slice(body: SliceIn, authorization: str | None = Header(default=None)):
    require_user(authorization)
    comp = "完整" if body.row_count >= body.expected_count and body.expected_count > 0 else (
        "部分完整" if body.row_count > 0 else "待检")
    with connect() as c:
        try:
            cur = c.execute(
                "INSERT INTO slices(slice_no,biz_date,partition_key,row_count,expected_count,completeness,release_status)"
                " VALUES (?,?,?,?,?,?,?)",
                (body.slice_no, body.biz_date, body.partition_key, body.row_count,
                 body.expected_count, comp, "未放行"),
            )
            return {"id": cur.lastrowid, "completeness": comp}
        except sqlite3.IntegrityError:
            raise HTTPException(409, "切片号已存在")


@app.post("/api/slices/{sid}/evaluate")
def evaluate(sid: int, authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        row = c.execute("SELECT * FROM slices WHERE id=?", (sid,)).fetchone()
        if not row:
            raise HTTPException(404, "切片不存在")
        comp = "完整" if row["row_count"] >= row["expected_count"] and row["expected_count"] > 0 else (
            "部分完整" if row["row_count"] > 0 else "待检")
        c.execute("UPDATE slices SET completeness=? WHERE id=?", (comp, sid))
    return {"id": sid, "completeness": comp}


# ---------------- 申请台（申请单：全状态只读的非放行凭证） ----------------

class RequestIn(BaseModel):
    slice_id: int
    consumer: str


@app.post("/api/requests")
def create_request(body: RequestIn, authorization: str | None = Header(default=None)):
    """任何登录角色（含只读）都可提申请；申请单永远不触碰放行态/成功流水/水位。"""
    user = current_user(authorization)
    with connect() as c:
        sl = c.execute("SELECT * FROM slices WHERE id=?", (body.slice_id,)).fetchone()
        if not sl:
            raise HTTPException(404, "切片不存在")
        for _ in range(3):
            request_no = gen_no("REQ")
            try:
                cur = c.execute(
                    "INSERT INTO release_requests(request_no,slice_id,consumer,applicant,applicant_role,status,"
                    "credential_kind,note,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (request_no, body.slice_id, body.consumer, user["username"], user["role"],
                     "待审批", NON_CREDENTIAL, BOUNDARY_NOTE, now()))
                break
            except sqlite3.IntegrityError:
                continue
        else:
            raise HTTPException(500, "申请单号冲突，请重试")
        # 明确不写 slices.release_status / releases / watermarks
        return {
            "id": cur.lastrowid,
            "request_no": request_no,
            "status": "待审批",
            "credential_kind": NON_CREDENTIAL,
            "credential_effect": "不具备放行效力",
            "boundary_note": BOUNDARY_NOTE,
        }


def _request_row(c: sqlite3.Connection, rid: int) -> sqlite3.Row | None:
    return c.execute("""SELECT q.*, s.slice_no, s.completeness, s.release_status
                        FROM release_requests q JOIN slices s ON s.id=q.slice_id
                        WHERE q.id=?""", (rid,)).fetchone()


@app.get("/api/requests")
def list_requests(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""SELECT q.*, s.slice_no, s.completeness AS slice_completeness,
                                   s.release_status AS slice_release_status
                            FROM release_requests q JOIN slices s ON s.id=q.slice_id
                            ORDER BY q.id DESC""").fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["credential_kind"] = NON_CREDENTIAL
        d["credential_effect"] = "不具备放行效力"
        d["boundary_note"] = BOUNDARY_NOTE
        items.append(d)
    return {"items": items, "credential_boundary": BOUNDARY_NOTE}


@app.get("/api/requests/export")
def export_requests(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""SELECT q.request_no, q.slice_id, s.slice_no, q.consumer, q.applicant,
                                   q.applicant_role, q.status, q.decided_by, q.created_at
                            FROM release_requests q JOIN slices s ON s.id=q.slice_id
                            ORDER BY q.id""").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["申请单号", "切片ID", "切片号", "下游", "申请人", "申请人角色",
                "申请状态", "审批人", "创建时间", "凭证口径", "凭证效力"])
    for r in rows:
        w.writerow([*tuple(r[k] for k in r.keys()), NON_CREDENTIAL, "不具备放行效力"])
    return PlainTextResponse(
        "﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="release_requests_non_credential.csv"'})


@app.get("/api/requests/{rid}")
def request_detail(rid: int, authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        row = _request_row(c, rid)
        if not row:
            raise HTTPException(404, "申请单不存在")
        contentions = c.execute(
            "SELECT * FROM credential_contention WHERE request_no=? ORDER BY id", (row["request_no"],)).fetchall()
    d = dict(row)
    d["credential_kind"] = NON_CREDENTIAL
    d["credential_effect"] = "不具备放行效力"
    d["boundary_note"] = BOUNDARY_NOTE  # 详情旁注：口径与列表/导出逐字一致
    d["contentions"] = [dict(x) for x in contentions]
    return d


def _record_contention(c: sqlite3.Connection, req: sqlite3.Row, loser: sqlite3.Row,
                       action: str, detail: str) -> None:
    c.execute(
        "INSERT INTO credential_contention(request_no,winner,loser,loser_role,loser_action,detail,created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (req["request_no"], req["decided_by"] or "先行裁决方", loser["username"], loser["role"],
         action, f"{CONTENTION_KIND}：{detail}", now()))


def _write_formal_release(c: sqlite3.Connection, slice_row: sqlite3.Row, consumer: str,
                          actor: str, note: str) -> str:
    """正式放行的唯一落笔处：放行态 + 成功流水(REL 单号) + 水位，同一事务内完成。"""
    release_no = gen_no("REL")
    ts = now()
    c.execute("UPDATE slices SET release_status='已放行' WHERE id=?", (slice_row["id"],))
    c.execute(
        "INSERT INTO releases(slice_id,consumer,status,note,created_at,release_no)"
        " VALUES (?,?,?,?,?,?)",
        (slice_row["id"], consumer, "成功", note, ts, release_no))
    c.execute(
        "INSERT INTO watermarks(consumer,biz_date,watermark,source_slice) VALUES (?,?,?,?)",
        (consumer, slice_row["biz_date"], ts, slice_row["slice_no"]))
    return release_no


def _tx_connect() -> sqlite3.Connection:
    c = connect()
    c.isolation_level = None
    c.execute("BEGIN IMMEDIATE")
    return c


@app.post("/api/requests/{rid}/approve")
def approve_request(rid: int, authorization: str | None = Header(default=None)):
    """乙门闩：仅管理员审批通过后，由服务端事务写正式放行；申请单本身保持只读。"""
    admin = require_admin(authorization)
    with request_lock(rid):
        c = _tx_connect()
        try:
            req = _request_row(c, rid)
            if not req:
                c.execute("ROLLBACK")
                raise HTTPException(404, "申请单不存在")
            if req["status"] != "待审批":
                # 后手排队入场后裁决失败：记凭证争用
                _record_contention(c, req, admin, "审批通过",
                                   f"申请单已由 {req['decided_by']} 裁决为{req['status']}，后手审批排队后驳回")
                c.execute("COMMIT")
                raise HTTPException(
                    409, f"{BOUNDARY_ERR}：申请单 {req['request_no']} 已被 {req['decided_by']} 裁决，"
                         f"后手动作按角色裁决排队后记为{CONTENTION_KIND}")
            sl = c.execute("SELECT * FROM slices WHERE id=?", (req["slice_id"],)).fetchone()
            if sl["completeness"] != "完整":
                c.execute("UPDATE release_requests SET status='审批驳回', decided_by=?, decided_at=?, note=?"
                          " WHERE id=?",
                          (admin["username"], now(),
                           f"管理员驳回：切片完整度为{sl['completeness']}，不满足放行条件。{BOUNDARY_NOTE}", rid))
                c.execute("COMMIT")
                raise HTTPException(409, "未完整禁止放行，申请单已驳回且未产生任何放行效力")
            release_no = _write_formal_release(c, sl, req["consumer"], admin["username"],
                                               f"管理员审批申请单 {req['request_no']} 后服务端事务放行")
            c.execute("UPDATE release_requests SET status='审批通过', decided_by=?, decided_at=? WHERE id=?",
                      (admin["username"], now(), rid))
            c.execute("COMMIT")
            return {"ok": True, "request_no": req["request_no"], "request_credential_kind": NON_CREDENTIAL,
                    "release_no": release_no, "release_credential_kind": FORMAL_CREDENTIAL}
        except HTTPException:
            raise
        except Exception:
            c.execute("ROLLBACK")
            raise
        finally:
            c.close()


@app.post("/api/requests/{rid}/reject")
def reject_request(rid: int, authorization: str | None = Header(default=None)):
    admin = require_admin(authorization)
    with request_lock(rid):
        c = _tx_connect()
        try:
            req = _request_row(c, rid)
            if not req:
                c.execute("ROLLBACK")
                raise HTTPException(404, "申请单不存在")
            if req["status"] != "待审批":
                _record_contention(c, req, admin, "审批驳回",
                                   f"申请单已由 {req['decided_by']} 裁决为{req['status']}，后手驳回排队后记争用")
                c.execute("COMMIT")
                raise HTTPException(
                    409, f"{BOUNDARY_ERR}：申请单 {req['request_no']} 已被裁决，后手动作记为{CONTENTION_KIND}")
            c.execute("UPDATE release_requests SET status='审批驳回', decided_by=?, decided_at=?, note=? WHERE id=?",
                      (admin["username"], now(), f"管理员驳回申请，申请单维持{NON_CREDENTIAL}。{BOUNDARY_NOTE}", rid))
            c.execute("COMMIT")
            return {"ok": True, "request_no": req["request_no"], "status": "审批驳回",
                    "credential_kind": NON_CREDENTIAL}
        except HTTPException:
            raise
        except Exception:
            c.execute("ROLLBACK")
            raise
        finally:
            c.close()


# ---------------- 放行写入口（正式凭证唯一客户端入口，管理员限定） ----------------

class ReleaseIn(BaseModel):
    consumer: str
    request_no: str | None = None
    release_no: str | None = None
    credential_no: str | None = None


@app.post("/api/slices/{sid}/release")
def release(sid: int, body: ReleaseIn, authorization: str | None = Header(default=None)):
    admin = require_admin(authorization)  # 只读令牌在此即被拦，detail 含“凭证口径偏了”

    # 禁止客户端拿申请单号打放行写接口 / 申请单号顶替放行单号
    if body.request_no:
        raise HTTPException(
            400, f"{BOUNDARY_ERR}：禁止持申请单号 {body.request_no} 打放行写接口，"
                 f"申请单号({NON_CREDENTIAL})不得顶替放行单号。")
    for no in (body.release_no, body.credential_no):
        if no and no.startswith("REQ-"):
            raise HTTPException(
                400, f"{BOUNDARY_ERR}：申请单号 {no} 不得顶替放行单号，正式放行单号由服务端以 REL 签发。")

    # 先定位该切片上的在途申请单，审批入口与写入口抢同一申请单时走同一把锁排队
    with connect() as probe:
        pending = probe.execute(
            "SELECT id FROM release_requests WHERE slice_id=? AND status='待审批' ORDER BY id LIMIT 1",
            (sid,)).fetchone()
    rid = pending["id"] if pending else None
    lock_ctx = request_lock(rid) if rid is not None else nullcontext()

    with lock_ctx:
        c = _tx_connect()
        try:
            sl = c.execute("SELECT * FROM slices WHERE id=?", (sid,)).fetchone()
            if not sl:
                c.execute("ROLLBACK")
                raise HTTPException(404, "切片不存在")
            req = c.execute("SELECT * FROM release_requests WHERE id=?", (rid,)).fetchone() if rid else None
            if req is not None and req["status"] != "待审批":
                # 排队期间已被审批入口先行裁决：后手记凭证争用
                _record_contention(c, req, admin, "放行写入",
                                   "排队期间审批入口已先行裁决该申请单，放行写入口后手落败")
                c.execute("COMMIT")
                raise HTTPException(
                    409, f"{BOUNDARY_ERR}：申请单 {req['request_no']} 已被先行裁决，"
                         f"本次放行写入按角色裁决排队后记为{CONTENTION_KIND}")
            if sl["completeness"] != "完整":
                c.execute(
                    "INSERT INTO releases(slice_id,consumer,status,note,created_at,release_no)"
                    " VALUES (?,?,?,?,?,?)",
                    (sid, body.consumer, "拒绝", "完整度未达标", now(), gen_no("REL")))
                c.execute("COMMIT")
                raise HTTPException(409, "未完整禁止放行")
            if sl["release_status"] == "已放行":
                c.execute("ROLLBACK")
                raise HTTPException(409, f"{BOUNDARY_ERR}：切片已持正式放行凭证，禁止重复放行")
            note = "管理员经放行写入口正式放行"
            if req is not None:
                note = f"管理员经放行写入口正式放行，关联申请单 {req['request_no']} 同步核销（申请单仍为{NON_CREDENTIAL}）"
            release_no = _write_formal_release(c, sl, body.consumer, admin["username"], note)
            if req is not None:
                c.execute(
                    "UPDATE release_requests SET status='审批通过', decided_by=?, decided_at=?, note=? WHERE id=?",
                    (admin["username"], now(),
                     f"放行写入口先行裁决，申请单同步核销；申请单本身始终为{NON_CREDENTIAL}。", req["id"]))
            c.execute("COMMIT")
            return {"ok": True, "release_no": release_no, "credential_kind": FORMAL_CREDENTIAL}
        except HTTPException:
            raise
        except Exception:
            c.execute("ROLLBACK")
            raise
        finally:
            c.close()


@app.get("/api/releases")
def list_releases(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""SELECT r.*, s.slice_no FROM releases r
                            JOIN slices s ON s.id=r.slice_id ORDER BY r.id DESC""").fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["credential_kind"] = FORMAL_CREDENTIAL if r["status"] == "成功" else NON_CREDENTIAL
        items.append(d)
    return {"items": items}


@app.get("/api/releases/export")
def export_releases(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""SELECT r.release_no, s.slice_no, r.consumer, r.status, r.note, r.created_at
                            FROM releases r JOIN slices s ON s.id=r.slice_id ORDER BY r.id""").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["放行单号", "切片号", "下游", "结果", "备注", "时间", "凭证口径"])
    for r in rows:
        kind = FORMAL_CREDENTIAL if r["status"] == "成功" else NON_CREDENTIAL
        w.writerow([r["release_no"], r["slice_no"], r["consumer"], r["status"], r["note"], r["created_at"], kind])
    return PlainTextResponse(
        "﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="releases_formal_credential.csv"'})


@app.get("/api/watermarks")
def list_wm(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT * FROM watermarks ORDER BY id DESC").fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["credential_kind"] = FORMAL_CREDENTIAL  # 水位只能由正式放行事务推出
        items.append(d)
    return {"items": items}


@app.get("/api/contention")
def list_contention(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("SELECT * FROM credential_contention ORDER BY id DESC").fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/permissions")
def permissions(authorization: str | None = Header(default=None)):
    require_user(authorization)
    return {"items": PERMISSION_MATRIX, "credential_boundary": BOUNDARY_NOTE,
            "request_credential_kind": NON_CREDENTIAL, "release_credential_kind": FORMAL_CREDENTIAL}


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
