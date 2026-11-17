
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app import app, init_db, BOUNDARY_ERR, NON_CREDENTIAL, FORMAL_CREDENTIAL, CONTENTION_KIND


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr("app.DB_PATH", tmp_path / "t.db")
    init_db()
    yield


def _login(c, username, password):
    r = c.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}


def _admin(c):
    return _login(c, "admin", "123456")


def _viewer(c):
    return _login(c, "viewer", "view123")


def _make_complete_slice(c, h, no="SL-T-1"):
    r = c.post("/api/slices", headers=h, json={
        "slice_no": no, "biz_date": "2026-11-04", "partition_key": "mid",
        "row_count": 10, "expected_count": 10})
    assert r.status_code == 200
    return r.json()["id"]


# ---------- 门闩一：申请单全状态下是只读的非放行凭证 ----------

def test_viewer_request_is_non_credential_and_moves_nothing():
    c = TestClient(app)
    admin = _admin(c)
    viewer = _viewer(c)
    sid = _make_complete_slice(c, admin)

    before_rel = len(c.get("/api/releases", headers=admin).json()["items"])
    before_wm = len(c.get("/api/watermarks", headers=admin).json()["items"])
    before_status = c.get("/api/slices", headers=admin).json()["items"][-1]["release_status"]

    r = c.post("/api/requests", headers=viewer, json={"slice_id": sid, "consumer": "ads_x"})
    assert r.status_code == 200
    body = r.json()
    assert body["request_no"].startswith("REQ-")
    assert body["credential_kind"] == NON_CREDENTIAL
    assert body["credential_effect"] == "不具备放行效力"

    after = c.get("/api/slices", headers=admin).json()["items"][-1]
    assert after["release_status"] == before_status == "未放行"
    assert len(c.get("/api/releases", headers=admin).json()["items"]) == before_rel
    assert len(c.get("/api/watermarks", headers=admin).json()["items"]) == before_wm

    # 列表、详情、导出三处口径必须逐字互证
    lst = c.get("/api/requests", headers=viewer).json()
    assert lst["items"][0]["credential_kind"] == NON_CREDENTIAL
    rid = lst["items"][0]["id"]
    detail = c.get(f"/api/requests/{rid}", headers=viewer).json()
    assert detail["boundary_note"] == lst["credential_boundary"]
    assert detail["credential_kind"] == NON_CREDENTIAL

    export = c.get("/api/requests/export", headers=viewer)
    assert export.status_code == 200
    text = export.content.decode("utf-8-sig")
    assert NON_CREDENTIAL in text and "不具备放行效力" in text
    assert "REL-" not in text  # 申请台导出里不得混出放行单号


def test_request_remains_non_credential_even_after_approval():
    c = TestClient(app)
    admin = _admin(c)
    sid = _make_complete_slice(c, admin)
    q = c.post("/api/requests", headers=admin, json={"slice_id": sid, "consumer": "ads_x"}).json()
    r = c.post(f"/api/requests/{q['id']}/approve", headers=admin)
    assert r.status_code == 200
    out = r.json()
    assert out["request_credential_kind"] == NON_CREDENTIAL
    assert out["release_no"].startswith("REL-")
    assert out["release_credential_kind"] == FORMAL_CREDENTIAL
    detail = c.get(f"/api/requests/{q['id']}", headers=admin).json()
    assert detail["credential_kind"] == NON_CREDENTIAL  # 申请单本身永不变凭证


# ---------- 门闩二：只读令牌不得审批、不得打放行写接口、不得推水位 ----------

def test_viewer_cannot_approve():
    c = TestClient(app)
    admin = _admin(c)
    viewer = _viewer(c)
    sid = _make_complete_slice(c, admin)
    q = c.post("/api/requests", headers=viewer, json={"slice_id": sid, "consumer": "ads_x"}).json()
    r = c.post(f"/api/requests/{q['id']}/approve", headers=viewer)
    assert r.status_code == 403
    assert BOUNDARY_ERR in r.json()["detail"]
    # 被拦后什么都没写
    assert c.get(f"/api/requests/{q['id']}", headers=admin).json()["status"] == "待审批"


def test_viewer_blocked_at_release_write_endpoint():
    c = TestClient(app)
    admin = _admin(c)
    viewer = _viewer(c)
    sid = _make_complete_slice(c, admin)
    r = c.post(f"/api/slices/{sid}/release", headers=viewer, json={"consumer": "ads_x"})
    assert r.status_code == 403
    assert BOUNDARY_ERR in r.json()["detail"]
    assert NON_CREDENTIAL in r.json()["detail"]
    sl = [s for s in c.get("/api/slices", headers=admin).json()["items"] if s["id"] == sid][0]
    assert sl["release_status"] == "未放行"


def test_request_no_cannot_impersonate_release_no():
    c = TestClient(app)
    admin = _admin(c)
    sid = _make_complete_slice(c, admin)
    # 持申请单号打放行写接口 → 拦截
    r1 = c.post(f"/api/slices/{sid}/release", headers=admin,
                json={"consumer": "ads_x", "request_no": "REQ-20261117-0001"})
    assert r1.status_code == 400 and BOUNDARY_ERR in r1.json()["detail"]
    # REQ 号顶替放行单号字段 → 拦截
    r2 = c.post(f"/api/slices/{sid}/release", headers=admin,
                json={"consumer": "ads_x", "release_no": "REQ-20261117-0001"})
    assert r2.status_code == 400 and BOUNDARY_ERR in r2.json()["detail"]
    r3 = c.post(f"/api/slices/{sid}/release", headers=admin,
                json={"consumer": "ads_x", "credential_no": "REQ-X"})
    assert r3.status_code == 400 and BOUNDARY_ERR in r3.json()["detail"]
    # 三次全部被拦，无放行、无水位
    sl = [s for s in c.get("/api/slices", headers=admin).json()["items"] if s["id"] == sid][0]
    assert sl["release_status"] == "未放行"


# ---------- 乙门闩主链路：管理员审批 → 服务端事务写正式放行 ----------

def test_admin_approval_writes_formal_release_transactionally():
    c = TestClient(app)
    admin = _admin(c)
    sid = _make_complete_slice(c, admin)
    q = c.post("/api/requests", headers=_viewer(c),
               json={"slice_id": sid, "consumer": "ads_x"}).json()
    r = c.post(f"/api/requests/{q['id']}/approve", headers=admin)
    assert r.status_code == 200
    rel_no = r.json()["release_no"]
    assert rel_no.startswith("REL-")

    # 申请台、成功流水、水位、切片态四证互对
    rels = c.get("/api/releases", headers=admin).json()["items"]
    mine = [x for x in rels if x["release_no"] == rel_no]
    assert len(mine) == 1 and mine[0]["status"] == "成功"
    assert mine[0]["credential_kind"] == FORMAL_CREDENTIAL
    wms = c.get("/api/watermarks", headers=admin).json()["items"]
    assert any(w["source_slice"] == "SL-T-1" and w["credential_kind"] == FORMAL_CREDENTIAL for w in wms)
    sl = [s for s in c.get("/api/slices", headers=admin).json()["items"] if s["id"] == sid][0]
    assert sl["release_status"] == "已放行"
    detail = c.get(f"/api/requests/{q['id']}", headers=admin).json()
    assert detail["status"] == "审批通过" and detail["decided_by"] == "admin"
    assert detail["credential_kind"] == NON_CREDENTIAL


def test_approve_incomplete_slice_rejects_without_release():
    c = TestClient(app)
    admin = _admin(c)
    # 种子切片 1 为部分完整
    q = c.post("/api/requests", headers=admin, json={"slice_id": 1, "consumer": "ads_x"}).json()
    r = c.post(f"/api/requests/{q['id']}/approve", headers=admin)
    assert r.status_code == 409
    detail = c.get(f"/api/requests/{q['id']}", headers=admin).json()
    assert detail["status"] == "审批驳回"
    assert detail["credential_kind"] == NON_CREDENTIAL
    sl = [s for s in c.get("/api/slices", headers=admin).json()["items"] if s["id"] == 1][0]
    assert sl["release_status"] == "未放行"
    assert not any(x["status"] == "成功" for x in c.get("/api/releases", headers=admin).json()["items"]
                   if x["slice_id"] == 1)


# ---------- 争用：同申请单并发裁决，按角色排队，后手留痕 ----------

def test_concurrent_approval_contention_recorded():
    c = TestClient(app)
    h1, h2 = _admin(c), _admin(c)
    sid = _make_complete_slice(c, h1)
    q = c.post("/api/requests", headers=h1, json={"slice_id": sid, "consumer": "ads_x"}).json()
    barrier = threading.Barrier(2)

    def approve(h):
        barrier.wait()
        return c.post(f"/api/requests/{q['id']}/approve", headers=h)

    with ThreadPoolExecutor(max_workers=2) as ex:
        rs = list(ex.map(approve, [h1, h2]))
    codes = sorted(r.status_code for r in rs)
    assert codes == [200, 409]
    loser = [r for r in rs if r.status_code == 409][0].json()["detail"]
    assert BOUNDARY_ERR in loser and CONTENTION_KIND in loser

    ct = c.get("/api/contention", headers=h1).json()["items"]
    assert len(ct) == 1
    assert ct[0]["request_no"] == q["request_no"]
    assert ct[0]["winner"] == "admin" and ct[0]["loser"] == "admin"
    assert "凭证争用" in ct[0]["detail"]
    # 正式放行只落一笔
    succ = [x for x in c.get("/api/releases", headers=h1).json()["items"]
            if x["slice_id"] == sid and x["status"] == "成功"]
    assert len(succ) == 1
    wms = [w for w in c.get("/api/watermarks", headers=h1).json()["items"]
           if w["source_slice"] == "SL-T-1"]
    assert len(wms) == 1
    # 争用记录在申请单详情旁注里可互证
    detail = c.get(f"/api/requests/{q['id']}", headers=h1).json()
    assert len(detail["contentions"]) == 1


def test_approve_and_release_writer_race_on_same_request():
    c = TestClient(app)
    h1, h2 = _admin(c), _admin(c)
    sid = _make_complete_slice(c, h1)
    q = c.post("/api/requests", headers=h1, json={"slice_id": sid, "consumer": "ads_x"}).json()
    barrier = threading.Barrier(2)

    def call(kind):
        barrier.wait()
        if kind == "approve":
            return c.post(f"/api/requests/{q['id']}/approve", headers=h1)
        return c.post(f"/api/slices/{sid}/release", headers=h2, json={"consumer": "ads_x"})

    with ThreadPoolExecutor(max_workers=2) as ex:
        rs = list(ex.map(call, ["approve", "release"]))
    codes = sorted(r.status_code for r in rs)
    assert codes == [200, 409]
    ct = c.get("/api/contention", headers=h1).json()["items"]
    assert len(ct) == 1 and ct[0]["request_no"] == q["request_no"]
    succ = [x for x in c.get("/api/releases", headers=h1).json()["items"]
            if x["slice_id"] == sid and x["status"] == "成功"]
    assert len(succ) == 1


def test_viewer_loses_role_adjudication_under_race():
    c = TestClient(app)
    admin = _admin(c)
    viewer = _viewer(c)
    sid = _make_complete_slice(c, admin)
    q = c.post("/api/requests", headers=viewer, json={"slice_id": sid, "consumer": "ads_x"}).json()
    barrier = threading.Barrier(2)

    def call(kind):
        barrier.wait()
        if kind == "admin":
            return c.post(f"/api/requests/{q['id']}/approve", headers=admin)
        return c.post(f"/api/slices/{sid}/release", headers=viewer, json={"consumer": "ads_x"})

    with ThreadPoolExecutor(max_workers=2) as ex:
        rs = list(ex.map(call, ["admin", "viewer"]))
    by = {r.status_code: r for r in rs}
    assert 200 in by and 403 in by
    assert BOUNDARY_ERR in by[403].json()["detail"]
    # 管理员照常完成正式放行
    assert any(x["status"] == "成功" for x in c.get("/api/releases", headers=admin).json()["items"])


# ---------- 互证：权限列表、流水导出、拒绝不发水 ----------

def test_permission_matrix_matches_enforcement():
    c = TestClient(app)
    p = c.get("/api/permissions", headers=_viewer(c)).json()
    roles = {x["role"]: x for x in p["items"]}
    assert roles["只读"]["can_write_release"] is False
    assert roles["只读"]["can_approve"] is False
    assert roles["只读"]["can_push_watermark"] is False
    assert roles["只读"]["can_create_request"] is True
    assert roles["管理员"]["can_write_release"] is True
    assert p["request_credential_kind"] == NON_CREDENTIAL
    assert p["release_credential_kind"] == FORMAL_CREDENTIAL


def test_release_export_credential_columns():
    c = TestClient(app)
    admin = _admin(c)
    sid = _make_complete_slice(c, admin)
    c.post(f"/api/slices/{sid}/release", headers=admin, json={"consumer": "ads_x"})
    text = c.get("/api/releases/export", headers=admin).content.decode("utf-8-sig")
    lines = [ln for ln in text.splitlines() if ln]
    assert "凭证口径" in lines[0]
    assert any("REL-" in ln and FORMAL_CREDENTIAL in ln for ln in lines[1:])
    assert not any("REQ-" in ln for ln in lines[1:])


def test_rejected_request_flow_never_pushes_watermark():
    c = TestClient(app)
    admin = _admin(c)
    before = len(c.get("/api/watermarks", headers=admin).json()["items"])
    # 部分完整切片走放行写入口
    r = c.post("/api/slices/1/release", headers=admin, json={"consumer": "ads_x"})
    assert r.status_code == 409
    assert len(c.get("/api/watermarks", headers=admin).json()["items"]) == before


def test_duplicate_formal_release_blocked():
    c = TestClient(app)
    admin = _admin(c)
    sid = _make_complete_slice(c, admin)
    assert c.post(f"/api/slices/{sid}/release", headers=admin, json={"consumer": "a"}).status_code == 200
    r = c.post(f"/api/slices/{sid}/release", headers=admin, json={"consumer": "b"})
    assert r.status_code == 409 and BOUNDARY_ERR in r.json()["detail"]
