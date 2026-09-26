from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import Principal
from app.archives.repository import DossierRepository
from app.services.audit import AuditService

BLOCKED_STATES = {"disposed", "pending_disposal", "quarantined"}
REVIEWABLE_STATES = {"in_review", "signing"}
SIGNER_PERMISSIONS = {
    "legal": "disclosure_packages.sign_legal",
    "security": "disclosure_packages.sign_security",
}
_DIGEST_KEYS = (
    "dossier_id", "dossier_version", "secrecy_level", "item_kind", "label",
    "confidential_until", "ownership_confirmed", "export_restricted",
    "auto_excluded", "auto_reason", "decision", "rationale",
)


def _parse_confidential_until(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = from_storage(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValidationError("保密期截止时间不是有效的 ISO-8601 时间") from exc
    if parsed is None:
        raise ValidationError("保密期截止时间不是有效的 ISO-8601 时间")
    return parsed


def _auto_reason(item: dict[str, Any], dossier_state: str, now: datetime) -> str:
    """按保密期、权属与出口管制规则给出自动剔除依据，空串表示无需剔除。"""
    if dossier_state in BLOCKED_STATES:
        return "档案状态禁止披露"
    if item["item_kind"] == "page_range":
        until = _parse_confidential_until(item.get("confidential_until"))
        if until is not None and until > now:
            return "仍在保密期"
    if item["item_kind"] == "attachment" and not item["ownership_confirmed"]:
        return "权属未确认"
    if item["item_kind"] == "field" and item["export_restricted"]:
        return "禁止出口"
    return ""


def _manifest_digest(items: list[dict[str, Any]]) -> str:
    """对排序后的清单条目生成稳定摘要，同一清单必得同一摘要。"""
    canonical_items = []
    for item in items:
        canonical_items.append({key: item[key] for key in _DIGEST_KEYS})
    canonical_items.sort(key=lambda entry: (entry["dossier_id"], entry["item_kind"], entry["label"]))
    canonical = json.dumps(canonical_items, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DossierContentService:
    """维护档案密级与内容条目（页码、附件、字段），是披露包自动剔除规则的底层数据。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def upsert_security_profile(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        dossier = self.dossiers.get(dossier_id)
        now = to_storage(self.clock.now())
        self.connection.execute(
            """INSERT INTO dossier_security_profiles(dossier_id,secrecy_level,updated_by,created_at,updated_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(dossier_id) DO UPDATE SET
                   secrecy_level=excluded.secrecy_level,
                   updated_by=excluded.updated_by,
                   updated_at=excluded.updated_at""",
            (dossier_id, data["secrecy_level"], principal.user_id, now, now),
        )
        profile = self.security_profile(dossier_id)
        self.dossiers.append_event(
            dossier_id,
            "security_profile.updated",
            principal.user_id,
            now,
            details={"secrecy_level": data["secrecy_level"]},
        )
        self.audit.record(
            principal,
            "dossier.security_profile",
            "dossier",
            str(dossier_id),
            after=profile,
            metadata={"dossier_code": dossier["dossier_code"]},
        )
        return profile

    def security_profile(self, dossier_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM dossier_security_profiles WHERE dossier_id=?", (dossier_id,)
        ).fetchone()
        if row:
            return dict(row)
        return {"dossier_id": dossier_id, "secrecy_level": "internal", "updated_by": None}

    def add_content_item(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        dossier = self.dossiers.get(dossier_id)
        _parse_confidential_until(data.get("confidential_until"))
        existing = self.connection.execute(
            "SELECT id FROM dossier_content_items WHERE dossier_id=? AND item_kind=? AND label=?",
            (dossier_id, data["item_kind"], data["label"]),
        ).fetchone()
        if existing:
            raise ConflictError("相同类型与名称的内容条目已经存在")
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            """INSERT INTO dossier_content_items(
                   dossier_id,item_kind,label,confidential_until,ownership_confirmed,export_restricted,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?)""",
            (
                dossier_id, data["item_kind"], data["label"], data.get("confidential_until"),
                int(data["ownership_confirmed"]), int(data["export_restricted"]), now, now,
            ),
        )
        item = self.content_item(cursor.lastrowid)
        self.dossiers.append_event(
            dossier_id,
            "content_item.registered",
            principal.user_id,
            now,
            details={"item_kind": data["item_kind"], "label": data["label"]},
        )
        self.audit.record(
            principal,
            "dossier.content_item.create",
            "dossier",
            str(dossier_id),
            after=item,
            metadata={"dossier_code": dossier["dossier_code"]},
        )
        return item

    def update_content_item(self, principal: Principal, dossier_id: int, item_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        self.dossiers.get(dossier_id)
        before = self.content_item(item_id)
        if before["dossier_id"] != dossier_id:
            raise NotFoundError("内容条目不属于该档案")
        merged = {
            "confidential_until": data.get("confidential_until", before["confidential_until"]),
            "ownership_confirmed": before["ownership_confirmed"] if data.get("ownership_confirmed") is None else int(data["ownership_confirmed"]),
            "export_restricted": before["export_restricted"] if data.get("export_restricted") is None else int(data["export_restricted"]),
        }
        _parse_confidential_until(merged["confidential_until"])
        now = to_storage(self.clock.now())
        self.connection.execute(
            """UPDATE dossier_content_items
               SET confidential_until=?,ownership_confirmed=?,export_restricted=?,updated_at=?
               WHERE id=?""",
            (merged["confidential_until"], merged["ownership_confirmed"], merged["export_restricted"], now, item_id),
        )
        after = self.content_item(item_id)
        self.dossiers.append_event(
            dossier_id,
            "content_item.updated",
            principal.user_id,
            now,
            details={"item_kind": before["item_kind"], "label": before["label"]},
        )
        self.audit.record(principal, "dossier.content_item.update", "dossier", str(dossier_id), before=before, after=after)
        return after

    def content_item(self, item_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM dossier_content_items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("内容条目不存在")
        return self._present_item(dict(row))

    def list_content_items(self, principal: Principal, dossier_id: int) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        self.dossiers.get(dossier_id)
        rows = self.connection.execute(
            "SELECT * FROM dossier_content_items WHERE dossier_id=? ORDER BY item_kind,label", (dossier_id,)
        ).fetchall()
        return [self._present_item(dict(row)) for row in rows]

    def _present_item(self, item: dict[str, Any]) -> dict[str, Any]:
        item["ownership_confirmed"] = bool(item["ownership_confirmed"])
        item["export_restricted"] = bool(item["export_restricted"])
        return item


class DisclosurePackageService:
    """披露包编排、审查、双角色签字与幂等发送登记。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.content = DossierContentService(connection, self.clock)
        self.audit = AuditService(connection, self.clock)

    # ---------- 编排 ----------

    def orchestrate(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("disclosure_packages.write")
        refs = data["dossiers"]
        dossier_ids = [ref["dossier_id"] for ref in refs]
        if len(set(dossier_ids)) != len(dossier_ids):
            raise ValidationError("披露包不能重复引用同一档案")
        package_code = data.get("package_code") or f"DPK-{uuid.uuid4().hex[:12]}"
        if self.connection.execute(
            "SELECT id FROM disclosure_packages WHERE package_code=?", (package_code,)
        ).fetchone():
            raise ConflictError("披露包编号已经存在")
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        items: list[dict[str, Any]] = []
        for ref in refs:
            dossier = self.dossiers.get(ref["dossier_id"])
            if dossier["version"] != ref["expected_version"]:
                raise ConflictError(
                    "档案版本已变化，请刷新后重试",
                    context={"dossier_id": ref["dossier_id"], "current_version": dossier["version"]},
                )
            if dossier["lifecycle_state"] in BLOCKED_STATES:
                raise ConflictError(
                    "档案当前状态禁止编排披露包",
                    context={"dossier_id": ref["dossier_id"], "lifecycle_state": dossier["lifecycle_state"]},
                )
            content_items = self.connection.execute(
                "SELECT * FROM dossier_content_items WHERE dossier_id=? ORDER BY item_kind,label",
                (ref["dossier_id"],),
            ).fetchall()
            if not content_items:
                raise ValidationError(
                    "档案尚未登记内容条目，无法编排披露包",
                    context={"dossier_id": ref["dossier_id"]},
                )
            secrecy_level = self.content.security_profile(ref["dossier_id"])["secrecy_level"]
            for content in content_items:
                items.append(self._build_item(dossier, secrecy_level, dict(content), now_dt))
        digest = _manifest_digest(items)
        cursor = self.connection.execute(
            """INSERT INTO disclosure_packages(package_code,recipient_code,purpose,state,manifest_digest,created_by,created_at,updated_at)
               VALUES(?,?,?,'in_review',?,?,?,?)""",
            (package_code, data["recipient_code"], data["purpose"], digest, principal.user_id, now, now),
        )
        package_id = int(cursor.lastrowid)
        for item in items:
            self._insert_item(package_id, item, now)
        self._append_event(package_id, "orchestrated", principal.user_id, now, {"manifest_digest": digest})
        package = self._package_row(package_id)
        self.audit.record(principal, "disclosure_package.orchestrate", "disclosure_package", str(package_id), after=package)
        return self._detail(package_id)

    def _build_item(
        self,
        dossier: dict[str, Any],
        secrecy_level: str,
        content: dict[str, Any],
        now: datetime,
    ) -> dict[str, Any]:
        candidate = {
            "item_kind": content["item_kind"],
            "label": content["label"],
            "confidential_until": content["confidential_until"],
            "ownership_confirmed": bool(content["ownership_confirmed"]),
            "export_restricted": bool(content["export_restricted"]),
        }
        reason = _auto_reason(candidate, dossier["lifecycle_state"], now)
        return {
            "dossier_id": dossier["id"],
            "dossier_version": dossier["version"],
            "secrecy_level": secrecy_level,
            **candidate,
            "auto_excluded": bool(reason),
            "auto_reason": reason,
            "decision": "excluded" if reason else "pending",
            "rationale": "",
            "decided_by": None,
            "decided_at": None,
        }

    def _insert_item(self, package_id: int, item: dict[str, Any], now: str) -> None:
        self.connection.execute(
            """INSERT INTO disclosure_package_items(
                   package_id,dossier_id,dossier_version,secrecy_level,item_kind,label,
                   confidential_until,ownership_confirmed,export_restricted,
                   auto_excluded,auto_reason,decision,rationale,decided_by,decided_at,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                package_id, item["dossier_id"], item["dossier_version"], item["secrecy_level"],
                item["item_kind"], item["label"], item["confidential_until"],
                int(item["ownership_confirmed"]), int(item["export_restricted"]),
                int(item["auto_excluded"]), item["auto_reason"], item["decision"],
                item["rationale"], item["decided_by"], item["decided_at"], now, now,
            ),
        )

    # ---------- 审查 ----------

    def decide_item(self, principal: Principal, package_id: int, item_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("disclosure_packages.write")
        package = self._sync_stale(self._package_row(package_id))
        if package["state"] not in REVIEWABLE_STATES:
            raise ConflictError("披露包当前状态不能审查，请先刷新重新进入审查")
        item = self._item_row(package_id, item_id)
        if item["auto_excluded"]:
            raise ConflictError("自动剔除的条目不允许人工调整")
        now = to_storage(self.clock.now())
        decision = "kept" if data["decision"] == "keep" else "excluded"
        self.connection.execute(
            """UPDATE disclosure_package_items
               SET decision=?,rationale=?,decided_by=?,decided_at=?,updated_at=?
               WHERE id=?""",
            (decision, data["rationale"], principal.user_id, now, now, item_id),
        )
        self._invalidate_signatures(package_id, principal.user_id, now, "审查决定变更")
        self._append_event(
            package_id,
            "item_decided",
            principal.user_id,
            now,
            {"item_id": item_id, "label": item["label"], "decision": decision, "rationale": data["rationale"]},
        )
        self._refresh_package_digest(package_id, "in_review", now)
        package = self._package_row(package_id)
        self.audit.record(
            principal,
            "disclosure_package.decide",
            "disclosure_package",
            str(package_id),
            metadata={"item_id": item_id, "decision": decision},
        )
        return self._detail(package_id)

    # ---------- 签字 ----------

    def sign(self, principal: Principal, package_id: int, data: dict[str, Any]) -> dict[str, Any]:
        signer_role = data["signer_role"]
        principal.require(SIGNER_PERMISSIONS[signer_role])
        package = self._sync_stale(self._package_row(package_id))
        if package["state"] not in REVIEWABLE_STATES:
            raise ConflictError("披露包当前状态不能签字")
        pending = self.connection.execute(
            "SELECT COUNT(*) FROM disclosure_package_items WHERE package_id=? AND decision='pending'",
            (package_id,),
        ).fetchone()[0]
        if pending:
            raise ConflictError("仍有待审查的条目，不能签字", context={"pending_items": pending})
        if self.connection.execute(
            "SELECT id FROM disclosure_package_signatures WHERE package_id=? AND signer_role=?",
            (package_id, signer_role),
        ).fetchone():
            raise ConflictError("该角色已经完成签字")
        if self.connection.execute(
            "SELECT id FROM disclosure_package_signatures WHERE package_id=? AND signer_user_id=?",
            (package_id, principal.user_id),
        ).fetchone():
            raise ConflictError("同一签字人只能以一种角色签字")
        now = to_storage(self.clock.now())
        self.connection.execute(
            """INSERT INTO disclosure_package_signatures(package_id,signer_user_id,signer_role,manifest_digest,signed_at)
               VALUES(?,?,?,?,?)""",
            (package_id, principal.user_id, signer_role, package["manifest_digest"], now),
        )
        self._append_event(
            package_id,
            "signed",
            principal.user_id,
            now,
            {"signer_role": signer_role, "manifest_digest": package["manifest_digest"]},
        )
        signed_count = self.connection.execute(
            "SELECT COUNT(*) FROM disclosure_package_signatures WHERE package_id=?", (package_id,)
        ).fetchone()[0]
        state = "signed" if signed_count >= package["required_signatures"] else "signing"
        self.connection.execute(
            "UPDATE disclosure_packages SET state=?,version=version+1,updated_at=? WHERE id=?",
            (state, now, package_id),
        )
        self.audit.record(
            principal,
            "disclosure_package.sign",
            "disclosure_package",
            str(package_id),
            metadata={"signer_role": signer_role, "state": state},
        )
        return self._detail(package_id)

    # ---------- 失效与重新审查 ----------

    def refresh(self, principal: Principal, package_id: int) -> dict[str, Any]:
        principal.require("disclosure_packages.write")
        package = self._sync_stale(self._package_row(package_id))
        if package["state"] in {"dispatched", "cancelled"}:
            raise ConflictError("已发送或已取消的披露包不能重新进入审查")
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        dossier_ids = [
            row[0]
            for row in self.connection.execute(
                "SELECT DISTINCT dossier_id FROM disclosure_package_items WHERE package_id=? ORDER BY dossier_id",
                (package_id,),
            ).fetchall()
        ]
        items: list[dict[str, Any]] = []
        for dossier_id in dossier_ids:
            dossier = self.dossiers.get(dossier_id)
            secrecy_level = self.content.security_profile(dossier_id)["secrecy_level"]
            content_items = self.connection.execute(
                "SELECT * FROM dossier_content_items WHERE dossier_id=? ORDER BY item_kind,label",
                (dossier_id,),
            ).fetchall()
            for content in content_items:
                items.append(self._build_item(dossier, secrecy_level, dict(content), now_dt))
        self.connection.execute("DELETE FROM disclosure_package_items WHERE package_id=?", (package_id,))
        for item in items:
            self._insert_item(package_id, item, now)
        self._invalidate_signatures(package_id, principal.user_id, now, "披露包重新进入审查")
        digest = _manifest_digest(items)
        self.connection.execute(
            "UPDATE disclosure_packages SET state='in_review',manifest_digest=?,version=version+1,updated_at=? WHERE id=?",
            (digest, now, package_id),
        )
        self._append_event(package_id, "refreshed", principal.user_id, now, {"manifest_digest": digest})
        self.audit.record(principal, "disclosure_package.refresh", "disclosure_package", str(package_id), before=package)
        return self._detail(package_id)

    def _sync_stale(self, package: dict[str, Any]) -> dict[str, Any]:
        """底层版本、密级或权属漂移时，让未完成发送的包重新进入审查。"""
        if package["state"] not in {"in_review", "signing", "signed"}:
            return package
        if self._live_digest(package["id"]) == package["manifest_digest"]:
            return package
        now = to_storage(self.clock.now())
        self._invalidate_signatures(package["id"], None, now, "底层档案数据变化")
        self.connection.execute(
            "UPDATE disclosure_packages SET state='stale',version=version+1,updated_at=? WHERE id=?",
            (now, package["id"]),
        )
        self._append_event(package["id"], "staled", None, now, {"reason": "底层版本、密级或权属发生变化"})
        return self._package_row(package["id"])

    def _live_digest(self, package_id: int) -> str:
        """按当前底层数据重算摘要，用于检测版本、密级、权属与保密期漂移。"""
        now_dt = self.clock.now()
        rows = self.connection.execute(
            "SELECT * FROM disclosure_package_items WHERE package_id=? ORDER BY dossier_id,item_kind,label",
            (package_id,),
        ).fetchall()
        live_items: list[dict[str, Any]] = []
        for row in rows:
            stored = dict(row)
            dossier_row = self.connection.execute(
                "SELECT * FROM dossiers WHERE id=?", (stored["dossier_id"],)
            ).fetchone()
            content_row = self.connection.execute(
                "SELECT * FROM dossier_content_items WHERE dossier_id=? AND item_kind=? AND label=?",
                (stored["dossier_id"], stored["item_kind"], stored["label"]),
            ).fetchone()
            if dossier_row is None or content_row is None:
                live_items.append({key: stored[key] for key in _DIGEST_KEYS} | {"dossier_version": -1})
                continue
            dossier = dict(dossier_row)
            content = dict(content_row)
            candidate = {
                "item_kind": content["item_kind"],
                "label": content["label"],
                "confidential_until": content["confidential_until"],
                "ownership_confirmed": bool(content["ownership_confirmed"]),
                "export_restricted": bool(content["export_restricted"]),
            }
            reason = _auto_reason(candidate, dossier["lifecycle_state"], now_dt)
            live_items.append(
                {
                    "dossier_id": dossier["id"],
                    "dossier_version": dossier["version"],
                    "secrecy_level": self.content.security_profile(dossier["id"])["secrecy_level"],
                    **candidate,
                    "auto_excluded": bool(reason),
                    "auto_reason": reason,
                    "decision": stored["decision"],
                    "rationale": stored["rationale"],
                }
            )
        return _manifest_digest(live_items)

    def _invalidate_signatures(self, package_id: int, actor_user_id: int | None, now: str, reason: str) -> None:
        count = self.connection.execute(
            "SELECT COUNT(*) FROM disclosure_package_signatures WHERE package_id=?", (package_id,)
        ).fetchone()[0]
        if not count:
            return
        self.connection.execute("DELETE FROM disclosure_package_signatures WHERE package_id=?", (package_id,))
        self._append_event(
            package_id,
            "signatures_invalidated",
            actor_user_id,
            now,
            {"reason": reason, "cleared_signatures": count},
        )

    def _refresh_package_digest(self, package_id: int, state: str, now: str) -> None:
        rows = self.connection.execute(
            "SELECT * FROM disclosure_package_items WHERE package_id=?", (package_id,)
        ).fetchall()
        items = []
        for row in rows:
            stored = dict(row)
            items.append(
                {
                    **{key: stored[key] for key in _DIGEST_KEYS},
                    "ownership_confirmed": bool(stored["ownership_confirmed"]),
                    "export_restricted": bool(stored["export_restricted"]),
                    "auto_excluded": bool(stored["auto_excluded"]),
                }
            )
        digest = _manifest_digest(items)
        self.connection.execute(
            "UPDATE disclosure_packages SET state=?,manifest_digest=?,version=version+1,updated_at=? WHERE id=?",
            (state, digest, now, package_id),
        )

    # ---------- 发送登记 ----------

    def dispatch(self, principal: Principal, package_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("disclosure_packages.dispatch")
        package = self._package_row(package_id)
        existing = self.connection.execute(
            "SELECT * FROM disclosure_dispatches WHERE package_id=?", (package_id,)
        ).fetchone()
        if existing:
            return {"record": dict(existing), "package": self._detail(package_id), "replayed": True}
        if self.connection.execute(
            "SELECT id FROM disclosure_dispatches WHERE idempotency_key=?", (data["idempotency_key"],)
        ).fetchone():
            raise ConflictError("幂等键已被其他披露包使用")
        package = self._sync_stale(package)
        if package["state"] == "stale":
            raise ConflictError("底层数据已变化，披露包需重新审查后再发送")
        if package["state"] != "signed":
            raise ConflictError("披露包尚未完成双人签字，不能登记发送")
        signatures = self.connection.execute(
            "SELECT * FROM disclosure_package_signatures WHERE package_id=?", (package_id,)
        ).fetchall()
        if len(signatures) < package["required_signatures"] or any(
            row["manifest_digest"] != package["manifest_digest"] for row in signatures
        ):
            raise ConflictError("签字与当前清单摘要不一致，不能登记发送")
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            """INSERT INTO disclosure_dispatches(package_id,idempotency_key,recipient_code,manifest_digest,dispatched_by,note,dispatched_at,created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                package_id, data["idempotency_key"], package["recipient_code"],
                package["manifest_digest"], principal.user_id, data.get("note", ""), now, now,
            ),
        )
        self.connection.execute(
            "UPDATE disclosure_packages SET state='dispatched',version=version+1,updated_at=? WHERE id=?",
            (now, package_id),
        )
        self._append_event(
            package_id,
            "dispatched",
            principal.user_id,
            now,
            {"idempotency_key": data["idempotency_key"], "manifest_digest": package["manifest_digest"]},
        )
        record = dict(
            self.connection.execute("SELECT * FROM disclosure_dispatches WHERE id=?", (cursor.lastrowid,)).fetchone()
        )
        self.audit.record(
            principal,
            "disclosure_package.dispatch",
            "disclosure_package",
            str(package_id),
            metadata={"idempotency_key": data["idempotency_key"]},
        )
        return {"record": record, "package": self._detail(package_id), "replayed": False}

    # ---------- 查询 ----------

    def detail(self, principal: Principal, package_id: int) -> dict[str, Any]:
        principal.require("disclosure_packages.read")
        return self._detail(package_id)

    def _detail(self, package_id: int) -> dict[str, Any]:
        package = self._package_row(package_id)
        if package["state"] in {"in_review", "signing", "signed"}:
            underlying_changed = self._live_digest(package_id) != package["manifest_digest"]
        else:
            underlying_changed = package["state"] == "stale"
        # 读路径同样落实失效转移，连接处于自动提交模式，转移与事件立即持久化。
        package = self._sync_stale(package)
        items = [
            self._present_package_item(dict(row))
            for row in self.connection.execute(
                """SELECT i.*,d.dossier_code,u.display_name AS decided_by_name
                   FROM disclosure_package_items i
                   JOIN dossiers d ON d.id=i.dossier_id
                   LEFT JOIN users u ON u.id=i.decided_by
                   WHERE i.package_id=? ORDER BY i.dossier_id,i.item_kind,i.label""",
                (package_id,),
            ).fetchall()
        ]
        signatures = [
            dict(row)
            for row in self.connection.execute(
                """SELECT s.*,u.display_name AS signer_name
                   FROM disclosure_package_signatures s JOIN users u ON u.id=s.signer_user_id
                   WHERE s.package_id=? ORDER BY s.id""",
                (package_id,),
            ).fetchall()
        ]
        dispatch_row = self.connection.execute(
            """SELECT x.*,u.display_name AS dispatched_by_name
               FROM disclosure_dispatches x JOIN users u ON u.id=x.dispatched_by
               WHERE x.package_id=?""",
            (package_id,),
        ).fetchone()
        events = [
            dict(row)
            for row in self.connection.execute(
                """SELECT e.*,u.display_name AS actor_name
                   FROM disclosure_package_events e LEFT JOIN users u ON u.id=e.actor_user_id
                   WHERE e.package_id=? ORDER BY e.id""",
                (package_id,),
            ).fetchall()
        ]
        for event in events:
            event["details"] = json.loads(event.pop("details_json"))
        counts = {
            "kept": sum(1 for item in items if item["decision"] == "kept"),
            "excluded": sum(1 for item in items if item["decision"] == "excluded"),
            "pending": sum(1 for item in items if item["decision"] == "pending"),
        }
        return {
            **package,
            "effective_state": package["state"],
            "underlying_changed": underlying_changed,
            "items": items,
            "excluded_items": [item for item in items if item["decision"] == "excluded"],
            "counts": counts,
            "signatures": signatures,
            "dispatch": dict(dispatch_row) if dispatch_row else None,
            "events": events,
        }

    def list(self, principal: Principal, state: str | None) -> list[dict[str, Any]]:
        principal.require("disclosure_packages.read")
        rows = self.connection.execute(
            "SELECT * FROM disclosure_packages ORDER BY id DESC"
        ).fetchall()
        result = []
        for row in rows:
            package = self._sync_stale(dict(row))
            if state and package["state"] != state:
                continue
            counts = dict(
                self.connection.execute(
                    """SELECT
                           SUM(CASE WHEN decision='kept' THEN 1 ELSE 0 END) AS kept,
                           SUM(CASE WHEN decision='excluded' THEN 1 ELSE 0 END) AS excluded,
                           SUM(CASE WHEN decision='pending' THEN 1 ELSE 0 END) AS pending
                       FROM disclosure_package_items WHERE package_id=?""",
                    (package["id"],),
                ).fetchone()
            )
            result.append({**package, "effective_state": package["state"], "counts": counts})
        return result

    # ---------- 内部 helpers ----------

    def _package_row(self, package_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM disclosure_packages WHERE id=?", (package_id,)).fetchone()
        if row is None:
            raise NotFoundError("披露包不存在")
        return dict(row)

    def _item_row(self, package_id: int, item_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM disclosure_package_items WHERE id=? AND package_id=?", (item_id, package_id)
        ).fetchone()
        if row is None:
            raise NotFoundError("披露包条目不存在")
        return self._present_package_item(dict(row))

    def _present_package_item(self, item: dict[str, Any]) -> dict[str, Any]:
        item["ownership_confirmed"] = bool(item["ownership_confirmed"])
        item["export_restricted"] = bool(item["export_restricted"])
        item["auto_excluded"] = bool(item["auto_excluded"])
        return item

    def _append_event(
        self,
        package_id: int,
        event_type: str,
        actor_user_id: int | None,
        now: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.connection.execute(
            """INSERT INTO disclosure_package_events(package_id,event_type,actor_user_id,details_json,occurred_at)
               VALUES(?,?,?,?,?)""",
            (package_id, event_type, actor_user_id, json.dumps(details or {}, ensure_ascii=False), now),
        )
