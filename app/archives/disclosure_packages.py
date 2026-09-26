"""对外披露包编排与双人审查流程。

市场部门向合作方发送技术资料前，法务要求先把一组档案及其版本编排成披露包：
系统按规则自动剔除仍在保密期的页码、未确认权属的附件和禁止出口的字段，
生成稳定的清单摘要；审查人逐项标记保留或剔除并说明依据；法务与保密两名
不同角色签字后才能登记发送。底层档案版本、密级或材料权属一旦变化，未签字
的包会重新进入审查；已签字的包在摘要漂移时无法发送，必须显式刷新重审。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import Principal
from app.archives.repository import DossierRepository
from app.archives.validation import parse_timestamp, require_code
from app.services.audit import AuditService

SIGNER_ROLE_CODES = {"legal": "legal_counsel", "security": "security_officer"}
REQUIRED_SIGNER_ROLES = tuple(sorted(SIGNER_ROLE_CODES))
BLOCKED_LIFECYCLE_STATES = {"disposed", "pending_disposal", "quarantined"}


def _evaluate_material(material: dict[str, Any], now: datetime) -> tuple[str, str | None]:
    """按披露规则自动判定材料条目是否进入清单。"""
    if material["material_kind"] == "page" and material.get("confidential_until"):
        until = from_storage(material["confidential_until"])
        if until and until > now:
            return "excluded", "页码仍处于保密期"
    if material["material_kind"] == "attachment" and material["ownership_state"] != "confirmed":
        return "excluded", "附件权属未确认"
    if material["material_kind"] == "field" and material["export_restricted"]:
        return "excluded", "字段禁止出口"
    return "included", None


def _manifest_digest(items: list[dict[str, Any]]) -> str:
    """对清单内容做确定性摘要：同样的档案版本与审查结论得到同样的摘要。"""
    canonical_items = [
        {
            "dossier_code": item["dossier_code"],
            "dossier_version": item["dossier_version"],
            "secrecy_level": item["dossier_secrecy_level"],
            "material_code": item["material_code"],
            "material_kind": item["material_kind"],
            "material_version": item["material_version"],
            "confidential_until": item["confidential_until"],
            "ownership_state": item["ownership_state"],
            "export_restricted": int(item["export_restricted"]),
            "auto_decision": item["auto_decision"],
            "exclusion_reason": item["exclusion_reason"],
            "review_decision": item["review_decision"],
            "review_note": item["review_note"],
        }
        for item in items
    ]
    canonical_items.sort(key=lambda entry: (entry["dossier_code"], entry["material_code"]))
    canonical = json.dumps(canonical_items, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _effective_decision(item: dict[str, Any]) -> str:
    if item["review_decision"] == "keep":
        return "included"
    if item["review_decision"] == "remove":
        return "excluded"
    return item["auto_decision"]


def _row(row: sqlite3.Row | None, message: str) -> dict[str, Any]:
    if row is None:
        raise NotFoundError(message)
    return dict(row)


class DossierMaterialRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def create(self, dossier_id: int, data: dict[str, Any], now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO dossier_materials(
                   dossier_id,material_code,material_kind,title,confidential_until,
                   ownership_state,export_restricted,created_at,updated_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                dossier_id, data["material_code"], data["material_kind"], data["title"],
                data.get("confidential_until"), data.get("ownership_state", "confirmed"),
                int(bool(data.get("export_restricted"))), now, now,
            ),
        )
        return self.get(cursor.lastrowid)

    def get(self, material_id: int) -> dict[str, Any]:
        return _row(
            self.connection.execute("SELECT * FROM dossier_materials WHERE id=?", (material_id,)).fetchone(),
            "披露材料不存在",
        )

    def by_code(self, dossier_id: int, material_code: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM dossier_materials WHERE dossier_id=? AND material_code=?",
            (dossier_id, material_code),
        ).fetchone()
        return dict(row) if row else None

    def for_dossier(self, dossier_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM dossier_materials WHERE dossier_id=? ORDER BY material_code,id",
            (dossier_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def update(self, material_id: int, changes: dict[str, Any], now: str) -> dict[str, Any]:
        assignments = ",".join(f"{key}=?" for key in changes)
        params = list(changes.values())
        self.connection.execute(
            f"UPDATE dossier_materials SET {assignments},version=version+1,updated_at=? WHERE id=?",
            (*params, now, material_id),
        )
        return self.get(material_id)


class DisclosurePackageRepository:
    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def create_package(self, data: dict[str, Any], created_by: int, now: str) -> dict[str, Any]:
        cursor = self.connection.execute(
            """INSERT INTO disclosure_packages(
                   package_code,title,partner_code,purpose,state,manifest_digest,
                   created_by,created_at,updated_at
               ) VALUES(?,?,?,?,'in_review','',?,?,?)""",
            (data["package_code"], data["title"], data["partner_code"], data["purpose"], created_by, now, now),
        )
        return self.get_package(cursor.lastrowid)

    def get_package(self, package_id: int) -> dict[str, Any]:
        return _row(
            self.connection.execute("SELECT * FROM disclosure_packages WHERE id=?", (package_id,)).fetchone(),
            "披露包不存在",
        )

    def by_code(self, package_code: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM disclosure_packages WHERE package_code=?", (package_code,)
        ).fetchone()
        return dict(row) if row else None

    def list_packages(self, state: str | None = None) -> list[dict[str, Any]]:
        sql = """SELECT p.*,
                        (SELECT COUNT(*) FROM disclosure_package_items i WHERE i.package_id=p.id) AS item_count,
                        (SELECT COUNT(*) FROM disclosure_package_items i WHERE i.package_id=p.id AND i.review_decision='pending') AS pending_count,
                        (SELECT COUNT(*) FROM disclosure_package_signatures s WHERE s.package_id=p.id) AS signature_count
                 FROM disclosure_packages p"""
        params: tuple[Any, ...] = ()
        if state:
            sql += " WHERE p.state=?"
            params = (state,)
        sql += " ORDER BY p.id DESC"
        return [dict(row) for row in self.connection.execute(sql, params).fetchall()]

    def update_package_state(self, package_id: int, state: str, digest: str, now: str) -> dict[str, Any]:
        self.connection.execute(
            "UPDATE disclosure_packages SET state=?,manifest_digest=?,version=version+1,updated_at=? WHERE id=?",
            (state, digest, now, package_id),
        )
        return self.get_package(package_id)

    def refresh_digest(self, package_id: int, digest: str, now: str) -> None:
        self.connection.execute(
            "UPDATE disclosure_packages SET manifest_digest=?,version=version+1,updated_at=? WHERE id=?",
            (digest, now, package_id),
        )

    def insert_item(self, package_id: int, dossier: dict[str, Any], material: dict[str, Any], decision: str, reason: str | None, now: str) -> None:
        self.connection.execute(
            """INSERT INTO disclosure_package_items(
                   package_id,dossier_id,material_id,dossier_version,dossier_secrecy_level,
                   material_version,ownership_state,confidential_until,export_restricted,
                   auto_decision,exclusion_reason,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                package_id, dossier["id"], material["id"], dossier["version"], dossier["secrecy_level"],
                material["version"], material["ownership_state"], material["confidential_until"],
                int(material["export_restricted"]), decision, reason, now,
            ),
        )

    def items(self, package_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT i.*,d.dossier_code,m.material_code,m.material_kind,m.title AS material_title,
                      u.display_name AS reviewer_name
               FROM disclosure_package_items i
               JOIN dossiers d ON d.id=i.dossier_id
               JOIN dossier_materials m ON m.id=i.material_id
               LEFT JOIN users u ON u.id=i.reviewed_by
               WHERE i.package_id=? ORDER BY d.dossier_code,m.material_code,i.id""",
            (package_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_item(self, package_id: int, item_id: int) -> dict[str, Any]:
        return _row(
            self.connection.execute(
                "SELECT * FROM disclosure_package_items WHERE id=? AND package_id=?",
                (item_id, package_id),
            ).fetchone(),
            "披露包清单条目不存在",
        )

    def mark_item(self, item_id: int, decision: str, note: str, reviewer_id: int, now: str) -> None:
        self.connection.execute(
            """UPDATE disclosure_package_items
               SET review_decision=?,review_note=?,reviewed_by=?,reviewed_at=? WHERE id=?""",
            (decision, note, reviewer_id, now, item_id),
        )

    def reset_item(self, item_id: int, snapshot: dict[str, Any], decision: str, reason: str | None) -> None:
        self.connection.execute(
            """UPDATE disclosure_package_items
               SET dossier_version=?,dossier_secrecy_level=?,material_version=?,ownership_state=?,
                   confidential_until=?,export_restricted=?,auto_decision=?,exclusion_reason=?,
                   review_decision='pending',review_note=NULL,reviewed_by=NULL,reviewed_at=NULL
               WHERE id=?""",
            (
                snapshot["dossier_version"], snapshot["dossier_secrecy_level"], snapshot["material_version"],
                snapshot["ownership_state"], snapshot["confidential_until"], int(snapshot["export_restricted"]),
                decision, reason, item_id,
            ),
        )

    def signatures(self, package_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT s.*,u.display_name AS signer_name
               FROM disclosure_package_signatures s JOIN users u ON u.id=s.signer_user_id
               WHERE s.package_id=? ORDER BY s.id""",
            (package_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def add_signature(self, package_id: int, signer_id: int, signer_role: str, digest: str, now: str) -> None:
        self.connection.execute(
            """INSERT INTO disclosure_package_signatures(package_id,signer_user_id,signer_role,manifest_digest,signed_at)
               VALUES(?,?,?,?,?)""",
            (package_id, signer_id, signer_role, digest, now),
        )

    def clear_signatures(self, package_id: int) -> None:
        self.connection.execute("DELETE FROM disclosure_package_signatures WHERE package_id=?", (package_id,))

    def append_event(self, package_id: int, event_type: str, actor_user_id: int | None, now: str, details: dict[str, Any] | None = None) -> None:
        self.connection.execute(
            """INSERT INTO disclosure_package_events(package_id,event_type,actor_user_id,details_json,occurred_at)
               VALUES(?,?,?,?,?)""",
            (package_id, event_type, actor_user_id, json.dumps(details or {}, ensure_ascii=False), now),
        )

    def events(self, package_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT e.id,e.event_type,e.actor_user_id,u.display_name AS actor_name,e.details_json,e.occurred_at
               FROM disclosure_package_events e LEFT JOIN users u ON u.id=e.actor_user_id
               WHERE e.package_id=? ORDER BY e.id""",
            (package_id,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            result.append(item)
        return result

    def dispatch_by_key(self, idempotency_key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM external_disclosure_events WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        return dict(row) if row else None

    def dispatch_for_package(self, package_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM external_disclosure_events WHERE package_id=?", (package_id,)
        ).fetchone()
        return dict(row) if row else None

    def insert_dispatch(self, package_id: int, partner_code: str, digest: str, sent_by: int, idempotency_key: str, note: str, now: str) -> dict[str, Any]:
        event_code = f"EXT-{uuid.uuid4().hex[:12].upper()}"
        cursor = self.connection.execute(
            """INSERT INTO external_disclosure_events(
                   event_code,package_id,idempotency_key,partner_code,manifest_digest,sent_by,note,sent_at,created_at
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (event_code, package_id, idempotency_key, partner_code, digest, sent_by, note, now, now),
        )
        return _row(
            self.connection.execute("SELECT * FROM external_disclosure_events WHERE id=?", (cursor.lastrowid,)).fetchone(),
            "披露发送登记不存在",
        )

    def packages_in_review_for_dossier(self, dossier_id: int) -> list[int]:
        rows = self.connection.execute(
            """SELECT DISTINCT i.package_id FROM disclosure_package_items i
               JOIN disclosure_packages p ON p.id=i.package_id
               WHERE i.dossier_id=? AND p.state='in_review'""",
            (dossier_id,),
        ).fetchall()
        return [int(row[0]) for row in rows]


class MaterialService:
    """维护档案的披露材料条目，并把变更即时传播给未签字的披露包。"""

    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.materials = DossierMaterialRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def register(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        dossier = self.dossiers.get(dossier_id)
        data = {**data, "material_code": require_code(data["material_code"], "材料编号")}
        if self.materials.by_code(dossier_id, data["material_code"]):
            raise ConflictError("材料编号已经存在")
        if data.get("confidential_until"):
            data["confidential_until"] = to_storage(parse_timestamp(data["confidential_until"], "保密期截止时间"))
        now = to_storage(self.clock.now())
        material = self.materials.create(dossier_id, data, now)
        self._bump_dossier(dossier_id, now)
        self.dossiers.append_event(
            dossier_id, "material.registered", principal.user_id, now,
            details={"material_code": material["material_code"], "material_kind": material["material_kind"]},
        )
        self.audit.record(principal, "material.register", "dossier_material", str(material["id"]), after=material)
        self._propagate(dossier_id, principal, f"档案 {dossier['dossier_code']} 新增披露材料")
        return material

    def update(self, principal: Principal, material_id: int, changes: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        material = self.materials.get(material_id)
        allowed = {key: value for key, value in changes.items() if key in {"title", "confidential_until", "ownership_state", "export_restricted"}}
        if not allowed:
            raise ValidationError("没有可更新的材料字段")
        if isinstance(allowed.get("confidential_until"), str):
            allowed["confidential_until"] = to_storage(parse_timestamp(allowed["confidential_until"], "保密期截止时间"))
        if "export_restricted" in allowed:
            allowed["export_restricted"] = int(bool(allowed["export_restricted"]))
        now = to_storage(self.clock.now())
        updated = self.materials.update(material_id, allowed, now)
        self._bump_dossier(material["dossier_id"], now)
        self.dossiers.append_event(
            material["dossier_id"], "material.updated", principal.user_id, now,
            details={"material_code": material["material_code"], "changes": sorted(allowed)},
        )
        self.audit.record(principal, "material.update", "dossier_material", str(material_id), before=material, after=updated)
        self._propagate(material["dossier_id"], principal, f"材料 {material['material_code']} 发生变更")
        return updated

    def update_secrecy(self, principal: Principal, dossier_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("dossiers.write")
        dossier = self.dossiers.get(dossier_id)
        if dossier["secrecy_level"] == data["secrecy_level"]:
            return {"dossier": dossier, "replayed": True}
        now = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "UPDATE dossiers SET secrecy_level=?,version=version+1,updated_at=? WHERE id=? AND version=?",
            (data["secrecy_level"], now, dossier_id, data["expected_version"]),
        )
        if cursor.rowcount != 1:
            raise ConflictError("档案版本已变化，请刷新后重试")
        updated = self.dossiers.get(dossier_id)
        self.dossiers.append_event(
            dossier_id, "secrecy.changed", principal.user_id, now,
            details={"from": dossier["secrecy_level"], "to": data["secrecy_level"], "reason": data["reason"]},
        )
        self.audit.record(
            principal, "dossier.secrecy_update", "dossier", str(dossier_id),
            before=dossier, after=updated, metadata={"reason": data["reason"]},
        )
        self._propagate(dossier_id, principal, f"档案 {dossier['dossier_code']} 密级调整")
        return {"dossier": updated, "replayed": False}

    def list_for_dossier(self, principal: Principal, dossier_id: int) -> list[dict[str, Any]]:
        principal.require("dossiers.read")
        self.dossiers.get(dossier_id)
        return self.materials.for_dossier(dossier_id)

    def _bump_dossier(self, dossier_id: int, now: str) -> None:
        self.connection.execute(
            "UPDATE dossiers SET version=version+1,updated_at=? WHERE id=?", (now, dossier_id)
        )

    def _propagate(self, dossier_id: int, principal: Principal, reason: str) -> None:
        packages = DisclosurePackageService(self.connection, self.clock)
        packages.reenter_review_for_dossier(dossier_id, principal, reason)


class DisclosurePackageService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None):
        self.connection = connection
        self.clock = clock or SystemClock()
        self.dossiers = DossierRepository(connection)
        self.materials = DossierMaterialRepository(connection)
        self.packages = DisclosurePackageRepository(connection)
        self.audit = AuditService(connection, self.clock)

    # ------------------------------------------------------------------ 编排

    def create(self, principal: Principal, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("disclosure_packages.manage")
        package_code = data.get("package_code") or f"PKG-{uuid.uuid4().hex[:12].upper()}"
        package_code = require_code(package_code, "披露包编号")
        if self.packages.by_code(package_code):
            raise ConflictError("披露包编号已经存在")
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        seen: set[int] = set()
        prepared: list[tuple[dict[str, Any], dict[str, Any], str, str | None]] = []
        for entry in data["items"]:
            dossier = self.dossiers.get(entry["dossier_id"])
            if dossier["id"] in seen:
                raise ValidationError("披露包中档案重复", context={"dossier_code": dossier["dossier_code"]})
            seen.add(dossier["id"])
            if dossier["version"] != entry["expected_version"]:
                raise ConflictError(
                    "档案版本已变化，请刷新后重试",
                    context={"dossier_code": dossier["dossier_code"], "current_version": dossier["version"]},
                )
            if dossier["lifecycle_state"] in BLOCKED_LIFECYCLE_STATES:
                raise ConflictError(
                    "档案当前状态禁止对外披露",
                    context={"dossier_code": dossier["dossier_code"], "lifecycle_state": dossier["lifecycle_state"]},
                )
            materials = self.materials.for_dossier(dossier["id"])
            if not materials:
                raise ValidationError(
                    "档案尚未登记披露材料，无法编排",
                    context={"dossier_code": dossier["dossier_code"]},
                )
            for material in materials:
                decision, reason = _evaluate_material(material, now_dt)
                prepared.append((dossier, material, decision, reason))
        package = self.packages.create_package(
            {**data, "package_code": package_code}, principal.user_id, now
        )
        for dossier, material, decision, reason in prepared:
            self.packages.insert_item(package["id"], dossier, material, decision, reason, now)
        items = self.packages.items(package["id"])
        digest = _manifest_digest(items)
        self.packages.refresh_digest(package["id"], digest, now)
        excluded = [item for item in items if item["auto_decision"] == "excluded"]
        self.packages.append_event(
            package["id"], "package.created", principal.user_id, now,
            details={
                "dossier_count": len(seen),
                "item_count": len(items),
                "auto_excluded_count": len(excluded),
                "manifest_digest": digest,
            },
        )
        package = self.packages.get_package(package["id"])
        self.audit.record(
            principal, "disclosure_package.create", "disclosure_package", str(package["id"]),
            after=package, metadata={"manifest_digest": digest},
        )
        return self.detail(principal, package["id"])

    # ------------------------------------------------------------------ 审查

    def review_item(self, principal: Principal, package_id: int, item_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("disclosure_packages.review")
        package = self._sync_package(package_id, principal)
        if package["state"] != "in_review":
            raise ConflictError("披露包不在审查阶段")
        item = self.packages.get_item(package_id, item_id)
        now = to_storage(self.clock.now())
        self.packages.mark_item(item_id, data["decision"], data["rationale"], principal.user_id, now)
        items = self.packages.items(package_id)
        digest = _manifest_digest(items)
        self.packages.refresh_digest(package_id, digest, now)
        updated = next(entry for entry in items if entry["id"] == item_id)
        self.packages.append_event(
            package_id, "package.item_reviewed", principal.user_id, now,
            details={
                "material_code": updated["material_code"],
                "decision": data["decision"],
                "rationale": data["rationale"],
            },
        )
        self.audit.record(
            principal, "disclosure_package.review_item", "disclosure_package", str(package_id),
            before=item, after=updated, metadata={"manifest_digest": digest},
        )
        return {"item": updated, "manifest_digest": digest, "state": "in_review"}

    # ------------------------------------------------------------------ 签字

    def sign(self, principal: Principal, package_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("disclosure_packages.sign")
        package = self._sync_package(package_id, principal)
        if package["state"] != "in_review":
            raise ConflictError("披露包当前状态不能签字")
        signer_role = data["signer_role"]
        required_role = SIGNER_ROLE_CODES[signer_role]
        if not self._has_role(principal.user_id, required_role):
            raise PermissionDeniedError(f"签字人必须持有角色：{required_role}")
        items = self.packages.items(package_id)
        pending = [item["material_code"] for item in items if item["review_decision"] == "pending"]
        if pending:
            raise ConflictError("仍有清单条目未审查", context={"pending_material_codes": pending})
        signatures = self.packages.signatures(package_id)
        if any(signature["signer_role"] == signer_role for signature in signatures):
            raise ConflictError("该签字角色已完成签字")
        if any(signature["signer_user_id"] == principal.user_id for signature in signatures):
            raise ValidationError("同一签字人不能以多个角色签字")
        now = to_storage(self.clock.now())
        digest = package["manifest_digest"]
        self.packages.add_signature(package_id, principal.user_id, signer_role, digest, now)
        remaining = REQUIRED_SIGNER_ROLES[len(signatures) + 1:]
        state = "signed" if not remaining else "in_review"
        package = self.packages.update_package_state(package_id, state, digest, now)
        self.packages.append_event(
            package_id, "package.signed", principal.user_id, now,
            details={"signer_role": signer_role, "manifest_digest": digest},
        )
        self.audit.record(
            principal, "disclosure_package.sign", "disclosure_package", str(package_id),
            metadata={"signer_role": signer_role, "manifest_digest": digest},
        )
        return self.detail(principal, package_id)

    # ------------------------------------------------------------------ 刷新

    def refresh(self, principal: Principal, package_id: int) -> dict[str, Any]:
        principal.require("disclosure_packages.manage")
        self._sync_package(package_id, principal, allow_signed_revert=True)
        return self.detail(principal, package_id)

    def reenter_review_for_dossier(self, dossier_id: int, principal: Principal, reason: str) -> None:
        for package_id in self.packages.packages_in_review_for_dossier(dossier_id):
            self._sync_package(package_id, principal, reason=reason)

    # ------------------------------------------------------------------ 发送

    def dispatch(self, principal: Principal, package_id: int, data: dict[str, Any]) -> dict[str, Any]:
        principal.require("disclosure_packages.manage")
        package = self._sync_package(package_id, principal)
        existing = self.packages.dispatch_by_key(data["idempotency_key"])
        if existing:
            if existing["package_id"] != package_id:
                raise ConflictError("幂等键已被其他披露包占用")
            return {"event": existing, "package": package, "replayed": True}
        if package["state"] == "sent":
            event = self.packages.dispatch_for_package(package_id)
            return {"event": event, "package": package, "replayed": True}
        if package["state"] != "signed":
            raise ConflictError("披露包尚未完成双人签字")
        items = self.packages.items(package_id)
        if self._detect_changes(items):
            raise ConflictError("清单摘要已变化，披露包需重新审查签字")
        current_digest = _manifest_digest(items)
        if current_digest != package["manifest_digest"]:
            raise ConflictError("清单摘要已变化，披露包需重新审查签字")
        signatures = self.packages.signatures(package_id)
        roles = {signature["signer_role"] for signature in signatures}
        if len(signatures) != len(REQUIRED_SIGNER_ROLES) or roles != set(REQUIRED_SIGNER_ROLES):
            raise ConflictError("披露包尚未完成双人签字")
        if any(signature["manifest_digest"] != current_digest for signature in signatures):
            raise ConflictError("签字对应的清单摘要已失效，需重新签字")
        now = to_storage(self.clock.now())
        event = self.packages.insert_dispatch(
            package_id, package["partner_code"], current_digest, principal.user_id,
            data["idempotency_key"], data.get("note", ""), now,
        )
        package = self.packages.update_package_state(package_id, "sent", current_digest, now)
        self.packages.append_event(
            package_id, "package.dispatched", principal.user_id, now,
            details={"event_code": event["event_code"], "partner_code": package["partner_code"]},
        )
        self.audit.record(
            principal, "disclosure_package.dispatch", "disclosure_package", str(package_id),
            after=event, metadata={"manifest_digest": current_digest},
        )
        return {"event": event, "package": package, "replayed": False}

    # ------------------------------------------------------------------ 查询

    def detail(self, principal: Principal, package_id: int) -> dict[str, Any]:
        principal.require("disclosure_packages.read")
        package = self.packages.get_package(package_id)
        items = self.packages.items(package_id)
        stale = bool(self._detect_changes(items)) if package["state"] != "sent" else False
        for item in items:
            item["effective_decision"] = _effective_decision(item)
        excluded_items = [
            {
                "item_id": item["id"],
                "dossier_code": item["dossier_code"],
                "material_code": item["material_code"],
                "material_title": item["material_title"],
                "material_kind": item["material_kind"],
                "source": "review" if item["review_decision"] == "remove" else "auto",
                "reason": item["review_note"] if item["review_decision"] == "remove" else item["exclusion_reason"],
            }
            for item in items
            if item["effective_decision"] == "excluded"
        ]
        dispatch = self.packages.dispatch_for_package(package_id)
        return {
            **package,
            "items": items,
            "excluded_items": excluded_items,
            "signatures": self.packages.signatures(package_id),
            "dispatch": dispatch,
            "digest_stale": stale,
            "responsibility_chain": self.packages.events(package_id),
        }

    def list(self, principal: Principal, state: str | None) -> list[dict[str, Any]]:
        principal.require("disclosure_packages.read")
        return self.packages.list_packages(state)

    # ------------------------------------------------------------------ 同步

    def _sync_package(
        self,
        package_id: int,
        principal: Principal,
        *,
        allow_signed_revert: bool = False,
        reason: str = "底层档案版本、密级或权属发生变更",
    ) -> dict[str, Any]:
        package = self.packages.get_package(package_id)
        if package["state"] == "sent":
            return package
        items = self.packages.items(package_id)
        changes = self._detect_changes(items)
        if not changes:
            return package
        if package["state"] == "signed" and not allow_signed_revert:
            return package
        now_dt = self.clock.now()
        now = to_storage(now_dt)
        changed_labels: list[str] = []
        for kind, *payload in changes:
            if kind == "new":
                snapshot = payload[0]
                decision, exclusion = _evaluate_material(snapshot, now_dt)
                dossier = self.dossiers.get(snapshot["dossier_id"])
                material = self.materials.get(snapshot["material_id"])
                self.packages.insert_item(package_id, dossier, material, decision, exclusion, now)
                changed_labels.append(f"+{snapshot['material_code']}")
            else:
                item, snapshot = payload
                decision, exclusion = _evaluate_material(snapshot, now_dt)
                self.packages.reset_item(item["id"], snapshot, decision, exclusion)
                changed_labels.append(f"~{item['material_code']}")
        self.packages.clear_signatures(package_id)
        items = self.packages.items(package_id)
        digest = _manifest_digest(items)
        from_state = package["state"]
        updated = self.packages.update_package_state(package_id, "in_review", digest, now)
        self.packages.append_event(
            package_id, "package.refreshed", principal.user_id, now,
            details={"from_state": from_state, "reason": reason, "changed_items": changed_labels, "manifest_digest": digest},
        )
        self.audit.record(
            principal, "disclosure_package.refresh", "disclosure_package", str(package_id),
            before=package, after=updated, metadata={"reason": reason, "changed_items": changed_labels},
        )
        return updated

    def _detect_changes(self, items: list[dict[str, Any]]) -> list[tuple]:
        indexed = {(item["dossier_id"], item["material_id"]): item for item in items}
        changes: list[tuple] = []
        for dossier_id in sorted({item["dossier_id"] for item in items}):
            for snapshot in self._current_snapshots(dossier_id):
                item = indexed.get((dossier_id, snapshot["material_id"]))
                if item is None:
                    changes.append(("new", snapshot))
                elif self._snapshot_changed(item, snapshot):
                    changes.append(("updated", item, snapshot))
        return changes

    def _current_snapshots(self, dossier_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """SELECT m.id AS material_id,m.material_code,m.material_kind,m.version AS material_version,
                      m.ownership_state,m.confidential_until,m.export_restricted,
                      d.id AS dossier_id,d.version AS dossier_version,d.secrecy_level AS dossier_secrecy_level
               FROM dossier_materials m JOIN dossiers d ON d.id=m.dossier_id
               WHERE m.dossier_id=? ORDER BY m.material_code,m.id""",
            (dossier_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _snapshot_changed(item: dict[str, Any], snapshot: dict[str, Any]) -> bool:
        return (
            item["dossier_version"] != snapshot["dossier_version"]
            or item["dossier_secrecy_level"] != snapshot["dossier_secrecy_level"]
            or item["material_version"] != snapshot["material_version"]
            or item["ownership_state"] != snapshot["ownership_state"]
            or (item["confidential_until"] or None) != (snapshot["confidential_until"] or None)
            or int(item["export_restricted"]) != int(snapshot["export_restricted"])
        )

    def _has_role(self, user_id: int, role_code: str) -> bool:
        row = self.connection.execute(
            """SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id
               WHERE ur.user_id=? AND r.code=?""",
            (user_id, role_code),
        ).fetchone()
        return row is not None
