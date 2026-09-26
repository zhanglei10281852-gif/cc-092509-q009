from __future__ import annotations


def _create_user(client, admin, username, display_name, role_codes):
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": username,
            "password": "Reviewer!234",
            "display_name": display_name,
            "role_codes": role_codes,
        },
    )
    assert response.status_code == 201, response.text
    login = client.post("/api/auth/login", json={"username": username, "password": "Reviewer!234"})
    assert login.status_code == 200, login.text
    return {"headers": {"Authorization": f"Bearer {login.json()['token']}"}, "body": login.json()}


def _bootstrap_dossier(client, admin, code="PKG-D-01"):
    vault = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={
            "code": f"V-{code}",
            "building": "档案楼",
            "room": "常温库",
            "cabinet": "一号柜",
            "shelf": "三层",
            "sensitivity": "normal",
            "capacity_units": 50,
        },
    )
    assert vault.status_code == 201, vault.text
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": f"IN-{code}", "project_code": "P-DISC", "expected_count": 1},
    )
    assert batch.status_code == 201, batch.text
    dossier = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": code,
            "intake_id": batch.json()["id"],
            "asset_type": "工艺技术文档",
            "secrecy_level": "internal",
            "quantity": 10,
            "unit": "册",
            "vault_id": vault.json()["id"],
        },
    )
    assert dossier.status_code == 201, dossier.text
    return dossier.json()


def _add_material(client, admin, dossier_id, code, kind, **kwargs):
    response = client.post(
        f"/api/dossiers/{dossier_id}/materials",
        headers=admin["headers"],
        json={"material_code": code, "material_kind": kind, "title": f"材料{code}", **kwargs},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _current_dossier(client, admin, dossier_id):
    response = client.get(f"/api/dossiers/{dossier_id}", headers=admin["headers"])
    assert response.status_code == 200, response.text
    return response.json()


def _standard_dossier(client, admin):
    dossier = _bootstrap_dossier(client, admin)
    _add_material(client, admin, dossier["id"], "PAGE-01", "page", confidential_until="2099-01-01T00:00:00+00:00")
    _add_material(client, admin, dossier["id"], "PAGE-02", "page", confidential_until="2020-01-01T00:00:00+00:00")
    _add_material(client, admin, dossier["id"], "ATT-01", "attachment", ownership_state="pending")
    _add_material(client, admin, dossier["id"], "ATT-02", "attachment")
    _add_material(client, admin, dossier["id"], "FLD-01", "field", export_restricted=True)
    return _current_dossier(client, admin, dossier["id"])


def _create_package(client, admin, dossier, **overrides):
    payload = {
        "title": "对合作方技术资料披露包",
        "partner_code": "PARTNER-01",
        "purpose": "联合研发技术资料交付",
        "items": [{"dossier_id": dossier["id"], "expected_version": dossier["version"]}],
    }
    payload.update(overrides)
    response = client.post("/api/disclosure-packages", headers=admin["headers"], json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _review_all(client, reviewer, package, overrides=None):
    overrides = overrides or {}
    for item in package["items"]:
        decision, rationale = overrides.get(item["material_code"], ("keep", "符合披露范围"))
        response = client.post(
            f"/api/disclosure-packages/{package['id']}/items/{item['id']}/review",
            headers=reviewer["headers"],
            json={"decision": decision, "rationale": rationale},
        )
        assert response.status_code == 200, response.text


def _sign(client, signer, package_id, role):
    return client.post(
        f"/api/disclosure-packages/{package_id}/signatures",
        headers=signer["headers"],
        json={"signer_role": role},
    )


def _detail(client, admin, package_id):
    response = client.get(f"/api/disclosure-packages/{package_id}", headers=admin["headers"])
    assert response.status_code == 200, response.text
    return response.json()


def test_orchestration_auto_excludes_and_digest_is_stable(client, admin):
    dossier = _standard_dossier(client, admin)
    package = _create_package(client, admin, dossier)
    assert package["state"] == "in_review"
    auto = {item["material_code"]: item["auto_decision"] for item in package["items"]}
    assert auto == {
        "PAGE-01": "excluded",
        "PAGE-02": "included",
        "ATT-01": "excluded",
        "ATT-02": "included",
        "FLD-01": "excluded",
    }
    reasons = {item["material_code"]: item["exclusion_reason"] for item in package["items"]}
    assert reasons["PAGE-01"] == "页码仍处于保密期"
    assert reasons["ATT-01"] == "附件权属未确认"
    assert reasons["FLD-01"] == "字段禁止出口"
    assert {item["material_code"] for item in package["excluded_items"]} == {"PAGE-01", "ATT-01", "FLD-01"}

    twin = _create_package(client, admin, dossier, title="复核对照包")
    assert twin["manifest_digest"] == package["manifest_digest"]


def test_create_rejects_stale_expected_version(client, admin):
    dossier = _standard_dossier(client, admin)
    response = client.post(
        "/api/disclosure-packages",
        headers=admin["headers"],
        json={
            "title": "版本过期披露包",
            "partner_code": "PARTNER-01",
            "purpose": "联合研发技术资料交付",
            "items": [{"dossier_id": dossier["id"], "expected_version": dossier["version"] + 1}],
        },
    )
    assert response.status_code == 409


def test_orchestration_requires_manage_permission(client, admin):
    outsider = _create_user(client, admin, "researcher01", "研究人员", ["researcher"])
    dossier = _standard_dossier(client, admin)
    response = client.post(
        "/api/disclosure-packages",
        headers=outsider["headers"],
        json={
            "title": "越权披露包",
            "partner_code": "PARTNER-01",
            "purpose": "联合研发技术资料交付",
            "items": [{"dossier_id": dossier["id"], "expected_version": dossier["version"]}],
        },
    )
    assert response.status_code == 403


def test_review_requires_rationale(client, admin):
    dossier = _standard_dossier(client, admin)
    package = _create_package(client, admin, dossier)
    item = package["items"][0]
    response = client.post(
        f"/api/disclosure-packages/{package['id']}/items/{item['id']}/review",
        headers=admin["headers"],
        json={"decision": "keep", "rationale": ""},
    )
    assert response.status_code == 422


def test_sign_requires_completed_review_and_distinct_roles(client, admin):
    legal = _create_user(client, admin, "legal03", "法务赵", ["legal_counsel"])
    security = _create_user(client, admin, "security03", "保密孙", ["security_officer"])
    dual = _create_user(client, admin, "dual01", "双角色人员", ["legal_counsel", "security_officer"])
    dossier = _standard_dossier(client, admin)
    package = _create_package(client, admin, dossier)

    early = _sign(client, legal, package["id"], "legal")
    assert early.status_code == 409

    _review_all(client, legal, package)

    wrong_role = _sign(client, security, package["id"], "legal")
    assert wrong_role.status_code == 403

    first = _sign(client, dual, package["id"], "legal")
    assert first.status_code == 201, first.text
    same_person = _sign(client, dual, package["id"], "security")
    assert same_person.status_code == 422
    repeated_role = _sign(client, legal, package["id"], "legal")
    assert repeated_role.status_code == 409

    done = _sign(client, security, package["id"], "security")
    assert done.status_code == 201, done.text
    assert done.json()["state"] == "signed"


def test_ownership_change_returns_unsigned_package_to_review(client, admin):
    legal = _create_user(client, admin, "legal02", "法务王", ["legal_counsel"])
    dossier = _standard_dossier(client, admin)
    package = _create_package(client, admin, dossier)
    _review_all(client, legal, package)
    signed = _sign(client, legal, package["id"], "legal")
    assert signed.status_code == 201, signed.text
    digest_before = signed.json()["manifest_digest"]

    materials = client.get(f"/api/dossiers/{dossier['id']}/materials", headers=admin["headers"]).json()
    attachment = next(item for item in materials if item["material_code"] == "ATT-01")
    updated = client.patch(
        f"/api/dossier-operations/materials/{attachment['id']}",
        headers=admin["headers"],
        json={"ownership_state": "confirmed"},
    )
    assert updated.status_code == 200, updated.text

    detail = _detail(client, admin, package["id"])
    assert detail["state"] == "in_review"
    assert detail["signatures"] == []
    assert detail["manifest_digest"] != digest_before
    assert detail["digest_stale"] is False
    att_item = next(item for item in detail["items"] if item["material_code"] == "ATT-01")
    assert att_item["review_decision"] == "pending"
    assert att_item["auto_decision"] == "included"
    refreshed = [event for event in detail["responsibility_chain"] if event["event_type"] == "package.refreshed"]
    assert refreshed


def test_secrecy_change_resets_review_progress(client, admin):
    dossier = _standard_dossier(client, admin)
    package = _create_package(client, admin, dossier)
    _review_all(client, admin, package)
    digest_before = _detail(client, admin, package["id"])["manifest_digest"]

    response = client.patch(
        f"/api/dossier-operations/{dossier['id']}/secrecy",
        headers=admin["headers"],
        json={"secrecy_level": "confidential", "expected_version": dossier["version"], "reason": "定密调整"},
    )
    assert response.status_code == 200, response.text

    detail = _detail(client, admin, package["id"])
    assert detail["manifest_digest"] != digest_before
    assert all(item["review_decision"] == "pending" for item in detail["items"])
    assert all(item["dossier_secrecy_level"] == "confidential" for item in detail["items"])


def test_new_material_joins_package_as_pending(client, admin):
    dossier = _standard_dossier(client, admin)
    package = _create_package(client, admin, dossier)
    _review_all(client, admin, package)

    _add_material(client, admin, dossier["id"], "PAGE-09", "page", confidential_until="2099-06-01T00:00:00+00:00")

    detail = _detail(client, admin, package["id"])
    new_item = next(item for item in detail["items"] if item["material_code"] == "PAGE-09")
    assert new_item["review_decision"] == "pending"
    assert new_item["auto_decision"] == "excluded"
    assert detail["state"] == "in_review"


def test_signed_package_blocks_dispatch_after_underlying_change(client, admin):
    legal = _create_user(client, admin, "legal04", "法务周", ["legal_counsel"])
    security = _create_user(client, admin, "security04", "保密吴", ["security_officer"])
    dossier = _standard_dossier(client, admin)
    package = _create_package(client, admin, dossier)
    _review_all(client, legal, package)
    assert _sign(client, legal, package["id"], "legal").status_code == 201
    assert _sign(client, security, package["id"], "security").status_code == 201

    materials = client.get(f"/api/dossiers/{dossier['id']}/materials", headers=admin["headers"]).json()
    attachment = next(item for item in materials if item["material_code"] == "ATT-01")
    updated = client.patch(
        f"/api/dossier-operations/materials/{attachment['id']}",
        headers=admin["headers"],
        json={"ownership_state": "confirmed"},
    )
    assert updated.status_code == 200, updated.text

    detail = _detail(client, admin, package["id"])
    assert detail["state"] == "signed"
    assert detail["digest_stale"] is True

    blocked = client.post(
        f"/api/disclosure-packages/{package['id']}/dispatch",
        headers=admin["headers"],
        json={"idempotency_key": "send-blocked"},
    )
    assert blocked.status_code == 409

    refreshed = client.post(f"/api/disclosure-packages/{package['id']}/refresh", headers=admin["headers"])
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["state"] == "in_review"
    assert refreshed.json()["signatures"] == []

    _review_all(client, legal, refreshed.json())
    assert _sign(client, legal, package["id"], "legal").status_code == 201
    assert _sign(client, security, package["id"], "security").status_code == 201
    sent = client.post(
        f"/api/disclosure-packages/{package['id']}/dispatch",
        headers=admin["headers"],
        json={"idempotency_key": "send-final"},
    )
    assert sent.status_code == 201, sent.text
    assert sent.json()["replayed"] is False


def test_full_review_sign_dispatch_flow(client, admin):
    legal = _create_user(client, admin, "legal01", "法务张", ["legal_counsel"])
    security = _create_user(client, admin, "security01", "保密李", ["security_officer"])
    dossier = _standard_dossier(client, admin)
    package = _create_package(client, admin, dossier)

    _review_all(
        client,
        legal,
        package,
        overrides={
            "PAGE-01": ("remove", "保密期未满，维持剔除"),
            "ATT-01": ("keep", "权属已线下确认"),
            "FLD-01": ("remove", "出口管制字段"),
        },
    )

    unsigned = client.post(
        f"/api/disclosure-packages/{package['id']}/dispatch",
        headers=admin["headers"],
        json={"idempotency_key": "send-early"},
    )
    assert unsigned.status_code == 409

    first = _sign(client, legal, package["id"], "legal")
    assert first.status_code == 201, first.text
    assert first.json()["state"] == "in_review"
    second = _sign(client, security, package["id"], "security")
    assert second.status_code == 201, second.text
    assert second.json()["state"] == "signed"

    sent = client.post(
        f"/api/disclosure-packages/{package['id']}/dispatch",
        headers=admin["headers"],
        json={"idempotency_key": "send-001", "note": "首批交付"},
    )
    assert sent.status_code == 201, sent.text
    assert sent.json()["replayed"] is False
    event_id = sent.json()["event"]["id"]

    replay = client.post(
        f"/api/disclosure-packages/{package['id']}/dispatch",
        headers=admin["headers"],
        json={"idempotency_key": "send-001"},
    )
    assert replay.status_code == 201
    assert replay.json()["replayed"] is True
    assert replay.json()["event"]["id"] == event_id

    other_key = client.post(
        f"/api/disclosure-packages/{package['id']}/dispatch",
        headers=admin["headers"],
        json={"idempotency_key": "send-002"},
    )
    assert other_key.json()["replayed"] is True
    assert other_key.json()["event"]["id"] == event_id

    detail = _detail(client, admin, package["id"])
    assert detail["state"] == "sent"
    assert detail["dispatch"]["id"] == event_id
    excluded = {item["material_code"]: item["reason"] for item in detail["excluded_items"]}
    assert set(excluded) == {"PAGE-01", "FLD-01"}
    assert excluded["PAGE-01"] == "保密期未满，维持剔除"
    att_item = next(item for item in detail["items"] if item["material_code"] == "ATT-01")
    assert att_item["effective_decision"] == "included"
    assert att_item["reviewer_name"] == "法务张"

    chain = [event["event_type"] for event in detail["responsibility_chain"]]
    assert chain[0] == "package.created"
    assert chain.count("package.item_reviewed") == 5
    assert chain.count("package.signed") == 2
    assert chain[-1] == "package.dispatched"
    signers = {signature["signer_role"]: signature["signer_name"] for signature in detail["signatures"]}
    assert signers == {"legal": "法务张", "security": "保密李"}
