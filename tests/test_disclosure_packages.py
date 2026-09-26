from __future__ import annotations


def _bootstrap_dossier(client, admin, code="DP-SAMPLE"):
    vault = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={
            "code": f"V-{code}",
            "building": "档案楼",
            "room": "常温库",
            "cabinet": "一号柜",
            "shelf": "一层",
            "sensitivity": "normal",
            "capacity_units": 50,
        },
    ).json()
    batch = client.post(
        "/api/dossiers/batches",
        headers=admin["headers"],
        json={"intake_code": f"B-{code}", "project_code": "DP", "expected_count": 1},
    ).json()
    dossier = client.post(
        "/api/dossiers",
        headers=admin["headers"],
        json={
            "dossier_code": code,
            "intake_id": batch["id"],
            "asset_type": "工艺技术文档",
            "quantity": 10,
            "unit": "册",
            "vault_id": vault["id"],
        },
    ).json()
    return vault, batch, dossier


def _add_content(client, admin, dossier_id):
    items = [
        {"item_kind": "page_range", "label": "页码 12-18", "confidential_until": "2099-01-01T00:00:00+00:00"},
        {"item_kind": "attachment", "label": "附件A-配方表", "ownership_confirmed": False},
        {"item_kind": "field", "label": "字段:核心参数", "export_restricted": True},
        {"item_kind": "page_range", "label": "页码 1-3"},
    ]
    created = []
    for item in items:
        response = client.post(
            f"/api/dossiers/{dossier_id}/content-items", headers=admin["headers"], json=item
        )
        assert response.status_code == 201, response.text
        created.append(response.json())
    return created


def _make_user(client, admin, username, display_name, role_codes):
    created = client.post(
        "/api/users",
        headers=admin["headers"],
        json={
            "username": username,
            "password": "Review!23456",
            "display_name": display_name,
            "role_codes": role_codes,
        },
    )
    assert created.status_code == 201, created.text
    login = client.post(
        "/api/auth/login",
        json={"username": username, "password": "Review!23456", "client_label": "tests"},
    )
    assert login.status_code == 200, login.text
    return {"headers": {"Authorization": f"Bearer {login.json()['token']}"}}


def _orchestrate(client, admin, dossier, package_code="DPK-001"):
    response = client.post(
        "/api/disclosure-packages",
        headers=admin["headers"],
        json={
            "package_code": package_code,
            "recipient_code": "PARTNER-01",
            "purpose": "向合作伙伴提供技术资料",
            "dossiers": [{"dossier_id": dossier["id"], "expected_version": dossier["version"]}],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _decide_all_pending(client, admin, package):
    for item in package["items"]:
        if item["decision"] == "pending":
            response = client.post(
                f"/api/disclosure-packages/{package['id']}/items/{item['id']}/decision",
                headers=admin["headers"],
                json={"decision": "keep", "rationale": "内容已脱敏，可对外提供"},
            )
            assert response.status_code == 200, response.text
    return client.get(f"/api/disclosure-packages/{package['id']}", headers=admin["headers"]).json()


def _sign_both(client, legal, security, package_id):
    first = client.post(
        f"/api/disclosure-packages/{package_id}/signatures",
        headers=legal["headers"],
        json={"signer_role": "legal"},
    )
    assert first.status_code == 201, first.text
    assert first.json()["state"] == "signing"
    second = client.post(
        f"/api/disclosure-packages/{package_id}/signatures",
        headers=security["headers"],
        json={"signer_role": "security"},
    )
    assert second.status_code == 201, second.text
    return second.json()


def test_orchestration_auto_excludes_and_digest_is_stable(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    _add_content(client, admin, dossier["id"])
    package = _orchestrate(client, admin, dossier)
    assert package["state"] == "in_review"
    by_label = {item["label"]: item for item in package["items"]}
    assert by_label["页码 12-18"]["auto_excluded"] is True
    assert by_label["页码 12-18"]["auto_reason"] == "仍在保密期"
    assert by_label["附件A-配方表"]["auto_reason"] == "权属未确认"
    assert by_label["字段:核心参数"]["auto_reason"] == "禁止出口"
    assert by_label["页码 1-3"]["decision"] == "pending"
    assert package["counts"]["excluded"] == 3
    assert package["counts"]["pending"] == 1

    twin = _orchestrate(client, admin, dossier, package_code="DPK-002")
    assert twin["manifest_digest"] == package["manifest_digest"]


def test_review_decisions_and_dual_role_signoff(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    _add_content(client, admin, dossier["id"])
    legal = _make_user(client, admin, "legal.one", "法务甲", ["legal_counsel"])
    security = _make_user(client, admin, "security.one", "保密乙", ["security_officer"])
    package = _orchestrate(client, admin, dossier)

    premature = client.post(
        f"/api/disclosure-packages/{package['id']}/signatures",
        headers=legal["headers"],
        json={"signer_role": "legal"},
    )
    assert premature.status_code == 409

    pending_item = next(item for item in package["items"] if item["decision"] == "pending")
    kept = client.post(
        f"/api/disclosure-packages/{package['id']}/items/{pending_item['id']}/decision",
        headers=admin["headers"],
        json={"decision": "keep", "rationale": "仅含公开参数"},
    )
    assert kept.status_code == 200, kept.text
    assert kept.json()["manifest_digest"] != package["manifest_digest"]

    locked = next(item for item in package["items"] if item["auto_excluded"])
    rejected = client.post(
        f"/api/disclosure-packages/{package['id']}/items/{locked['id']}/decision",
        headers=admin["headers"],
        json={"decision": "keep", "rationale": "尝试保留自动剔除条目"},
    )
    assert rejected.status_code == 409

    signed = _sign_both(client, legal, security, package["id"])
    assert signed["state"] == "signed"
    assert {row["signer_role"] for row in signed["signatures"]} == {"legal", "security"}
    assert all(row["manifest_digest"] == signed["manifest_digest"] for row in signed["signatures"])

    duplicate_role = client.post(
        f"/api/disclosure-packages/{package['id']}/signatures",
        headers=legal["headers"],
        json={"signer_role": "legal"},
    )
    assert duplicate_role.status_code == 409


def test_same_user_cannot_sign_both_roles(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    _add_content(client, admin, dossier["id"])
    package = _decide_all_pending(client, admin, _orchestrate(client, admin, dossier))
    first = client.post(
        f"/api/disclosure-packages/{package['id']}/signatures",
        headers=admin["headers"],
        json={"signer_role": "legal"},
    )
    assert first.status_code == 201
    second = client.post(
        f"/api/disclosure-packages/{package['id']}/signatures",
        headers=admin["headers"],
        json={"signer_role": "security"},
    )
    assert second.status_code == 409


def test_decision_change_invalidates_existing_signatures(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    _add_content(client, admin, dossier["id"])
    legal = _make_user(client, admin, "legal.two", "法务丙", ["legal_counsel"])
    package = _decide_all_pending(client, admin, _orchestrate(client, admin, dossier))
    client.post(
        f"/api/disclosure-packages/{package['id']}/signatures",
        headers=legal["headers"],
        json={"signer_role": "legal"},
    )
    item = next(row for row in package["items"] if row["decision"] == "kept")
    changed = client.post(
        f"/api/disclosure-packages/{package['id']}/items/{item['id']}/decision",
        headers=admin["headers"],
        json={"decision": "exclude", "rationale": "复核后认为仍需保留在境内"},
    )
    assert changed.status_code == 200, changed.text
    body = changed.json()
    assert body["state"] == "in_review"
    assert body["signatures"] == []
    event_types = [event["event_type"] for event in body["events"]]
    assert "signatures_invalidated" in event_types
    excluded = next(row for row in body["excluded_items"] if row["id"] == item["id"])
    assert excluded["rationale"] == "复核后认为仍需保留在境内"


def test_underlying_version_change_forces_re_review(client, admin):
    vault, _, dossier = _bootstrap_dossier(client, admin)
    _add_content(client, admin, dossier["id"])
    legal = _make_user(client, admin, "legal.three", "法务丁", ["legal_counsel"])
    security = _make_user(client, admin, "security.three", "保密戊", ["security_officer"])
    package = _decide_all_pending(client, admin, _orchestrate(client, admin, dossier))
    _sign_both(client, legal, security, package["id"])

    target = client.post(
        "/api/dossiers/vaults",
        headers=admin["headers"],
        json={
            "code": "V-DP-TARGET",
            "building": "档案楼",
            "room": "低温库",
            "cabinet": "二号柜",
            "shelf": "一层",
            "sensitivity": "normal",
            "capacity_units": 50,
        },
    ).json()
    moved = client.post(
        f"/api/dossier-operations/{dossier['id']}/transfers",
        headers=admin["headers"],
        json={"vault_id": target["id"], "expected_version": dossier["version"], "reason": "调整库位"},
    )
    assert moved.status_code == 200, moved.text

    detail = client.get(f"/api/disclosure-packages/{package['id']}", headers=admin["headers"]).json()
    assert detail["state"] == "stale"
    assert detail["effective_state"] == "stale"
    assert detail["underlying_changed"] is True
    assert detail["signatures"] == []

    blocked = client.post(
        f"/api/disclosure-packages/{package['id']}/dispatch",
        headers=admin["headers"],
        json={"idempotency_key": "send-dp-001"},
    )
    assert blocked.status_code == 409

    refreshed = client.post(f"/api/disclosure-packages/{package['id']}/refresh", headers=admin["headers"])
    assert refreshed.status_code == 200, refreshed.text
    body = refreshed.json()
    assert body["state"] == "in_review"
    assert body["signatures"] == []
    assert body["counts"]["pending"] == 1
    assert any(event["event_type"] == "staled" for event in body["events"])

    renewed = _decide_all_pending(client, admin, body)
    _sign_both(client, legal, security, renewed["id"])
    dispatched = client.post(
        f"/api/disclosure-packages/{renewed['id']}/dispatch",
        headers=admin["headers"],
        json={"idempotency_key": "send-dp-001"},
    )
    assert dispatched.status_code == 201, dispatched.text
    assert dispatched.json()["replayed"] is False


def test_secrecy_and_ownership_changes_force_re_review(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    content = _add_content(client, admin, dossier["id"])
    legal = _make_user(client, admin, "legal.four", "法务己", ["legal_counsel"])
    security = _make_user(client, admin, "security.four", "保密庚", ["security_officer"])
    package = _decide_all_pending(client, admin, _orchestrate(client, admin, dossier))
    _sign_both(client, legal, security, package["id"])

    profile = client.put(
        f"/api/dossiers/{dossier['id']}/security-profile",
        headers=admin["headers"],
        json={"secrecy_level": "restricted"},
    )
    assert profile.status_code == 200, profile.text
    detail = client.get(f"/api/disclosure-packages/{package['id']}", headers=admin["headers"]).json()
    assert detail["effective_state"] == "stale"

    refreshed = client.post(f"/api/disclosure-packages/{package['id']}/refresh", headers=admin["headers"]).json()
    assert refreshed["items"][0]["secrecy_level"] == "restricted"
    renewed = _decide_all_pending(client, admin, refreshed)
    _sign_both(client, legal, security, renewed["id"])

    attachment = next(item for item in content if item["item_kind"] == "attachment")
    updated = client.patch(
        f"/api/dossiers/{dossier['id']}/content-items/{attachment['id']}",
        headers=admin["headers"],
        json={"ownership_confirmed": True},
    )
    assert updated.status_code == 200, updated.text
    detail = client.get(f"/api/disclosure-packages/{package['id']}", headers=admin["headers"]).json()
    assert detail["effective_state"] == "stale"

    refreshed = client.post(f"/api/disclosure-packages/{package['id']}/refresh", headers=admin["headers"]).json()
    by_label = {item["label"]: item for item in refreshed["items"]}
    assert by_label["附件A-配方表"]["auto_excluded"] is False
    assert by_label["附件A-配方表"]["decision"] == "pending"


def test_dispatch_is_idempotent_and_shows_responsibility_chain(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    _add_content(client, admin, dossier["id"])
    legal = _make_user(client, admin, "legal.five", "法务辛", ["legal_counsel"])
    security = _make_user(client, admin, "security.five", "保密壬", ["security_officer"])
    package = _decide_all_pending(client, admin, _orchestrate(client, admin, dossier))
    _sign_both(client, legal, security, package["id"])

    first = client.post(
        f"/api/disclosure-packages/{package['id']}/dispatch",
        headers=admin["headers"],
        json={"idempotency_key": "send-dp-002", "note": "邮件发送"},
    )
    assert first.status_code == 201, first.text
    assert first.json()["replayed"] is False
    record_id = first.json()["record"]["id"]

    for key in ("send-dp-002", "send-dp-002-retry"):
        replay = client.post(
            f"/api/disclosure-packages/{package['id']}/dispatch",
            headers=admin["headers"],
            json={"idempotency_key": key},
        )
        assert replay.status_code == 201, replay.text
        assert replay.json()["replayed"] is True
        assert replay.json()["record"]["id"] == record_id

    detail = client.get(f"/api/disclosure-packages/{package['id']}", headers=admin["headers"]).json()
    assert detail["state"] == "dispatched"
    assert detail["dispatch"]["id"] == record_id
    assert detail["dispatch"]["manifest_digest"] == detail["manifest_digest"]

    excluded_labels = {item["label"] for item in detail["excluded_items"]}
    assert excluded_labels == {"页码 12-18", "附件A-配方表", "字段:核心参数"}
    reasons = {item["label"]: item["auto_reason"] for item in detail["excluded_items"]}
    assert reasons["页码 12-18"] == "仍在保密期"
    assert reasons["附件A-配方表"] == "权属未确认"
    assert reasons["字段:核心参数"] == "禁止出口"

    chain = [(event["event_type"], event["actor_name"]) for event in detail["events"]]
    assert chain[0][0] == "orchestrated"
    assert "item_decided" in [event[0] for event in chain]
    signed_by = [event[1] for event in chain if event[0] == "signed"]
    assert signed_by == ["法务辛", "保密壬"]
    assert chain[-1][0] == "dispatched"


def test_orchestration_guards(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    empty = client.post(
        "/api/disclosure-packages",
        headers=admin["headers"],
        json={
            "recipient_code": "PARTNER-01",
            "purpose": "无内容条目的档案",
            "dossiers": [{"dossier_id": dossier["id"], "expected_version": dossier["version"]}],
        },
    )
    assert empty.status_code == 422

    _add_content(client, admin, dossier["id"])
    stale_version = client.post(
        "/api/disclosure-packages",
        headers=admin["headers"],
        json={
            "recipient_code": "PARTNER-01",
            "purpose": "版本不一致",
            "dossiers": [{"dossier_id": dossier["id"], "expected_version": dossier["version"] + 1}],
        },
    )
    assert stale_version.status_code == 409

    duplicated = client.post(
        "/api/disclosure-packages",
        headers=admin["headers"],
        json={
            "recipient_code": "PARTNER-01",
            "purpose": "重复引用同一档案",
            "dossiers": [
                {"dossier_id": dossier["id"], "expected_version": dossier["version"]},
                {"dossier_id": dossier["id"], "expected_version": dossier["version"]},
            ],
        },
    )
    assert duplicated.status_code == 422

    researcher = _make_user(client, admin, "researcher.nine", "研究员癸", ["researcher"])
    forbidden = client.post(
        "/api/disclosure-packages",
        headers=researcher["headers"],
        json={
            "recipient_code": "PARTNER-01",
            "purpose": "无权限编排",
            "dossiers": [{"dossier_id": dossier["id"], "expected_version": dossier["version"]}],
        },
    )
    assert forbidden.status_code == 403


def test_dispatch_requires_completed_signoff(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    _add_content(client, admin, dossier["id"])
    package = _decide_all_pending(client, admin, _orchestrate(client, admin, dossier))
    response = client.post(
        f"/api/disclosure-packages/{package['id']}/dispatch",
        headers=admin["headers"],
        json={"idempotency_key": "send-dp-003"},
    )
    assert response.status_code == 409


def test_list_packages_and_content_registry(client, admin):
    _, _, dossier = _bootstrap_dossier(client, admin)
    _add_content(client, admin, dossier["id"])
    listed = client.get(f"/api/dossiers/{dossier['id']}/content-items", headers=admin["headers"])
    assert listed.status_code == 200
    assert {item["label"] for item in listed.json()} == {
        "页码 12-18", "附件A-配方表", "字段:核心参数", "页码 1-3",
    }

    package = _orchestrate(client, admin, dossier)
    packages = client.get("/api/disclosure-packages", headers=admin["headers"])
    assert packages.status_code == 200
    assert [row["package_code"] for row in packages.json()] == ["DPK-001"]
    assert packages.json()[0]["counts"] == {"kept": 0, "excluded": 3, "pending": 1}

    in_review = client.get("/api/disclosure-packages?state=in_review", headers=admin["headers"])
    assert len(in_review.json()) == 1
    signed = client.get("/api/disclosure-packages?state=signed", headers=admin["headers"])
    assert signed.json() == []

    duplicate = client.post(
        f"/api/dossiers/{dossier['id']}/content-items",
        headers=admin["headers"],
        json={"item_kind": "field", "label": "字段:核心参数"},
    )
    assert duplicate.status_code == 409
    invalid = client.post(
        f"/api/dossiers/{dossier['id']}/content-items",
        headers=admin["headers"],
        json={"item_kind": "page_range", "label": "页码 30-31", "confidential_until": "not-a-date"},
    )
    assert invalid.status_code == 422
