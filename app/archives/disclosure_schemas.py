from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class MaterialCreate(BaseModel):
    material_code: str = Field(min_length=3, max_length=64)
    material_kind: Literal["page", "attachment", "field"]
    title: str = Field(min_length=1, max_length=200)
    confidential_until: str | None = Field(default=None, min_length=10, max_length=40)
    ownership_state: Literal["confirmed", "pending"] = "confirmed"
    export_restricted: bool = False


class MaterialUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    confidential_until: str | None = Field(default=None, min_length=10, max_length=40)
    ownership_state: Literal["confirmed", "pending"] | None = None
    export_restricted: bool | None = None


class SecrecyUpdate(BaseModel):
    secrecy_level: Literal["internal", "confidential", "restricted", "top_secret"]
    expected_version: int = Field(gt=0)
    reason: str = Field(min_length=2, max_length=500)


class PackageItemInput(BaseModel):
    dossier_id: int = Field(gt=0)
    expected_version: int = Field(gt=0)


class DisclosurePackageCreate(BaseModel):
    package_code: str | None = Field(default=None, min_length=3, max_length=64)
    title: str = Field(min_length=2, max_length=200)
    partner_code: str = Field(min_length=2, max_length=100)
    purpose: str = Field(min_length=4, max_length=500)
    items: list[PackageItemInput] = Field(min_length=1, max_length=100)


class ReviewMark(BaseModel):
    decision: Literal["keep", "remove"]
    rationale: str = Field(min_length=2, max_length=500)


class SignatureCreate(BaseModel):
    signer_role: Literal["legal", "security"]


class DispatchCreate(BaseModel):
    idempotency_key: str = Field(min_length=4, max_length=100)
    note: str = Field(default="", max_length=500)
