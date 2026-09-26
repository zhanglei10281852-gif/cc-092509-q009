from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class SecurityProfileUpsert(BaseModel):
    secrecy_level: Literal["internal", "confidential", "restricted", "top_secret"]


class ContentItemCreate(BaseModel):
    item_kind: Literal["page_range", "attachment", "field"]
    label: str = Field(min_length=1, max_length=200)
    confidential_until: str | None = Field(default=None, min_length=10, max_length=40)
    ownership_confirmed: bool = True
    export_restricted: bool = False


class ContentItemUpdate(BaseModel):
    confidential_until: str | None = Field(default=None, min_length=10, max_length=40)
    ownership_confirmed: bool | None = None
    export_restricted: bool | None = None

    @model_validator(mode="after")
    def ensure_change(self):
        if (
            self.confidential_until is None
            and self.ownership_confirmed is None
            and self.export_restricted is None
        ):
            raise ValueError("至少更新一项内容条目属性")
        return self


class PackageDossierRef(BaseModel):
    dossier_id: int = Field(gt=0)
    expected_version: int = Field(gt=0)


class DisclosurePackageCreate(BaseModel):
    package_code: str | None = Field(default=None, min_length=3, max_length=64)
    recipient_code: str = Field(min_length=2, max_length=100)
    purpose: str = Field(min_length=4, max_length=500)
    dossiers: list[PackageDossierRef] = Field(min_length=1, max_length=100)


class ItemDecision(BaseModel):
    decision: Literal["keep", "exclude"]
    rationale: str = Field(min_length=2, max_length=500)


class PackageSign(BaseModel):
    signer_role: Literal["legal", "security"]


class DispatchCreate(BaseModel):
    idempotency_key: str = Field(min_length=4, max_length=100)
    note: str = Field(default="", max_length=500)
