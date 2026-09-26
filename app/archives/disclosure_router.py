from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import current_principal
from app.database import get_connection, transaction
from app.core.security import Principal
from app.archives.disclosure_package import DisclosurePackageService
from app.archives.disclosure_schemas import (
    DisclosurePackageCreate,
    DispatchCreate,
    ItemDecision,
    PackageSign,
)

router = APIRouter(prefix="/api/disclosure-packages", tags=["披露包"])


@router.post("", status_code=status.HTTP_201_CREATED)
def orchestrate_package(payload: DisclosurePackageCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DisclosurePackageService(connection).orchestrate(principal, payload.model_dump())


@router.get("")
def list_packages(
    state: str | None = Query(default=None),
    principal: Principal = Depends(current_principal),
):
    return DisclosurePackageService(get_connection()).list(principal, state)


@router.get("/{package_id}")
def get_package(package_id: int, principal: Principal = Depends(current_principal)):
    return DisclosurePackageService(get_connection()).detail(principal, package_id)


@router.post("/{package_id}/items/{item_id}/decision")
def decide_item(
    package_id: int,
    item_id: int,
    payload: ItemDecision,
    principal: Principal = Depends(current_principal),
):
    with transaction(immediate=True) as connection:
        return DisclosurePackageService(connection).decide_item(principal, package_id, item_id, payload.model_dump())


@router.post("/{package_id}/signatures", status_code=status.HTTP_201_CREATED)
def sign_package(package_id: int, payload: PackageSign, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DisclosurePackageService(connection).sign(principal, package_id, payload.model_dump())


@router.post("/{package_id}/refresh")
def refresh_package(package_id: int, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DisclosurePackageService(connection).refresh(principal, package_id)


@router.post("/{package_id}/dispatch", status_code=status.HTTP_201_CREATED)
def dispatch_package(package_id: int, payload: DispatchCreate, principal: Principal = Depends(current_principal)):
    with transaction(immediate=True) as connection:
        return DisclosurePackageService(connection).dispatch(principal, package_id, payload.model_dump())
