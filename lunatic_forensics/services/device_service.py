"""Device records attached to cases (manual entry or acquisition connectors)."""
from __future__ import annotations

from sqlalchemy import select

from ..core.errors import NotFound, ValidationError
from ..core.rbac import Perm
from ..core.timeutils import utcnow
from ..storage.models import Device
from .base import ServiceBase

PLATFORMS = ("android", "ios", "other", "unknown")
EDITABLE = {"label", "platform", "manufacturer", "model", "os_version", "identifiers", "access_level",
            "limitations", "connection_state", "authorization_ref", "collection_scope", "acquired_at"}


class DeviceService(ServiceBase):
    def add(self, actor, case_id: int, **fields) -> int:
        self.authorize(actor, Perm.ACQUIRE_DEVICE)
        unknown = set(fields) - EDITABLE
        if unknown:
            raise ValidationError(f"Unknown device fields: {', '.join(sorted(unknown))}")
        if fields.get("platform", "unknown") not in PLATFORMS:
            raise ValidationError("Invalid platform.")
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            dev = Device(case_id=case_id, **fields)
            s.add(dev)
            s.flush()
            self.ctx.cases.touch(s, case_id)
            self.ctx.audit.log("device.add", actor, case_id=case_id, object_type="device", object_id=dev.id,
                               details={k: v for k, v in fields.items() if k != "identifiers"}, session=s)
            return dev.id

    def update(self, actor, device_id: int, **fields) -> None:
        self.authorize(actor, Perm.ACQUIRE_DEVICE)
        unknown = set(fields) - EDITABLE
        if unknown:
            raise ValidationError(f"Unknown device fields: {', '.join(sorted(unknown))}")
        with self.db.session() as s:
            dev = s.get(Device, device_id)
            if dev is None:
                raise NotFound("Device not found.")
            self.case_for(s, actor, dev.case_id)
            for k, v in fields.items():
                setattr(dev, k, v)
            self.ctx.audit.log("device.update", actor, case_id=dev.case_id, object_type="device",
                               object_id=dev.id, details=sorted(fields), session=s)

    def list(self, actor, case_id: int) -> list[Device]:
        self.authorize(actor, Perm.VIEW_CASE)
        with self.db.session() as s:
            self.case_for(s, actor, case_id)
            return list(s.scalars(select(Device).where(Device.case_id == case_id).order_by(Device.id)))

    def register_probe(self, actor, case_id: int, probe, authorization_ref: str, collection_scope: str) -> int:
        """Store a device probe produced by an acquisition connector."""
        if not authorization_ref.strip():
            raise ValidationError("An authorisation reference (warrant, consent form, mandate) is required.")
        return self.add(actor, case_id, label=probe.label, platform=probe.platform, manufacturer=probe.manufacturer,
                        model=probe.model, os_version=probe.os_version, identifiers=probe.identifiers,
                        access_level=probe.access_level, limitations=probe.limitations,
                        connection_state=probe.connection_state, authorization_ref=authorization_ref,
                        collection_scope=collection_scope, acquired_at=utcnow())
