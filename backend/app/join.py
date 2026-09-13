import logging

from pydantic import BaseModel

from app.models import Asset, BusinessService, Vulnerability

log = logging.getLogger(__name__)


class JoinedRisk(BaseModel):
    vulnerability: Vulnerability
    asset: Asset
    service: BusinessService | None


def join(
    vulns: list[Vulnerability],
    assets: list[Asset],
    services: dict[str, BusinessService],
) -> list[JoinedRisk]:
    by_id = {a.asset_id: a for a in assets}
    out: list[JoinedRisk] = []
    for v in vulns:
        asset = by_id.get(v.asset_id)
        if asset is None:
            log.warning("vuln %s references unknown asset %s; dropping", v.vuln_id, v.asset_id)
            continue
        svc = services.get(asset.business_service)
        if svc is None:
            log.warning("asset %s references unknown service %s", asset.asset_id, asset.business_service)
        out.append(JoinedRisk(vulnerability=v, asset=asset, service=svc))
    return out
