from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mosh.models import utc_now
from mosh.scope import normalize_url


ENGAGEMENT_SCHEMA = "mosh.engagement.v1"
ASSET_SCHEMA = "mosh.asset.v1"

VALID_ASSET_TYPES = {"live_url", "source_tree", "source_repo", "mobile_app"}
GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}
MOBILE_APP_HOSTS = {"apps.apple.com", "play.google.com"}


@dataclass(frozen=True)
class EngagementAsset:
    id: str
    type: str
    locator: str
    label: str | None = None
    created_at: str = field(default_factory=utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["metadata"] = _clean_asset_metadata(data.get("metadata"))
        return {"schema": ASSET_SCHEMA, **data}

    def to_ref_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EngagementAsset":
        return cls(
            id=str(value.get("id") or ""),
            type=str(value.get("type") or ""),
            locator=str(value.get("locator") or ""),
            label=value.get("label") if value.get("label") is None else str(value.get("label")),
            created_at=str(value.get("created_at") or utc_now()),
            metadata=_clean_asset_metadata(value.get("metadata")),
        )


@dataclass(frozen=True)
class Engagement:
    id: str
    title: str | None = None
    created_at: str = field(default_factory=utc_now)
    assets: list[EngagementAsset] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": ENGAGEMENT_SCHEMA,
            "id": self.id,
            "title": self.title,
            "created_at": self.created_at,
            "assets": [asset.to_ref_dict() for asset in self.assets],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Engagement":
        return cls(
            id=str(value.get("id") or ""),
            title=value.get("title") if value.get("title") is None else str(value.get("title")),
            created_at=str(value.get("created_at") or utc_now()),
            assets=[
                EngagementAsset.from_dict(item)
                for item in value.get("assets", [])
                if isinstance(item, dict)
            ],
            metadata=value.get("metadata") if isinstance(value.get("metadata"), dict) else {},
        )


@dataclass(frozen=True)
class AttachAssetResult:
    engagement: Engagement
    asset: EngagementAsset
    created: bool


def create_engagement(output_root: Path, title: str | None = None) -> Engagement:
    output_root.mkdir(parents=True, exist_ok=True)
    engagement_id = _new_engagement_id(output_root)
    engagement = Engagement(id=engagement_id, title=_clean_optional_text(title))
    save_engagement(output_root, engagement)
    return engagement


def load_engagement(output_root: Path, engagement_id: str) -> Engagement:
    path = engagement_manifest_path(output_root, engagement_id)
    if not path.exists():
        raise FileNotFoundError(f"Engagement not found: {engagement_id}")
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain an engagement object")
    engagement = _engagement_from_mapping(output_root, parsed)
    validate_engagement(engagement)
    return engagement


def save_engagement(output_root: Path, engagement: Engagement) -> None:
    validate_engagement(engagement)
    root = engagement_dir(output_root, engagement.id)
    root.mkdir(parents=True, exist_ok=True)
    _write_json(root / "engagement.json", engagement.to_dict())
    for asset in engagement.assets:
        write_asset_file(output_root, engagement.id, asset)


def write_asset_file(output_root: Path, engagement_id: str, asset: EngagementAsset) -> None:
    root = asset_dir(output_root, engagement_id, asset.id)
    root.mkdir(parents=True, exist_ok=True)
    _write_json(root / "asset.json", asset.to_dict())


def load_asset(output_root: Path, engagement_id: str, asset_id: str) -> EngagementAsset:
    path = asset_dir(output_root, engagement_id, asset_id) / "asset.json"
    if not path.exists():
        raise FileNotFoundError(f"Asset not found: {asset_id}")
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain an asset object")
    asset = EngagementAsset.from_dict(parsed)
    validate_asset_id(asset.id)
    validate_asset_type(asset.type)
    if asset.id != asset_id:
        raise ValueError(f"{path} contains asset id `{asset.id}`, expected `{asset_id}`")
    return asset


def attach_asset(
    output_root: Path,
    engagement_id: str,
    locator: str,
    *,
    asset_type: str | None = None,
    label: str | None = None,
) -> AttachAssetResult:
    engagement = load_engagement(output_root, engagement_id)
    normalized_type = validate_asset_type(asset_type) if asset_type else infer_asset_type(locator)
    normalized_locator = normalize_asset_locator(locator, normalized_type)
    for asset in engagement.assets:
        if asset.type == normalized_type and asset.locator == normalized_locator:
            write_asset_file(output_root, engagement.id, asset)
            return AttachAssetResult(engagement=engagement, asset=asset, created=False)

    asset = EngagementAsset(
        id=_next_asset_id(engagement, normalized_type),
        type=normalized_type,
        locator=normalized_locator,
        label=_clean_optional_text(label),
    )
    updated = Engagement(
        id=engagement.id,
        title=engagement.title,
        created_at=engagement.created_at,
        assets=[*engagement.assets, asset],
        metadata=engagement.metadata,
    )
    save_engagement(output_root, updated)
    return AttachAssetResult(engagement=updated, asset=asset, created=True)


def record_asset_discovery(
    output_root: Path,
    engagement_id: str,
    asset_id: str,
    report_dir: Path,
) -> EngagementAsset:
    engagement = load_engagement(output_root, engagement_id)
    updated_assets: list[EngagementAsset] = []
    discovered: EngagementAsset | None = None
    for asset in engagement.assets:
        if asset.id != asset_id:
            updated_assets.append(asset)
            continue
        metadata = _clean_asset_metadata(asset.metadata)
        discovery = dict(metadata.get("discovery")) if isinstance(metadata.get("discovery"), dict) else {}
        discovery["last_discovered_at"] = utc_now()
        metadata["discovery"] = discovery
        discovered = EngagementAsset(
            id=asset.id,
            type=asset.type,
            locator=asset.locator,
            label=asset.label,
            created_at=asset.created_at,
            metadata=metadata,
        )
        updated_assets.append(discovered)
    if discovered is None:
        raise ValueError(f"Unknown asset id `{asset_id}` for engagement `{engagement_id}`")
    save_engagement(
        output_root,
        Engagement(
            id=engagement.id,
            title=engagement.title,
            created_at=engagement.created_at,
            assets=updated_assets,
            metadata=engagement.metadata,
        ),
    )
    return discovered


def engagement_exists(output_root: Path, engagement_id: str) -> bool:
    try:
        return engagement_manifest_path(output_root, engagement_id).exists()
    except ValueError:
        return False


def engagement_dir(output_root: Path, engagement_id: str) -> Path:
    return output_root / validate_engagement_id(engagement_id)


def engagement_plan_dir(output_root: Path, engagement_id: str) -> Path:
    return engagement_dir(output_root, engagement_id) / "plan"


def engagement_manifest_path(output_root: Path, engagement_id: str) -> Path:
    return engagement_dir(output_root, engagement_id) / "engagement.json"


def asset_dir(output_root: Path, engagement_id: str, asset_id: str) -> Path:
    return engagement_dir(output_root, engagement_id) / "assets" / validate_asset_id(asset_id)


def asset_discovery_dir(output_root: Path, engagement_id: str, asset_id: str) -> Path:
    return asset_dir(output_root, engagement_id, asset_id) / "discovery"


def infer_asset_type(locator: str) -> str:
    value = locator.strip()
    if not value:
        raise ValueError("Asset locator cannot be empty")
    path = Path(value).expanduser()
    if path.exists() and path.is_dir():
        return "source_tree"
    if path.exists() and path.is_file() and path.suffix.lower() in {".apk", ".ipa"}:
        return "mobile_app"
    if _looks_like_ssh_git(value):
        return "source_repo"
    parsed = urlparse(value)
    if parsed.scheme in {"ssh", "git"} and parsed.netloc:
        return "source_repo"
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        host = (parsed.hostname or "").lower()
        if host in MOBILE_APP_HOSTS:
            return "mobile_app"
        if value.rstrip("/").endswith(".git") or host in GIT_HOSTS:
            return "source_repo"
        return "live_url"
    if value.rstrip("/").endswith(".git"):
        return "source_repo"
    raise ValueError(f"Cannot infer asset type for `{locator}`; pass --type explicitly.")


def validate_asset_type(asset_type: str | None) -> str:
    normalized = (asset_type or "").strip().lower().replace("-", "_")
    if normalized not in VALID_ASSET_TYPES:
        allowed = ", ".join(sorted(VALID_ASSET_TYPES))
        raise ValueError(f"Unsupported asset type `{asset_type}`. Expected one of: {allowed}.")
    return normalized


def normalize_asset_locator(locator: str, asset_type: str) -> str:
    value = locator.strip()
    if not value:
        raise ValueError("Asset locator cannot be empty")
    normalized_type = validate_asset_type(asset_type)
    if normalized_type == "live_url":
        return normalize_url(value).rstrip("/")
    if normalized_type == "source_tree":
        path = Path(value).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Source path not found: {locator}")
        if not path.is_dir():
            raise NotADirectoryError(f"Source path is not a directory: {locator}")
        return str(path.resolve())
    if normalized_type in {"source_repo", "mobile_app"}:
        return value.rstrip("/")
    return value


def validate_engagement(engagement: Engagement) -> None:
    validate_engagement_id(engagement.id)
    seen_asset_ids: set[str] = set()
    seen_asset_identities: set[tuple[str, str]] = set()
    for asset in engagement.assets:
        validate_asset_id(asset.id)
        validate_asset_type(asset.type)
        if asset.id in seen_asset_ids:
            raise ValueError(f"Duplicate asset id `{asset.id}` in engagement `{engagement.id}`")
        seen_asset_ids.add(asset.id)
        identity = (asset.type, asset.locator)
        if identity in seen_asset_identities:
            raise ValueError(f"Duplicate asset locator `{asset.locator}` in engagement `{engagement.id}`")
        seen_asset_identities.add(identity)


def _engagement_from_mapping(output_root: Path, value: dict[str, Any]) -> Engagement:
    engagement_id = str(value.get("id") or "")
    assets: list[EngagementAsset] = []
    for item in value.get("assets", []):
        if not isinstance(item, dict):
            continue
        asset_id = str(item.get("id") or "")
        extra_keys = set(item) - {"id", "created_at"}
        if extra_keys:
            raise ValueError(
                f"Engagement manifest asset `{asset_id}` must be an asset ref; "
                f"move canonical asset data to assets/{asset_id}/asset.json"
            )
        if asset_id:
            assets.append(load_asset(output_root, engagement_id, asset_id))
    return Engagement(
        id=engagement_id,
        title=value.get("title") if value.get("title") is None else str(value.get("title")),
        created_at=str(value.get("created_at") or utc_now()),
        assets=assets,
        metadata=value.get("metadata") if isinstance(value.get("metadata"), dict) else {},
    )

def _clean_asset_metadata(value: Any) -> dict[str, Any]:
    metadata = dict(value) if isinstance(value, dict) else {}
    discovery = metadata.get("discovery")
    if isinstance(discovery, dict):
        cleaned_discovery = dict(discovery)
        cleaned_discovery.pop("report_dir", None)
        cleaned_discovery.pop("report_path", None)
        metadata["discovery"] = cleaned_discovery
    return metadata


def validate_engagement_id(value: str) -> str:
    if not re.fullmatch(r"eng_[a-z0-9]{8}", value):
        raise ValueError(f"Invalid engagement id `{value}`")
    return value


def validate_asset_id(value: str) -> str:
    if not re.fullmatch(r"asset_[a-z0-9_]+_[0-9]+", value):
        raise ValueError(f"Invalid asset id `{value}`")
    return value


def _new_engagement_id(output_root: Path) -> str:
    for _ in range(100):
        engagement_id = f"eng_{secrets.token_hex(4)}"
        if not (output_root / engagement_id).exists():
            return engagement_id
    raise RuntimeError("Unable to allocate a unique engagement id")


def _next_asset_id(engagement: Engagement, asset_type: str) -> str:
    prefix = {
        "live_url": "live",
        "source_tree": "source",
        "source_repo": "repo",
        "mobile_app": "mobile",
    }[validate_asset_type(asset_type)]
    existing = {asset.id for asset in engagement.assets}
    index = 1
    while True:
        candidate = f"asset_{prefix}_{index}"
        if candidate not in existing:
            return candidate
        index += 1


def _looks_like_ssh_git(value: str) -> bool:
    return bool(re.fullmatch(r"git@[^:]+:.+\.git", value))


def _clean_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as tmp:
        tmp.write(payload)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
