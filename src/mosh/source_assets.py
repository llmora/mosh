from __future__ import annotations

import subprocess
from pathlib import Path

from mosh.engagements import EngagementAsset, asset_dir


SOURCE_ASSET_TYPES = {"source_tree", "source_repo"}


def is_source_asset(asset: EngagementAsset) -> bool:
    return asset.type in SOURCE_ASSET_TYPES


def first_source_asset(assets: list[EngagementAsset]) -> EngagementAsset | None:
    return next((asset for asset in assets if is_source_asset(asset)), None)


def source_checkout_dir(output_root: Path, engagement_id: str, asset: EngagementAsset) -> Path:
    if asset.type != "source_repo":
        raise ValueError(f"Asset `{asset.id}` is not a source_repo asset.")
    return asset_dir(output_root, engagement_id, asset.id) / "checkout"


def readable_source_root(output_root: Path, engagement_id: str, asset: EngagementAsset) -> Path | None:
    if asset.type == "source_tree":
        path = Path(asset.locator).expanduser()
    elif asset.type == "source_repo":
        path = source_checkout_dir(output_root, engagement_id, asset)
    else:
        return None
    if not path.exists() or not path.is_dir():
        return None
    return path.resolve()


def ensure_source_root(output_root: Path, engagement_id: str, asset: EngagementAsset) -> Path:
    if asset.type == "source_tree":
        path = Path(asset.locator).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Source path not found: {asset.locator}")
        if not path.is_dir():
            raise NotADirectoryError(f"Source path is not a directory: {asset.locator}")
        return path.resolve()
    if asset.type == "source_repo":
        return ensure_source_repo_checkout(output_root, engagement_id, asset)
    raise ValueError(f"Asset `{asset.id}` is not a source asset.")


def ensure_source_repo_checkout(output_root: Path, engagement_id: str, asset: EngagementAsset) -> Path:
    checkout = source_checkout_dir(output_root, engagement_id, asset)
    if checkout.exists():
        if not checkout.is_dir():
            raise NotADirectoryError(f"Source repository checkout path is not a directory: {checkout}")
        if _is_git_work_tree(checkout):
            return checkout.resolve()
        if any(checkout.iterdir()):
            raise ValueError(f"Source repository checkout exists but is not a Git checkout: {checkout}")

    checkout.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", asset.locator, str(checkout)],
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Failed to clone source repository `{asset.locator}`: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        suffix = f": {detail[:1000]}" if detail else ""
        raise RuntimeError(f"Failed to clone source repository `{asset.locator}`{suffix}")
    if not _is_git_work_tree(checkout):
        raise RuntimeError(f"Source repository clone did not create a valid Git checkout: {checkout}")
    return checkout.resolve()


def _is_git_work_tree(path: Path) -> bool:
    if not path.exists() or not path.is_dir():
        return False
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"
