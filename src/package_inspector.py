import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List

HIGH_RISK_PERMISSIONS = [
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CALL_LOG",
    "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
    "SYSTEM_ALERT_WINDOW", "INSTALL_PACKAGES", "READ_CONTACTS",
]

PACKAGE_EXTENSIONS = {".apk", ".aab", ".appx", ".msix", ".zip", ".jar", ".whl", ".ipa"}


def inspect_package(package_path: str) -> Dict[str, Any]:
    """Safely inspects APK, AAB, APPX, and archive packages for manifests, libs, and risk signals."""
    path = Path(package_path).resolve()
    if not path.exists() or not path.is_file():
        return {"error": f"Package file not found: {package_path}"}

    ext = path.suffix.lower()
    if ext not in PACKAGE_EXTENSIONS and not zipfile.is_zipfile(path):
        return {
            "file": path.name,
            "format": ext or "binary",
            "size_bytes": path.stat().st_size,
            "note": "Non-archive binary file; basic metadata recorded.",
        }

    entries: List[str] = []
    native_libs: List[str] = []
    config_and_manifests: List[str] = []
    detected_permissions: List[str] = []
    suspicious_urls: List[str] = []
    total_uncompressed_bytes = 0

    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                entries.append(name)
                total_uncompressed_bytes += info.file_size
                lower_name = name.lower()

                if lower_name.endswith((".so", ".dll", ".dylib", ".pyd")):
                    native_libs.append(name)

                if any(k in lower_name for k in (
                    "manifest", "config", "strings", "values", "package.json", "appxmanifest", "web.config"
                )):
                    config_and_manifests.append(name)

                if info.file_size <= 262_144 and lower_name.endswith(
                    (".xml", ".json", ".txt", ".properties", ".yml", ".yaml", ".manifest", ".config")
                ):
                    try:
                        raw_bytes = zf.read(name)
                        text = raw_bytes.decode("utf-8", errors="ignore")
                        printable = " ".join(re.findall(r"[A-Za-z0-9_./:-]{4,}", text))
                        combined = f"{text}\n{printable}"

                        for perm in HIGH_RISK_PERMISSIONS:
                            if perm in combined and perm not in detected_permissions:
                                detected_permissions.append(perm)

                        urls = re.findall(r"https?://[^\s'\x22<>()]+", combined)
                        for u in urls:
                            if u not in suspicious_urls and len(suspicious_urls) < 40:
                                suspicious_urls.append(u)
                    except Exception:
                        pass
    except zipfile.BadZipFile:
        return {
            "file": path.name,
            "format": ext,
            "size_bytes": path.stat().st_size,
            "error": "Invalid or corrupted archive structure.",
        }

    return {
        "file": path.name,
        "format": ext.lstrip(".").upper() or "ARCHIVE",
        "compressed_size_bytes": path.stat().st_size,
        "uncompressed_size_bytes": total_uncompressed_bytes,
        "total_entries": len(entries),
        "native_libraries": native_libs[:100],
        "manifests_and_configs": config_and_manifests[:100],
        "high_risk_permissions_detected": detected_permissions,
        "extracted_urls": suspicious_urls,
        "sample_entries": entries[:60],
    }
