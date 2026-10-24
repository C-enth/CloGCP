"""Byte-scale synthetic evidence, streamed to disk; not estate-capacity certification."""

import json
import zipfile
from pathlib import Path

from offline_analyzer.contracts.r0 import Source
from offline_analyzer.ingestion.safety import sha256_file
from tools.collector_fixture import convert as canonical
from tools.collector_v030_fixture import convert as v030
from tools.fixtures.r12_demo import build


def large_aws(directory: Path, *, mib: float = 222.6) -> dict:
    directory.mkdir(parents=True, exist_ok=False)
    raw = directory / "r0"
    build(raw)
    manifest = json.loads((raw / "manifest.json").read_text())
    file_bytes = int(mib * 1024 * 1024 / 4)
    chunk = "0123456789abcdef" * 3750
    for index in range(4):
        name = f"large-vpc-{index}.json"
        path = raw / name
        prefix = json.dumps(
            {
                "Vpcs": [
                    {
                        "VpcId": f"vpc-{index + 1000:08x}",
                        "OwnerId": "111111111111",
                        "CidrBlock": "10.0.0.0/16",
                    }
                ]
            }
        )[:-1]
        with path.open("w", encoding="utf-8") as output:
            output.write(prefix + ',"SyntheticPadding":[')
            remaining = file_bytes - output.tell() - 2
            first = True
            while remaining > 3:
                overhead = 2 if first else 3
                count = min(len(chunk), remaining - overhead)
                output.write(("" if first else ",") + '"' + chunk[:count] + '"')
                remaining -= count + overhead
                first = False
            output.write("]}" + " " * remaining)
        assert path.stat().st_size == file_bytes
        source = Source(
            path=name,
            sha256=sha256_file(path),
            format="aws-json-v1",
            operation="ec2:DescribeVpcs",
            account_id="111111111111",
            region="us-east-1",
            collected_at=manifest["sources"][0]["collected_at"],
            coverage="PARTIAL",
            request_parameters={},
        )
        manifest["sources"].append(source.model_dump(mode="json"))
    (raw / "manifest.json").write_text(json.dumps(manifest))
    packages = canonical(raw, directory / "canonical", extras=True)
    primary = next(path for path in packages if path.name.endswith("111111111111"))
    folder = v030(primary, directory / "v030")
    archive = directory / "synthetic-large-aws.zip"
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=1) as output:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                output.write(path, path.relative_to(folder).as_posix())
    return {
        "folder": folder,
        "archive": archive,
        "expanded_bytes": sum(p.stat().st_size for p in folder.rglob("*") if p.is_file()),
        "archive_bytes": archive.stat().st_size,
        "files": sum(p.is_file() for p in folder.rglob("*")),
    }
