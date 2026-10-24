"""Dependency-free structural checks of synthetic report exports."""

import re

from offline_analyzer.reporting.pdf import write_text_pdf


def test_pdf_paginated_literal_text_and_original_unicode(tmp_path):
    path = tmp_path / "synthetic.pdf"
    hostile = r") Tj ET /OpenAction (https://example.invalid) \\"
    unicode = "Synthetic \u6d4b\u8bd5 \U0001f512"
    text = f"{hostile}\n{unicode}\n" + "\n".join(
        f"Synthetic row {n}: " + "a" * 220 for n in range(120)
    )
    write_text_pdf("Synthetic report", text, path)
    content = path.read_bytes()
    assert content.startswith(b"%PDF-1.4") and content.endswith(b"%%EOF\n")
    assert b"\\) Tj ET /OpenAction \\(" in content
    assert b"[U+6D4B]" in content and b"[U+1F512]" in content
    assert ("\ufeff" + unicode).encode("utf-16-be").hex().encode() in content
    pages = int(re.search(rb"/Type /Pages /Count (\d+)", content)[1])
    assert pages > 2 and content.count(b"/Type /Page /Parent") == pages
    # Every text baseline remains within the printable page region.
    baselines = [int(v) for v in re.findall(rb"Tf 48 (\d+) Td", content)]
    assert min(baselines) >= 32 and max(baselines) <= 777
    xref_offset = int(re.search(rb"startxref\n(\d+)", content)[1])
    assert content[xref_offset:].startswith(b"xref\n")
    entries = content[xref_offset:].split(b"\n")[3 : 3 + 4 + pages * 2]
    for number, entry in enumerate(entries, 1):
        offset = int(entry.split()[0])
        assert content[offset:].startswith(f"{number} 0 obj\n".encode())
