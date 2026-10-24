"""WCAG AA contrast of the UI colour tokens in the light and dark themes.

Tokens are read from frontend/src/style.css, so this checks the shipped values. Text
pairs need 4.5:1; component boundaries, focus rings and diagram edges need 3:1. The
severity chart colours are fixed across themes (meaning must not change) and are not
the only carrier of information: the legend shows each severity name and count.
"""

import re
from pathlib import Path

import pytest

CSS = Path(__file__).parents[1] / "frontend" / "src" / "style.css"


def block(css: str, selector: str) -> dict[str, str]:
    body = css.split(selector + " {", 1)[1].split("\n}", 1)[0]
    return dict(re.findall(r"(--[a-z0-9-]+):\s*(#[0-9a-f]{6})\b", body))


def themes() -> dict[str, dict[str, str]]:
    css = CSS.read_text()
    light = block(css, ":root")
    return {"light": light, "dark": {**light, **block(css, ':root[data-theme="dark"]')}}


def luminance(hex_colour: str) -> float:
    def channel(c: int) -> float:
        c = c / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (int(hex_colour[i : i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(a: str, b: str) -> float:
    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


SURFACES = ("bg", "surface", "surface-2", "surface-3", "surface-accent")
TEXT = [(fg, bg) for fg in ("text", "text-muted", "text-subtle", "link") for bg in SURFACES]
TEXT += [
    ("on-accent", "accent"),
    ("on-accent", "accent-hover"),
    ("on-accent", "danger-solid"),
    ("on-accent", "danger-solid-hover"),
    ("danger", "danger-bg"),
    ("danger", "surface"),
    ("warning", "warning-bg"),
    ("caution-fg", "caution-bg"),
    ("success", "success-bg"),
    ("success", "surface"),
    ("sev-critical-fg", "sev-critical-bg"),
    ("sev-high-fg", "sev-high-bg"),
    ("link", "surface-accent-strong"),
    ("text", "surface-accent-strong"),
    ("diagram-text", "diagram-node"),
    ("diagram-text", "diagram-node-selected"),
    ("text-subtle", "diagram-node"),
    *[
        (fg, bg)
        for fg in ("nav-fg", "nav-fg-muted", "nav-fg-strong", "nav-accent")
        for bg in ("nav-bg", "nav-hover", "nav-active")
    ],
    *[(f"nav-env-{e}", "nav-bg") for e in ("synthetic", "unlabeled", "assessment")],
]
GRAPHICS = [
    ("input-border", "surface"),
    ("focus", "surface"),
    ("focus", "bg"),
    ("accent", "surface"),
    *[(f"edge-{e}", "surface") for e in ("observed", "supported", "potential", "blocked")],
    ("edge-unknown", "surface"),
    ("diagram-node-border", "diagram-node"),
    ("chart-bar", "surface"),
]


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_text_tokens_meet_wcag_aa(theme):
    tokens = themes()[theme]
    failing = [
        (fg, bg, round(contrast(tokens[f"--{fg}"], tokens[f"--{bg}"]), 2))
        for fg, bg in TEXT
        if contrast(tokens[f"--{fg}"], tokens[f"--{bg}"]) < 4.5
    ]
    assert failing == []


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_boundaries_focus_and_diagram_edges_meet_3_to_1(theme):
    tokens = themes()[theme]
    failing = [
        (fg, bg, round(contrast(tokens[f"--{fg}"], tokens[f"--{bg}"]), 2))
        for fg, bg in GRAPHICS
        if contrast(tokens[f"--{fg}"], tokens[f"--{bg}"]) < 3
    ]
    assert failing == []


def test_severity_colours_do_not_change_with_theme():
    light, dark = themes()["light"], themes()["dark"]
    severity = [k for k in light if k.startswith("--sev-chart-")]
    assert len(severity) == 5
    assert all(light[k] == dark[k] for k in severity)


def test_components_use_tokens_not_hardcoded_colours():
    css = CSS.read_text()
    rules = re.sub(r":root(\[data-theme=\"dark\"\])? \{.*?\n\}", "", css, flags=re.S)
    assert not re.findall(r"#[0-9a-fA-F]{3,8}\b|rgba?\(|(?<![-\w])(white|black)(?![-\w])", rules)
    for source in (CSS.parent).glob("*.tsx"):
        assert not re.findall(r"#[0-9a-fA-F]{6}\b", source.read_text()), source.name
