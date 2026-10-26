"""Per-principal role view in the compiled GUI, light and dark themes (synthetic data)."""

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("RUN_GUI_BROWSER") != "1", reason="Opt-in Chromium")
OUTPUT = Path("artifacts/principal-browser")
MEMBER = "serviceAccount:worker@demo-beta.iam.gserviceaccount.com"


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_principal_view_and_finding_link(tmp_path, theme):
    from playwright.sync_api import expect, sync_playwright
    from test_theme_browser import serve
    from test_theme_browser import workspace as synthetic_workspace

    work = synthetic_workspace(tmp_path)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with serve(work, "synthetic-principal") as origin, sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(color_scheme=theme, viewport={"width": 1500, "height": 1000})
        # The theme is chosen in the UI (Dark is the default); store the choice up front.
        context.add_init_script(f"localStorage.setItem('closec-theme', '{theme}')")
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(origin + "/#token=synthetic-principal")
        page.get_by_role("button", name="Dashboard", exact=True).wait_for()
        assert page.locator("html").get_attribute("data-theme") == theme
        page.get_by_role("tab", name="GCP", exact=True).click()
        page.get_by_role("button", name="IAM intelligence", exact=True).click()
        view = page.get_by_label("Principal roles", exact=True)
        expect(view.get_by_label("Observed principals")).to_be_visible()
        view.get_by_label("Filter principals").fill("worker@demo-beta")
        view.get_by_role("button", name=f"Show roles of {MEMBER}").click()
        detail = page.get_by_label(f"Roles of {MEMBER}", exact=True)
        bindings = detail.get_by_label("Observed role bindings")
        expect(bindings).to_contain_text("roles/editor")
        expect(bindings).to_contain_text("privileged")
        expect(detail.get_by_label("Resolution by project")).to_contain_text("demo-alpha")
        expect(detail).to_contain_text("no parent recorded — verify standalone project")
        expect(detail).to_contain_text("IN_SCOPE_OTHER_PROJECT")
        page.screenshot(path=str(OUTPUT / f"{theme}-principal-roles.png"), full_page=True)

        # A finding naming a member or attached account links back to the same view.
        candidates = page.get_by_role("heading", name="IAM candidate findings").locator(
            "xpath=following-sibling::div[1]"
        )
        candidates.locator("tr", has_text="Broad Owner or Editor binding").first.get_by_role(
            "button", name="View"
        ).click()
        links = page.get_by_label("Principals in this finding")
        expect(links).to_be_visible()
        first = links.locator("code").first.inner_text()
        links.get_by_role("button", name=f"View roles of {first}").click()
        expect(page.get_by_label(f"Roles of {first}", exact=True)).to_be_visible()
        expect(page.get_by_label("Principal roles", exact=True)).to_be_visible()
        assert not errors
        browser.close()
