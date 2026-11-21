"""Exercise the offline financial review UI with an already installed Playwright and Chromium."""

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from check_public_lab_browser import DEVICES, VIRTUAL_ORIGIN, context_for, file_access


ROOT = Path(__file__).resolve().parents[1]


def import_report(page, raw, expected):
    page.locator("#import-report").set_input_files(
        {"name": "review.json", "mimeType": "application/json", "buffer": raw})
    expect(page.locator("#import-state")).to_contain_text(expected)
    expect(page.locator("#import-state")).to_contain_text(sha256(raw).hexdigest())


def exercise(browser, html, name, direct_file, output):
    report_bytes = (html.parent / "results.json").read_bytes()
    recorded = json.loads(report_bytes)
    doc = html.read_bytes()
    unexpected, errors, sockets, violations = [], [], [], []
    with context_for(browser, **DEVICES[name]) as context:
        def route(request):
            if request.request.url == VIRTUAL_ORIGIN and request.request.resource_type == "document" and not direct_file:
                request.fulfill(content_type="text/html; charset=utf-8", body=doc)
            else:
                unexpected.append(request.request.url)
                request.abort()

        def socket(ws):
            sockets.append(ws.url)
            ws.close()

        context.route("http*://**/*", route)
        context.route_web_socket("**/*", socket)
        context.expose_binding("recordPolicyViolation", lambda _, value: violations.append(value))
        context.add_init_script("document.addEventListener('securitypolicyviolation',e=>window.recordPolicyViolation(e.violatedDirective))")
        page = context.new_page()
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(html.as_uri() if direct_file else VIRTUAL_ORIGIN)
        page.screenshot(path=output / (name + ".png"), animations="disabled")
        page.keyboard.press("Tab")
        expect(page.get_by_role("link", name="Skip to challenge selection")).to_be_focused()
        page.keyboard.press("Enter")
        expect(page.locator("#matrix")).to_be_focused()
        family, case = page.locator("#family"), page.locator("#case")
        phase = phase_delta = None
        for row in recorded["cases"]:
            family.select_option(row["id"][0])
            case.select_option(row["id"])
            expect(page.locator("#case-code")).to_contain_text(row["id"])
            expect(page.locator("#expected")).to_have_text(row["expected"]["outcome"])
            expect(page.locator("#recorded")).to_have_text(row["observed"]["outcome"])
            expect(page.locator("#byte-panes .digest").last).to_have_text(row["sha256"])
            expect(page.locator("#command")).to_contain_text("--case " + row["id"])
            page.locator("#hash").click()
            expect(page.locator("#hash-result")).to_contain_text("MATCH ·")
            width = page.evaluate("({viewport: innerWidth, content: document.documentElement.scrollWidth})")
            assert width["viewport"] >= width["content"], width
            if row["id"] == "P01":
                phase = row["observed"]["phase"]
            elif row["observed"]["phase"] != phase:
                phase_delta = row["observed"]["phase"]
        family.select_option("P")
        case.select_option("P01")
        page.locator("#note").fill("Fixed fictional sample")
        page.locator("#next").click()
        page.locator("#prev").click()
        expect(page.locator("#note")).to_have_value("Fixed fictional sample")
        import_report(page, report_bytes, "Complete observation matches")
        local = deepcopy(recorded)
        positive = next(r for r in local["cases"] if r["id"] == "P01")
        positive["observed"]["details"]["settlement"] = "FICTIONAL_VARIANT"
        positive["observed"]["phase"] = phase_delta
        raw = json.dumps(local).encode()
        import_report(page, raw, "$.details.settlement")
        expect(page.locator("#import-state")).to_contain_text("$.phase")
        with page.expect_download() as download:
            page.locator("#export").click()
        dest = output / (name + "-finding.json")
        download.value.save_as(dest)
        finding = json.loads(dest.read_bytes())
        assert finding["challenge_id"] == "P01" and finding["reviewer_note"] == "Fixed fictional sample"
        comparison = finding["submitted_comparison"]
        assert comparison["self_reported_provenance"] == recorded["provenance"]
        assert comparison["observed_phase"] == phase_delta
        assert comparison["report_sha256"] == sha256(raw).hexdigest()
        assert comparison["outcome_and_reason_match_expected"] and not comparison["complete_observation_matches_package"]
        assert set(comparison["difference_paths"]) == {"$.phase", "$.details.settlement"}
        assert b"FICTIONAL_VARIANT" not in dest.read_bytes()
        incomplete = deepcopy(recorded)
        incomplete["cases"].pop()
        import_report(page, json.dumps(incomplete).encode(), "incomplete")
        import_report(page, b'{"schema":null,"schema":null}', "Repeated field")
        assert not unexpected and not sockets and not errors and not violations, [unexpected, sockets, errors, violations]
    return {"outcome": "PASS", "fixture_digest_matches": len(recorded["cases"]), "viewport": width,
            "keyboard_skip": True, "note_preserved": True, "imported_report_exact": True,
            "nested_and_phase_differences": comparison["difference_paths"], "finding_digest": comparison["report_sha256"],
            "partial_report_refused": True, "duplicate_report_field_refused": True,
            "extra_requests": unexpected, "sockets": sockets, "page_errors": errors, "csp_violations": violations}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--html", type=Path, default=ROOT / "public_lab/financial/index.html")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--chromium", default="/usr/bin/chromium")
    args = parser.parse_args()
    html = args.html.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright, playwright.chromium.launch(
            executable_path=args.chromium, headless=True,
            args=["--disable-background-networking", "--disable-component-update", "--no-pings"]) as browser:
        access = file_access(browser, html)
        devices = {name: exercise(browser, html, name, access["outcome"] == "SUPPORTED", args.output)
                   for name in DEVICES}
        result = {"outcome": "PASS", "browser": browser.version, "html_sha256": sha256(html.read_bytes()).hexdigest(),
                  "file_navigation": access, "devices": devices}
    data = json.dumps(result, indent=2, sort_keys=True) + "\n"
    (args.output / "browser-qa.json").write_text(data, encoding="utf-8")
    print(data, end="")


if __name__ == "__main__":
    main()
