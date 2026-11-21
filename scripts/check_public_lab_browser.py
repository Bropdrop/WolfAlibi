"""Exercise the standalone lab in Chromium with page networking disabled.

Requires Python Playwright and an installed Chromium. Screenshots and the JSON
report belong in a user-selected output directory outside the checkout.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory

from playwright.sync_api import Error, expect, sync_playwright


ROOT = Path(__file__).resolve().parents[1]
CASES = ("education", "finance", "history")
VIRTUAL_ORIGIN = "http://127.0.0.1:36749/"
DEVICES = {
    "desktop": {"viewport": {"width": 1440, "height": 1000}},
    "mobile": {"viewport": {"width": 390, "height": 844}, "is_mobile": True, "has_touch": True},
}


def context_for(browser, **device):
    context = browser.new_context(offline=True, service_workers="block", accept_downloads=True, **device)
    context.set_default_timeout(6000)
    return context


def file_access(browser, html_file):
    with context_for(browser) as context:
        context.route("http*://**/*", lambda route: route.abort())
        page = context.new_page()
        try:
            page.goto(html_file.as_uri(), wait_until="load")
        except Error as error:
            reason = str(error).split(" at ", 1)[0]
            if "ERR_BLOCKED_BY_ADMINISTRATOR" in reason:
                return {"outcome": "UNSUPPORTED", "reason": "CHROMIUM_POLICY_BLOCKS_FILE_URL"}
            raise
        return {"outcome": "SUPPORTED", "secure_context": page.evaluate("isSecureContext")}


def native_record_check(page, html_file, case, variant):
    vectors = html_file.parent / "vectors" / case
    inputs = [case, *(vectors.joinpath(name).read_bytes().decode("utf-8") for name in
                      (f"{variant}.json", "pins.json", "challenge.txt"))]
    return page.evaluate("record => window.quorvaneCheckRecord(...record)", inputs)


def unsupported_check(browser, html_file):
    with context_for(browser) as context:
        context.route("**/*", lambda route: route.fulfill(
            body=html_file.read_bytes(), content_type="text/html; charset=utf-8",
        ) if route.request.url == VIRTUAL_ORIGIN else route.abort())
        context.add_init_script("""const importKey = SubtleCrypto.prototype.importKey;
            SubtleCrypto.prototype.importKey = async function(format, key, algorithm, ...options) {
              if (algorithm?.name === 'Ed25519') throw new DOMException('Disabled in this QA case', 'NotSupportedError');
              return importKey.call(this, format, key, algorithm, ...options);
            };""")
        page = context.new_page()
        page.goto(VIRTUAL_ORIGIN, wait_until="load")
        result = native_record_check(page, html_file, "education", "genuine")
        assert result["outcome"] == "UNSUPPORTED" and "Python verifier" in result["detail"], result
        return {"control": "SIMULATED_ED25519_UNAVAILABLE", **result}


def run_browser(browser, html_file, *, origin, device_name, output):
    html = html_file.read_bytes()
    with context_for(browser, **DEVICES[device_name]) as context:
        blocked = []
        observed = []
        socket_attempts = []
        page_errors = []

        def route_document(route):
            url = route.request.url
            if url == VIRTUAL_ORIGIN and route.request.resource_type == "document":
                route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)
                return
            blocked.append(url)
            route.abort()

        def reject_socket(socket_route):
            socket_attempts.append(socket_route.url)
            socket_route.close()

        if origin == VIRTUAL_ORIGIN:
            context.route("**/*", route_document)
        else:
            context.route("http*://**/*", route_document)
        context.on("request", lambda request: observed.append(request.url))
        context.route_web_socket("**/*", reject_socket)
        context.grant_permissions(["clipboard-read", "clipboard-write"],
                                  origin=VIRTUAL_ORIGIN if origin == VIRTUAL_ORIGIN else None)
        context.add_init_script("""window.labPolicyViolations = [];
            document.addEventListener('securitypolicyviolation', event => {
              window.labPolicyViolations.push([event.violatedDirective, event.blockedURI]);
            });""")
        page = context.new_page()
        page.on("pageerror", lambda error: page_errors.append(str(error)))
        page.on("websocket", lambda ws: socket_attempts.append(ws.url))
        try:
            response = page.goto(origin, wait_until="load")
            if origin == VIRTUAL_ORIGIN:
                assert response is not None and response.body() == html, "page bytes differ from the archive"
            expect(page.get_by_role("tablist").first).to_be_visible()
            page.screenshot(path=output / f"{device_name}.png", animations="disabled")
            if device_name == "mobile":
                page.screenshot(path=output / "mobile-full.png", full_page=True, animations="disabled")
            native = {case: {variant: native_record_check(page, html_file, case, variant)["outcome"]
                             for variant in ("genuine", "tampered")} for case in CASES}
            assert all(pair == {"genuine": "MATCH", "tampered": "REJECTED"} for pair in native.values()), native
            result = exercise(page, html_file, device_name, output)
            assert not blocked, f"unexpected resource requests were attempted: {blocked}"
            assert not socket_attempts, f"WebSocket connections were attempted: {socket_attempts}"
            assert not page_errors, f"page errors: {page_errors}"
            policy_violations = page.evaluate("window.labPolicyViolations")
            assert not policy_violations, f"CSP violations: {policy_violations}"
            assert set(observed) == {origin}, f"unexpected browser requests: {observed}"
            return {**result, "native_record_checks": native,
                    "document_requests": len(observed), "outbound_requests": 0,
                    "websocket_attempts": 0, "csp_violations": 0, "page_errors": 0}
        except (Error, AssertionError):
            page.screenshot(path=output / f"{device_name}-failure.png", full_page=True, animations="disabled")
            raise


def section(page, name):
    return page.locator(f"#tab-{name}"), page.locator(f"#panel-{name}")


def show_section(page, name):
    tab, panel = section(page, name)
    tab.click()
    expect(tab).to_have_attribute("aria-selected", "true")
    expect(panel).to_be_visible()
    return panel


def keyboard_navigation(page):
    overview, panel = section(page, "overview")
    assurance, assurance_panel = section(page, "assurance")
    overview.focus()
    page.keyboard.press("Shift+Tab")
    expect(page.get_by_role("link", name="Skip to evidence")).to_be_focused()
    page.keyboard.press("Enter")
    expect(page.locator("#main-content")).to_be_focused()
    overview.focus()
    page.keyboard.press("ArrowRight")
    expect(assurance).to_be_focused()
    page.keyboard.press("Enter")
    expect(assurance).to_have_attribute("aria-selected", "true")
    expect(assurance_panel).to_be_visible()
    expect(panel).to_be_hidden()
    show_section(page, "overview")


def viewport_width(page, device_name):
    sizes = page.evaluate("""() => ({viewport: document.documentElement.clientWidth,
      window: window.innerWidth, document: document.documentElement.scrollWidth})""")
    assert sizes["viewport"] == DEVICES[device_name]["viewport"]["width"], sizes
    assert sizes["document"] <= sizes["viewport"], f"page has horizontal overflow: {sizes}"
    return sizes


def artifact_controls(page, html_file, device_name, output):
    overview = section(page, "overview")[1]
    vector = (html_file.parent / "vectors" / "history" / "tampered.json").read_bytes()
    overview.locator("[data-artifact='tampered.json']").click()
    overview.locator("[data-action='check-digest']").click()
    digest_result = overview.locator("[data-region='digest-result']")
    expect(digest_result).to_contain_text(re.compile(r"^MATCH\b"))
    comparison = overview.get_by_label("Choose a local artifact to compare")
    comparison.set_input_files({"name": "comparison.json", "mimeType": "application/json", "buffer": vector + b"\n"})
    expect(digest_result).to_contain_text(re.compile(r"^MISMATCH\b"))
    comparison.set_input_files({"name": "comparison.json", "mimeType": "application/json", "buffer": vector})
    expect(digest_result).to_contain_text(re.compile(r"^MATCH\b"))
    overview.locator("[data-action='copy-artifact']").click()
    page.wait_for_function("async expected => await navigator.clipboard.readText() === expected",
                           arg=vector.decode("utf-8"))
    with page.expect_download() as captured:
        overview.locator("[data-action='download-artifact']").click()
    download = output / f"{device_name}-tampered.json"
    captured.value.save_as(download)
    assert download.read_bytes() == vector, "downloaded evidence differs from the standalone vector"
    if device_name == "desktop":
        page.screenshot(path=output / "desktop-evidence.png", full_page=True, animations="disabled")
    return {"artifact_copy": "EXACT_BYTES", "artifact_download": "EXACT_BYTES", "browser_digest": "MATCH",
            "altered_local_file_digest": "MISMATCH", "exact_local_file_digest": "MATCH"}


def finding_controls(page, html_file, device_name, output):
    panel = show_section(page, "review")
    form = panel.locator("[data-form='finding']")
    fields = {
        "environment": "Synthetic offline Chromium QA",
        "steps": "Select the tampered history inquiry and inspect the signed record result.",
        "expected": "An altered inquiry challenge is rejected.",
        "observed": "The tampered history record was rejected.",
    }
    for name, value in fields.items():
        form.locator(f"[name='{name}']").fill(value)
    with page.expect_download() as captured:
        form.locator("button[type='submit']").click()
    download = output / f"{device_name}-finding.json"
    captured.value.save_as(download)
    vector = html_file.parent / "vectors" / "history" / "tampered.json"
    manifest = html_file.parent / "manifest.json"
    expected = {
        **fields, "schema": "quorvane.public-lab.finding.v1", "experiment": "history", "variant": "tampered",
        "artifact_sha256": hashlib.sha256(vector.read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
    }
    actual = json.loads(download.read_bytes())
    assert actual == expected, "finding JSON differs from the selected fictional evidence and text"
    with TemporaryDirectory(prefix="finding-inbox-", dir=output) as temporary:
        finding_cli = html_file.parents[1] / "scripts" / "public_lab_finding.py"
        command = [sys.executable, "-I", str(finding_cli), "submit", str(download.resolve()),
                   "--inbox", str(Path(temporary).resolve() / "inbox")]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=True)
        intake = json.loads(result.stdout)
    if device_name == "desktop":
        page.screenshot(path=output / "desktop-finding.png", full_page=True, animations="disabled")
    return {"finding_download": "EXACT_REFERENCES", "finding_intake_exit": result.returncode,
            "finding_intake": intake["outcome"]}


def exercise(page, html_file, device_name, output):
    layout = viewport_width(page, device_name)
    keyboard_navigation(page)
    verdicts = {}
    overview = section(page, "overview")[1]
    for case in CASES:
        overview.locator(f"[data-experiment-id='{case}']").click()
        pair = {}
        for variant, verdict in (("genuine", "VERIFIED"), ("tampered", "REJECTED")):
            overview.locator(f"[data-variant='{variant}']").click()
            result = overview.locator("[data-region='recorded-result'] .verdict-outcome b")
            expect(result).to_have_text(verdict)
            command = overview.locator("[data-region='command']")
            expect(command).to_contain_text(f"{case}/{variant}.json")
            overview.locator("[data-action='check-signed-record']").click()
            native = "MATCH" if variant == "genuine" else "REJECTED"
            expect(overview.locator("[data-region='signed-result']")).to_contain_text(re.compile(r"^" + native + r"\b"))
            pair[variant] = verdict
        verdicts[case] = pair
        viewport_width(page, device_name)
    controls = artifact_controls(page, html_file, device_name, output)
    show_section(page, "assurance")
    viewport_width(page, device_name)
    controls.update(finding_controls(page, html_file, device_name, output))
    viewport_width(page, device_name)
    return {"viewport": layout, "keyboard_navigation": "PASS", "recorded_verdicts": verdicts, **controls}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--html", type=lambda path: Path(path).resolve(strict=True),
                        default=ROOT / "public_lab" / "index.html")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--chromium", default="/usr/bin/chromium")
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright, playwright.chromium.launch(
            executable_path=args.chromium, headless=True,
            args=["--disable-background-networking", "--disable-component-update", "--no-pings"]) as browser:
        access = file_access(browser, args.html)
        origin = args.html.as_uri() if access["outcome"] == "SUPPORTED" else VIRTUAL_ORIGIN
        device_checks = {}
        for device in DEVICES:
            try:
                checks = run_browser(browser, args.html, origin=origin, device_name=device, output=args.output)
                device_checks[device] = {"outcome": "PASS", **checks}
            except (AssertionError, Error, OSError, ValueError, subprocess.SubprocessError) as error:
                device_checks[device] = {"outcome": "BLOCKED", "reason": str(error).splitlines()[0]}
        try:
            unsupported = unsupported_check(browser, args.html)
        except (AssertionError, Error, OSError) as error:
            unsupported = {"outcome": "BLOCKED", "reason": str(error).splitlines()[0]}
        passed = (all(device["outcome"] == "PASS" for device in device_checks.values())
                  and unsupported["outcome"] == "UNSUPPORTED")
        report = {
            "outcome": "PASS" if passed else "BLOCKED", "browser": browser.version,
            "html_sha256": hashlib.sha256(args.html.read_bytes()).hexdigest(), "file_navigation": access,
            "navigation_mode": "DIRECT_FILE" if access["outcome"] == "SUPPORTED" else "VIRTUAL_LOOPBACK_OFFLINE",
            "device_checks": device_checks, "unsupported_control": unsupported,
        }
    raw = json.dumps(report, indent=2, sort_keys=True) + "\n"
    (args.output / "browser-qa.json").write_text(raw, encoding="utf-8")
    sys.stdout.write(raw)
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
