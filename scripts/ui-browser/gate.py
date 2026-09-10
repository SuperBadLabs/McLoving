#!/usr/bin/env python3
"""Executing browser gate for the shipped McLoving web client (UI-002).

`UI-001` closed asserting that a browser journey gate proved the desktop flow,
strict-YAML validation, the audit and explainability views, a clean console and a
390-pixel viewport without horizontal overflow. No such gate existed: the one
executing check read the served HTML as text and never rendered anything. This
module is that gate. It drives a real rendering engine against
`crates/controller-api/examples/ui_browser_fixture.rs` and makes each of those
claims a separately named assertion that can fail on its own.

It runs inside the contained browser image (scripts/ui-browser/Containerfile) and
speaks WebDriver classic to a pinned chromedriver over loopback HTTP, so it needs
nothing outside the Python standard library.

Exit status is the gate's verdict: 0 only when every assertion passed and the
count of assertions matched `--expected-assertions`.
"""

import argparse
import base64
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ORGANIZATION = "11111111-1111-4111-8111-111111111111"
PROJECT = "22222222-2222-4222-8222-222222222222"
BUILD = "33333333-3333-4333-8333-333333333333"
TOKEN = "browser-token"
VIEWS = ("dashboard", "pipeline", "build", "audit", "explain")

# A source that the strict-YAML parser must reject, and the substring of its
# refusal that has to reach the user. Duplicate mapping keys are the right probe
# because permissive YAML parsers accept them silently -- the refusal is
# evidence that the strict parser, not a lenient one, answered.
INVALID_PIPELINE_SOURCE = "version: 1\nname: first\nname: second\n"
INVALID_PIPELINE_REFUSAL = "duplicate mapping key"

# The source the client ships in its textarea, restored before any journey that
# needs the parser to accept, so an earlier refusal probe cannot leak into it.
VALID_PIPELINE_SOURCE = (
    "version: 1\n"
    "name: hello\n"
    "stages:\n"
    "  - id: hello\n"
    "    name: Hello\n"
    "    steps:\n"
    "      - process:\n"
    "          program: echo\n"
    "          args: [hello]\n"
)

TAB = "\ue004"


class WebDriverError(RuntimeError):
    pass


class Session:
    """The subset of WebDriver classic this gate needs."""

    def __init__(self, port, chrome_binary, window=(1280, 900)):
        self.base = f"http://127.0.0.1:{port}"
        payload = {
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "chrome",
                    "goog:chromeOptions": {
                        "binary": chrome_binary,
                        "args": [
                            "--headless=new",
                            # The container's namespaces are this browser's
                            # isolation boundary; see UI_BROWSER_GATE_V1.md.
                            "--no-sandbox",
                            "--disable-gpu",
                            "--disable-dev-shm-usage",
                            "--disable-background-networking",
                            "--disable-component-update",
                            "--disable-sync",
                            "--no-first-run",
                            "--no-default-browser-check",
                            f"--window-size={window[0]},{window[1]}",
                        ],
                    },
                    # Without this the browser log endpoint returns nothing and
                    # "clean console" would pass by never being asked.
                    "goog:loggingPrefs": {"browser": "ALL"},
                }
            }
        }
        self.session_id = self._request("POST", "/session", payload)["value"]["sessionId"]

    def _request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{self.base}{path}",
            data=data,
            method=method,
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise WebDriverError(
                f"{method} {path} failed: {error.read().decode(errors='replace')[:600]}"
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            # A dead or unreachable chromedriver is the common CI failure and it
            # is far easier to act on when it is named as one.
            raise WebDriverError(
                f"{method} {path} could not reach chromedriver at {self.base}: {error}"
            ) from error
        except json.JSONDecodeError as error:
            raise WebDriverError(
                f"{method} {path} returned a non-JSON body: {error}"
            ) from error

    def _session(self, method, path, body=None):
        return self._request(method, f"/session/{self.session_id}{path}", body)

    def navigate(self, url):
        self._session("POST", "/url", {"url": url})

    def script(self, source, *args):
        return self._session("POST", "/execute/sync", {"script": source, "args": list(args)})["value"]

    def console(self):
        return self._session("POST", "/log", {"type": "browser"}).get("value", [])

    def screenshot(self):
        return base64.b64decode(self._session("GET", "/screenshot")["value"])

    def press(self, *keys):
        """Send real key events, so focus moves the way a keyboard moves it."""
        actions = []
        for key in keys:
            actions.append({"type": "keyDown", "value": key})
            actions.append({"type": "keyUp", "value": key})
        self._session(
            "POST",
            "/actions",
            {"actions": [{"type": "key", "id": "keyboard", "actions": actions}]},
        )

    def set_viewport(self, width, height):
        """Set the *inner* width, which is what a 390-pixel claim is about.

        `Set Window Rect` sizes the outer window, so the viewport comes out
        narrower by whatever the window chrome costs. Measure and correct rather
        than assuming headless chrome has no border.
        """
        target = width
        outer = width
        for _ in range(6):
            self._session("POST", "/window/rect", {"width": outer, "height": height})
            inner = self.script("return window.innerWidth")
            if inner == target:
                return inner
            # Correct the OUTER width toward the target inner width. Folding the
            # correction back into the comparison value instead -- as this did --
            # makes every later iteration measure against a window size nobody
            # asked for, so a browser with any chrome at all never converges and
            # the 390-pixel assertion fails on a viewport that was in fact
            # reached.
            if not inner:
                break
            outer += target - inner
            if outer < 1:
                break
        return self.script("return window.innerWidth")

    def quit(self):
        try:
            self._session("DELETE", "")
        except WebDriverError:
            pass


class Gate:
    def __init__(self, session, base_url, output_dir):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.output_dir = output_dir
        self.results = []

    def assertion(self, name, ok, detail):
        self.results.append(
            {"assertion": name, "passed": bool(ok), "detail": detail}
        )
        status = "pass" if ok else "FAIL"
        print(f"  [{status}] {name}: {detail}", flush=True)
        return bool(ok)

    def capture(self, name):
        path = self.output_dir / "screenshots" / f"{name}.png"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.session.screenshot())
        return path

    # -- journey helpers ---------------------------------------------------

    def show_view(self, view):
        self.session.script(
            "for (const b of document.querySelectorAll('[data-view]'))"
            " if (b.dataset.view === arguments[0]) b.click();",
            view,
        )
        time.sleep(0.3)

    def connect_context(self):
        self.session.script(
            """
            document.getElementById('organization').value = arguments[0];
            document.getElementById('project').value = arguments[1];
            document.getElementById('token').value = arguments[2];
            document.getElementById('context-form').requestSubmit();
            """,
            ORGANIZATION,
            PROJECT,
            TOKEN,
        )
        self.settle()

    def settle(self, seconds=1.2):
        time.sleep(seconds)

    def result_text(self):
        return self.session.script(
            "return document.getElementById('operation-result').textContent"
        )

    def result_is_error(self):
        return self.session.script(
            "return document.getElementById('operation-result').classList.contains('error')"
        )

    # -- the claims UI-001 made ------------------------------------------

    def check_dashboard(self):
        self.show_view("dashboard")
        rows = self.session.script("return document.querySelectorAll('#build-list tr').length")
        first = self.session.script(
            "const c = document.querySelector('#build-list tr td');"
            " return c ? c.textContent : null;"
        )
        self.capture("dashboard")
        self.assertion(
            "desktop_dashboard_lists_builds",
            rows >= 1 and first == BUILD,
            f"{rows} row(s), first build id {first!r}",
        )

    def check_pipeline_validate_accepts(self):
        self.show_view("pipeline")
        self.session.script("document.getElementById('validate-pipeline').click()")
        self.settle()
        text, errored = self.result_text(), self.result_is_error()
        self.capture("pipeline-validate-accepted")
        self.assertion(
            "desktop_pipeline_validate_accepts_valid_source",
            not errored and '"valid": true' in text,
            f"error-styled={errored}, result begins {text[:80]!r}",
        )

    def check_strict_yaml_refusal(self):
        """The refusal must be the strict parser's, and it must reach the user.

        The fixture compiles this source through the same
        `compile_strict_yaml_with_parameters` entry point the shipped
        `validate_pipeline` handler uses, so the message asserted here is the
        production parser's own wording rather than an error the gate injected.
        """
        self.show_view("pipeline")
        self.session.script(
            "document.getElementById('pipeline-source').value = arguments[0];"
            " document.getElementById('validate-pipeline').click();",
            INVALID_PIPELINE_SOURCE,
        )
        self.settle()
        text, errored = self.result_text(), self.result_is_error()
        self.capture("pipeline-validate-refused")
        self.assertion(
            "strict_yaml_refusal_surfaced_to_user",
            errored
            and "pipeline_rejected" in text
            and INVALID_PIPELINE_REFUSAL in text,
            f"error-styled={errored}, rendered refusal {text[:140]!r}",
        )

    def check_pipeline_plan(self):
        self.show_view("pipeline")
        self.session.script(
            "document.getElementById('pipeline-source').value = arguments[0];"
            " document.getElementById('plan-pipeline').click();",
            VALID_PIPELINE_SOURCE,
        )
        self.settle()
        text = self.result_text()
        self.capture("pipeline-plan")
        self.assertion(
            "desktop_pipeline_plan_renders_stages",
            '"stages"' in text and '"process_steps"' in text,
            f"plan result begins {text[:80]!r}",
        )

    def check_pipeline_save_and_submit(self):
        self.show_view("pipeline")
        self.session.script("document.getElementById('save-pipeline').click()")
        self.settle()
        saved = self.result_text()
        self.session.script("document.getElementById('pipeline-form').requestSubmit()")
        self.settle()
        submitted = self.result_text()
        self.capture("pipeline-submitted")
        self.assertion(
            "desktop_pipeline_save_and_submit",
            '"revision"' in saved and '"build_id"' in submitted,
            f"save {saved[:60]!r}; submit {submitted[:60]!r}",
        )

    def check_build_view(self):
        self.show_view("build")
        self.session.script(
            "document.getElementById('build-id').value = arguments[0];"
            " document.getElementById('build-form').requestSubmit();",
            BUILD,
        )
        self.settle(1.6)
        panels = self.session.script(
            """
            const ids = ['build-summary','build-graph','build-logs','build-tests','build-approvals'];
            const out = {};
            for (const id of ids) out[id] = document.getElementById(id).textContent.trim().length;
            // The artifact panel renders controls rather than text, so a text
            // length would report it populated while it held nothing. Count the
            // rows and their download controls instead. Leaving it out of this
            // list let the whole artifact surface disappear with the assertion
            // still green.
            out['build-artifacts'] = document.querySelectorAll(
                '#build-artifacts .artifact').length;
            out['artifact-download-controls'] = document.querySelectorAll(
                '#build-artifacts .artifact button').length;
            return out;
            """
        )
        self.capture("build")
        empty = [name for name, length in panels.items() if length == 0]
        self.assertion(
            "desktop_build_view_renders_all_panels",
            not empty,
            f"populated {panels}" if not empty else f"empty panels: {empty}",
        )

    def check_audit_view(self):
        self.show_view("audit")
        self.session.script("document.getElementById('load-audit').click()")
        self.settle()
        text = self.session.script(
            "return document.getElementById('audit-output').textContent"
        )
        self.capture("audit")
        self.assertion(
            "desktop_audit_view_renders_events",
            '"events"' in text and "build.submitted" in text,
            f"audit output begins {text[:80]!r}",
        )

    def check_explain_view(self):
        self.show_view("explain")
        self.session.script("document.getElementById('explain-form').requestSubmit()")
        self.settle()
        text = self.session.script(
            "return document.getElementById('explain-output').textContent"
        )
        self.capture("explain")
        self.assertion(
            "desktop_explain_view_renders_reason",
            '"reason"' in text,
            f"explain output begins {text[:80]!r}",
        )

    def check_console_clean(self):
        """Split in two, because these fail for different reasons.

        A script error is always a defect. A failed network request is only a
        defect if the gate did not deliberately provoke it: this run submits a
        knowingly invalid pipeline to prove the refusal reaches the user, and the
        browser logs that correct 422 as a SEVERE console entry. Excusing it
        wholesale would let a genuine script error hide behind the same
        allowance, so the excused set is enumerated by URL and status and written
        into the evidence rather than inferred.
        """
        entries = [
            entry
            for entry in self.session.console()
            if entry.get("level") in ("SEVERE", "ERROR")
        ]
        script_errors = [e for e in entries if e.get("source") != "network"]
        network_errors = [e for e in entries if e.get("source") == "network"]
        provoked, unexpected = [], []
        for entry in network_errors:
            message = entry.get("message", "")
            if "/pipelines/validate" in message and "422" in message:
                provoked.append(entry)
            else:
                unexpected.append(entry)

        (self.output_dir / "console.json").write_text(
            json.dumps(
                {
                    "script_errors": script_errors,
                    "provoked_network_failures": provoked,
                    "unexpected_network_failures": unexpected,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        self.assertion(
            "console_has_no_script_errors",
            not script_errors,
            "no script errors logged across every journey"
            if not script_errors
            else f"{len(script_errors)}: "
            + "; ".join(e.get("message", "")[:150] for e in script_errors[:4]),
        )
        self.assertion(
            "console_has_no_unexpected_resource_failures",
            not unexpected,
            f"{len(provoked)} deliberately provoked refusal(s), nothing else"
            if not unexpected
            else f"{len(unexpected)} unexpected: "
            + "; ".join(e.get("message", "")[:150] for e in unexpected[:4]),
        )

    def check_viewport_390(self):
        inner = self.session.set_viewport(390, 844)
        offenders = {}
        for view in VIEWS:
            self.show_view(view)
            time.sleep(0.35)
            state = self.session.script(
                """
                const de = document.documentElement;
                const wide = [];
                for (const el of document.querySelectorAll('body *')) {
                  if (el.closest('.hidden')) continue;
                  // Elements inside their own horizontal scroller are contained
                  // by it and do not widen the document.
                  let scroller = false;
                  for (let p = el.parentElement; p; p = p.parentElement) {
                    const o = getComputedStyle(p).overflowX;
                    if (o === 'auto' || o === 'scroll') { scroller = true; break; }
                  }
                  if (scroller) continue;
                  if (el.getBoundingClientRect().right > de.clientWidth + 1) {
                    wide.push({tag: el.tagName, id: el.id || null,
                               cls: (el.className && el.className.toString()) || null,
                               right: Math.round(el.getBoundingClientRect().right)});
                  }
                }
                return {viewport: de.clientWidth, scrollWidth: de.scrollWidth,
                        overflowing: de.scrollWidth > de.clientWidth, widest: wide.slice(0, 6)};
                """
            )
            self.capture(f"viewport-390-{view}")
            if state["overflowing"]:
                offenders[view] = state
        self.session.set_viewport(1280, 900)
        self.assertion(
            "viewport_390_has_no_horizontal_overflow",
            inner == 390 and not offenders,
            f"inner width {inner}px, no view overflows"
            if not offenders
            else f"inner width {inner}px; overflowing: "
            + "; ".join(
                f"{view} scrollWidth={s['scrollWidth']} "
                f"({', '.join(str(w['tag']) + (('#' + w['id']) if w['id'] else '') for w in s['widest'][:3])})"
                for view, s in offenders.items()
            ),
        )

    def check_landmarks(self):
        state = self.session.script(
            """
            return {banner: document.querySelectorAll('body > header').length,
                    main: document.querySelectorAll('main').length,
                    nav: document.querySelectorAll('nav[aria-label]').length,
                    h1: document.querySelectorAll('h1').length,
                    labelledSections: [...document.querySelectorAll('section[aria-labelledby]')]
                      .filter(s => document.getElementById(s.getAttribute('aria-labelledby'))).length,
                    sections: document.querySelectorAll('section').length,
                    live: [...document.querySelectorAll('[role=status][aria-live]')].map(e => e.id)};
            """
        )
        ok = (
            state["banner"] == 1
            and state["main"] == 1
            and state["nav"] >= 1
            and state["h1"] == 1
            and state["labelledSections"] == state["sections"]
            and len(state["live"]) >= 2
        )
        self.assertion("landmarks_present_in_rendered_dom", ok, json.dumps(state, sort_keys=True))

    def check_accessible_names(self):
        unnamed = []
        for view in VIEWS:
            self.show_view(view)
            unnamed.extend(
                self.session.script(
                    """
                    const bad = [];
                    for (const el of document.querySelectorAll('input,select,textarea,button')) {
                      if (el.closest('.hidden')) continue;
                      let name = el.getAttribute('aria-label') || '';
                      if (!name && el.labels && el.labels.length) {
                        name = [...el.labels].map(l => l.textContent.trim()).join(' ');
                      }
                      if (!name && el.tagName === 'BUTTON') name = el.textContent.trim();
                      if (!name.trim()) {
                        bad.push({view: arguments[0], tag: el.tagName, id: el.id || null,
                                  html: el.outerHTML.slice(0, 80)});
                      }
                    }
                    return bad;
                    """,
                    view,
                )
            )
        self.assertion(
            "every_control_has_accessible_name",
            not unnamed,
            "every rendered control resolves a non-empty name"
            if not unnamed
            else f"{len(unnamed)} unnamed: {json.dumps(unnamed[:4])}",
        )

    def check_keyboard_focus_visible(self):
        """Tab through each view and require a visible focus ring at every stop.

        `:focus-visible` is what the shipped stylesheet keys its outline off, so
        the assertion checks the computed outline of the element the browser
        actually considers keyboard-focused -- not merely that a rule exists.
        """
        invisible = []
        stops = 0
        for view in VIEWS:
            self.show_view(view)
            self.session.script("document.body.focus(); window.focus();")
            # Tab the whole view, not a sample of it: count the focusable
            # controls the view actually renders and walk every one. The cap is
            # a runaway guard, not the intended stopping point.
            focusable = self.session.script(
                """
                let n = 0;
                for (const el of document.querySelectorAll(
                    'a[href],button,input,select,textarea,[tabindex]')) {
                  if (el.closest('.hidden')) continue;
                  if (el.disabled) continue;
                  if (el.getAttribute('tabindex') === '-1') continue;
                  n += 1;
                }
                return n;
                """
            )
            for _ in range(min(focusable, 120)):
                self.session.press(TAB)
                state = self.session.script(
                    """
                    const el = document.activeElement;
                    if (!el || el === document.body) return null;
                    const style = getComputedStyle(el);
                    return {tag: el.tagName, id: el.id || null,
                            focusVisible: el.matches(':focus-visible'),
                            outlineStyle: style.outlineStyle,
                            outlineWidth: style.outlineWidth,
                            hidden: !!el.closest('.hidden')};
                    """
                )
                if state is None or state["hidden"]:
                    continue
                stops += 1
                visible = (
                    state["focusVisible"]
                    and state["outlineStyle"] != "none"
                    and state["outlineWidth"] not in ("0px", "")
                )
                if not visible:
                    invisible.append({"view": view, **state})
            self.capture(f"focus-{view}")
        self.assertion(
            "keyboard_focus_is_visible_through_journeys",
            stops > 0 and not invisible,
            f"{stops} keyboard stops across {len(VIEWS)} views, every one with a visible ring"
            if not invisible
            else f"{len(invisible)} of {stops} stops without a visible ring: "
            + json.dumps(invisible[:4]),
        )

    def check_focus_survives_live_updates(self):
        """Focus must survive the refreshes the client performs on its own.

        The dashboard rebuilds its table body wholesale, and the build view does
        the same work on a timer. A keyboard user who is on a control when either
        fires must still be on it afterwards, or the interface is unusable
        without a mouse the moment anything live is running.
        """
        self.show_view("dashboard")
        self.settle(0.4)
        before = self.session.script(
            """
            const button = document.querySelector('#build-list tr button');
            if (!button) return null;
            button.focus();
            return {id: document.activeElement.id || null,
                    text: (document.activeElement.textContent || '').slice(0, 60),
                    row: document.activeElement.closest('tr')?.querySelector('td')?.textContent};
            """
        )
        # One assertion call, whatever happened. Reporting the same claim from
        # two call sites would make it impossible to pin the assertion count or
        # to mutation-prove which of them bound.
        if before is None:
            ok = False
            detail = "no build row rendered, so focus could not be placed"
        else:
            for _ in range(3):
                self.session.script("document.getElementById('refresh-builds').click()")
                self.settle(0.9)
            after = self.session.script(
                """
                const el = document.activeElement;
                // Cap the text: when focus has fallen back to <body> its
                // textContent is the whole page, which would bury the verdict.
                return {tag: el.tagName, id: el.id || null,
                        text: (el.textContent || '').slice(0, 60),
                        isBody: el === document.body,
                        row: el.closest && el.closest('tr')
                             ? el.closest('tr').querySelector('td').textContent : null,
                        focusVisible: el.matches ? el.matches(':focus-visible') : false};
                """
            )
            self.capture("focus-after-refresh")
            ok = (
                not after["isBody"]
                and after["text"] == before["text"]
                and after["row"] == before["row"]
            )
            detail = f"focus before {before} -> after {after}"
        self.assertion("focus_survives_repeated_live_updates", ok, detail)

    def check_artifact_download(self):
        """Activate the Download control, not merely observe that it exists.

        Asserting that rows and buttons render stops one step short of the
        journey the client advertises: the click listener could be gone, the URL
        `downloadArtifact` builds could be wrong, or the response could be
        unusable, and a render-only assertion would stay green through all three.
        """
        self.show_view("build")
        self.settle(0.4)
        clicked = self.session.script(
            """
            const buttons = document.querySelectorAll('#build-artifacts .artifact button');
            const button = buttons[buttons.length - 1];
            if (!button) return null;
            if (button.disabled) return {disabled: true};
            button.click();
            return {disabled: false, count: buttons.length};
            """
        )
        self.settle(1.4)
        result = self.result_text()
        errored = self.result_is_error()
        self.capture("artifact-download")
        # The byte count comes from the rendered listing, and the fixture serves
        # exactly that many bytes, so a client that fetched a different record
        # would disagree with what it had just displayed.
        self.assertion(
            "artifact_download_delivers_content",
            clicked is not None
            and not clicked.get("disabled")
            and not errored
            and '"downloaded": "report.txt"' in result
            and '"bytes": 34' in result,
            f"clicked={clicked}, error-styled={errored}, result {result[:120]!r}",
        )

    def check_focus_survives_build_view_live_refresh(self):
        """The surface that refreshes *by itself*, not the one you click.

        `focus_survives_repeated_live_updates` drives the dashboard's manual
        Refresh button. That is not the case a keyboard user actually hits: the
        build view re-renders its artifact rows on a two-second timer, through a
        different call site (`renderArtifacts`), with no user action at all.
        Asserting only the clicked path meant removing focus preservation from
        `renderArtifacts` left every assertion green -- the repair was real and
        the coverage was not, which is the same defect this whole ticket exists
        to correct.
        """
        self.show_view("build")
        self.session.script(
            "document.getElementById('build-id').value = arguments[0];"
            " document.getElementById('build-form').requestSubmit();",
            BUILD,
        )
        self.settle(1.6)
        before = self.session.script(
            """
            // The LAST row, deliberately. The two fixture artifacts share an
            // attempt and a name and differ only by fence, so restoring focus
            // to "the first row matching the key" is only indistinguishable
            // from correct behaviour if the key ignores the fence. Focusing the
            // second row makes that property load-bearing here.
            const buttons = document.querySelectorAll('#build-artifacts .artifact button');
            const button = buttons[buttons.length - 1];
            if (!button) return null;
            button.focus();
            const row = button.closest('[data-focus-key]');
            const rows = [...document.querySelectorAll('#build-artifacts .artifact')];
            return {key: row ? row.dataset.focusKey : null,
                    index: rows.indexOf(row),
                    label: (row ? row.textContent : '').slice(0, 60)};
            """
        )
        # One assertion call, whatever happened: two call sites for the same
        # claim make the count unpinnable and the failure unattributable.
        if before is None:
            ok = False
            detail = "no artifact row rendered, so focus could not be placed"
        else:
            # Start the client's own timer and let it fire more than once.
            # Nothing below clicks anything: the refreshes have to happen on
            # their own or the assertion is testing the wrong thing.
            self.session.script("document.getElementById('toggle-live').click()")
            time.sleep(5.0)
            after = self.session.script(
                """
                const el = document.activeElement;
                const row = el.closest ? el.closest('[data-focus-key]') : null;
                const rows = [...document.querySelectorAll('#build-artifacts .artifact')];
                // Compare the row's IDENTITY, not just its key. Under a key that
                // drops the fence both artifact rows carry the SAME key, so a
                // key-only comparison cannot tell "restored to the row I was on"
                // from "restored to the first row that looked like it". The
                // mutation proof caught exactly that escape.
                return {tag: el.tagName, isBody: el === document.body,
                        key: row ? row.dataset.focusKey : null,
                        index: row ? rows.indexOf(row) : -1,
                        label: (row ? row.textContent : '').slice(0, 60),
                        focusVisible: el.matches ? el.matches(':focus-visible') : false};
                """
            )
            self.session.script("document.getElementById('toggle-live').click()")
            self.capture("focus-after-live-refresh")
            ok = (
                not after["isBody"]
                and after["key"] == before["key"]
                and after["index"] == before["index"]
                and after["label"] == before["label"]
            )
            detail = f"focus before {before} -> after {after}"
        self.assertion("focus_survives_build_view_live_refresh", ok, detail)

    def check_live_status_announcements(self):
        """A live region only announces if its text actually changes in place."""
        readings = self.session.script(
            "return {connection: document.getElementById('connection-state').textContent,"
            " live: document.getElementById('connection-state').getAttribute('aria-live'),"
            " resultLive: document.getElementById('operation-result').getAttribute('aria-live'),"
            " logsLive: document.getElementById('build-logs').getAttribute('aria-live')}"
        )
        self.show_view("dashboard")
        first = self.result_text()
        self.session.script("document.getElementById('load-audit').click()")
        self.settle()
        second = self.result_text()
        changed = first != second
        self.assertion(
            "live_status_region_announces_changes",
            readings["connection"] == "Context active"
            and readings["live"] == "polite"
            and readings["resultLive"] == "polite"
            and readings["logsLive"] == "polite"
            and changed,
            f"regions {json.dumps(readings, sort_keys=True)}, result text changed={changed}",
        )

    def run(self):
        self.session.navigate(f"{self.base_url}/")
        self.settle(0.8)
        self.capture("initial-load")
        self.connect_context()
        self.check_dashboard()
        self.check_pipeline_validate_accepts()
        self.check_pipeline_plan()
        self.check_pipeline_save_and_submit()
        self.check_strict_yaml_refusal()
        self.check_build_view()
        self.check_audit_view()
        self.check_explain_view()
        self.check_landmarks()
        self.check_accessible_names()
        self.check_keyboard_focus_visible()
        self.check_focus_survives_live_updates()
        self.check_artifact_download()
        self.check_focus_survives_build_view_live_refresh()
        self.check_live_status_announcements()
        self.check_viewport_390()
        # Console last: it accumulates across every journey above, so asking
        # earlier would exempt everything that came after.
        self.check_console_clean()
        return self.results


def wait_for_port(port, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.25).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def source_manifest(ui_source_dir):
    """Bind the evidence to the exact client bytes that produced it.

    A baseline that does not name the source it rendered cannot be compared
    against anything later, which is the failure `UI-002` exists to correct.
    """
    manifest = {}
    for name in sorted(("index.html", "app.js", "app.css")):
        path = ui_source_dir / name
        data = path.read_bytes()
        manifest[name] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "lines": data.decode("utf-8").count("\n"),
        }
    combined = hashlib.sha256()
    for name in sorted(manifest):
        combined.update(name.encode())
        combined.update(bytes.fromhex(manifest[name]["sha256"]))
    return {"files": manifest, "combined_sha256": combined.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:19090")
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--ui-source-dir", required=True, type=pathlib.Path)
    parser.add_argument("--label", required=True)
    parser.add_argument(
        "--expected-assertions",
        type=int,
        required=True,
        help="pinned assertion count; a gate that silently stops running "
        "assertions must fail rather than report success",
    )
    parser.add_argument(
        "--record-only",
        action="store_true",
        help="record the verdict without failing the process. For capturing a "
        "pre-repair baseline only; CI must never pass this.",
    )
    parser.add_argument("--driver-port", type=int, default=19515)
    arguments = parser.parse_args()

    chrome = os.environ.get("MCLOVING_CHROME", "/opt/mcloving/chrome-linux64/chrome")
    chromedriver = os.environ.get(
        "MCLOVING_CHROMEDRIVER", "/opt/mcloving/chromedriver-linux64/chromedriver"
    )
    arguments.output_dir.mkdir(parents=True, exist_ok=True)

    driver = subprocess.Popen(
        [chromedriver, f"--port={arguments.driver_port}", "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    session = None
    try:
        if not wait_for_port(arguments.driver_port):
            print("chromedriver did not accept connections", file=sys.stderr)
            return 69
        session = Session(arguments.driver_port, chrome)
        gate = Gate(session, arguments.base_url, arguments.output_dir)
        print(f"Browser gate: {arguments.label}", flush=True)
        results = gate.run()
    finally:
        if session is not None:
            session.quit()
        driver.terminate()
        try:
            driver.wait(timeout=15)
        except subprocess.TimeoutExpired:
            driver.kill()
            driver.wait(timeout=15)

    failed = [r for r in results if not r["passed"]]
    counted = len(results)
    count_matches = counted == arguments.expected_assertions

    verdict = {
        "label": arguments.label,
        "gate_protocol": "mcloving.ui.browser/1",
        "browser": {
            "chrome": subprocess.run(
                [chrome, "--version"], capture_output=True, text=True, check=False
            ).stdout.strip(),
            "chromedriver": subprocess.run(
                [chromedriver, "--version"], capture_output=True, text=True, check=False
            ).stdout.strip(),
        },
        "ui_source": source_manifest(arguments.ui_source_dir),
        "expected_assertions": arguments.expected_assertions,
        "observed_assertions": counted,
        "assertion_count_matches": count_matches,
        "passed": len(results) - len(failed),
        "failed": len(failed),
        "failing_assertions": [r["assertion"] for r in failed],
        "recorded_without_enforcing": bool(arguments.record_only),
        "assertions": results,
    }
    (arguments.output_dir / "gate-results.json").write_text(
        json.dumps(verdict, indent=2, sort_keys=True) + "\n"
    )

    print(
        f"\n{verdict['passed']} passed, {verdict['failed']} failed, "
        f"{counted} assertions (expected {arguments.expected_assertions})",
        flush=True,
    )
    print(f"Client source {verdict['ui_source']['combined_sha256']}", flush=True)

    if not count_matches:
        print(
            f"assertion count {counted} does not match the pinned "
            f"{arguments.expected_assertions}; update the pin deliberately",
            file=sys.stderr,
        )
        # A wrong count is a gate defect, not a UI verdict, so it fails even
        # when the run was only meant to record a baseline.
        return 65
    if failed:
        if arguments.record_only:
            print(
                f"recorded {len(failed)} failing assertion(s) without enforcing: "
                + ", ".join(verdict["failing_assertions"]),
                file=sys.stderr,
            )
            return 0
        print(
            "failing assertions: " + ", ".join(verdict["failing_assertions"]),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
