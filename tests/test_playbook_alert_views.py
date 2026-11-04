# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Playbook alert details widget: one section per category, rendered from the BFI response.

SOAR's widget base template and custom_template tags are only available on a SOAR instance,
so they are replaced with stubs and the details template is rendered with Django directly.
"""

import os
import re
import sys
import types

import pytest


django = pytest.importorskip("django")
from django.conf import settings
from django.template import Context, Engine

from recordedfuture_view import (
    PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING,
    format_datetime_string,
    playbook_alert_details_results,
    playbook_alert_search_results,
)


APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STUB_TAGS_MODULE = "recordedfuture_test_custom_template"


class FakeResult:
    def __init__(self, data, param=None):
        self._data = data
        self._param = param or {}

    def get_data(self):
        return self._data

    def get_param(self):
        return self._param


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    if not settings.configured:
        settings.configure()
        django.setup()
    stub_dir = tmp_path_factory.mktemp("templates")
    (stub_dir / "widgets").mkdir()
    (stub_dir / "widgets" / "widget_template.html").write_text("{% block widget_content %}{% endblock %}")
    tags = types.ModuleType(STUB_TAGS_MODULE)
    tags.register = django.template.Library()
    sys.modules[STUB_TAGS_MODULE] = tags
    return Engine(dirs=[APP_DIR, str(stub_dir)], libraries={"custom_template": STUB_TAGS_MODULE})


def render_details(engine, alert):
    context = {}
    template_name = playbook_alert_details_results(None, [(None, [FakeResult([alert])])], context)
    return engine.get_template(template_name).render(Context(context))


def make_alert(category, case_rule_label, summary=None, **panels):
    return {
        "playbook_alert_id": "task:test",
        "category": category,
        "panel_status": {
            "status": "New",
            "priority": "High",
            "created": "2026-11-01T10:00:00.000+00:00",
            "updated": "2026-11-02T10:00:00.000+00:00",
            "case_rule_label": case_rule_label,
            "entity_name": "Subject name",
        },
        "panel_evidence_summary": summary or {},
        **panels,
    }


def assert_rendered(html, *texts):
    for text in texts:
        assert text in html, f"{text!r} not rendered"


def test_search_results_use_category_display_names():
    alerts = [
        {
            "playbook_alert_id": f"task:{category}",
            "category": category,
            "status": "New",
            "created": "2026-11-01T10:00:00.000+00:00",
            "updated": "2026-11-02T10:00:00.000+00:00",
        }
        for category in PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING
    ]
    context = {}
    playbook_alert_search_results(None, [(None, [FakeResult([alerts])])], context)
    rendered = {alert["category"]: alert["category_display"] for alert in context["results"][0]["data"]}
    assert rendered == PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING


def make_identity_alert():
    alert = make_alert(
        "identity_novel_exposures",
        "Novel Identity Exposure",
        summary={
            "subject": "poc_user411@acme.com",
            "assessments": [{"name": "Stealer Malware", "criticality": "Moderate"}],
            "exposed_secret": {
                "type": "clear",
                "effectively_clear": True,
                "hashes": [{"algorithm": "SHA256"}, {"algorithm": "MD5"}, {"algorithm": "SHA256"}],
                "details": {"properties": ["UpperCase", "AtLeast8Characters", "Letter", "Number"], "clear_text_hint": "Y1"},
            },
            "dump": {"name": "Combolist 2026"},
            "authorization_url": "https://appv2.sanctionscanner.com/Login/Index",
            "infrastructure": {"ip": "78.183.209.231"},
            "compromised_host": {
                "exfiltration_date": "2026-11-05T19:51:00.000+00:00",
                "os": "macOS 26.5.1 (25F80)",
                "os_username": "ibrahimordo",
                "antivirus": ["Defender", "XProtect"],
            },
            "malware_family": {"name": "Phexia Stealer"},
            "technologies": [{"name": "Okta", "category": "SSO"}],
        },
    )
    alert["panel_status"].update({"assignee_name": "Aaron Soehnen", "alert_rule": {"name": "Identity Exposure"}})
    return alert


def test_identity_novel_exposures_details(engine):
    assert PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING["identity_novel_exposures"] == "Novel Identity Exposure"
    html = render_details(engine, make_identity_alert())
    assert_rendered(
        html,
        "Novel Identity Exposure",
        "poc_user411@acme.com",
        "rf-priority-level-Moderate",
        "Stealer Malware",
        "Aaron Soehnen",
        "2026-11-02, 10:00",
        "Identity Exposure",
        'href="https://app.recordedfuture.com/portal/playbook-alerts/task:test"',
        "Y1••••",
        "(effectively clear)",
        "UpperCase, AtLeast8Characters, Letter, Number",
        "MD5, SHA256",
        "Combolist 2026",
        ">appv2.sanctionscanner.com<",
        "https://appv2.sanctionscanner.com/Login/Index",
        "78.183.209.231",
        "2026-11-05, 19:51",
        "macOS 26.5.1 (25F80)",
        "ibrahimordo",
        "Defender, XProtect",
        "Phexia Stealer",
        "Okta (Category: SSO)",
        "Enforce Password Reset",
    )


def test_identity_novel_exposures_missing_host_fields_show_na(engine):
    html = render_details(engine, make_identity_alert())
    for label in ("File Path Location", "Time Zone", "Name of the Machine", "User Account Control Setting"):
        assert re.search(label + r"</div>\s*<div>N/A</div>", html), label


def test_identity_novel_exposures_never_shows_a_clear_text_value(engine):
    alert = make_identity_alert()
    alert["panel_evidence_summary"]["exposed_secret"]["details"]["clear_text_value"] = "Y1SecretValue"
    assert "Y1SecretValue" not in render_details(engine, alert)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2026-11-01T10:00:00.000+00:00", "2026-11-01, 10:00"),
        ("2026-11-01T00:00:00Z", "2026-11-01, 00:00"),
        ("2026-11-05T19:51:00.123Z", "2026-11-05, 19:51"),
        ("not a date", "not a date"),
        (None, None),
    ],
)
def test_format_datetime_string(value, expected):
    assert format_datetime_string(value) == expected
