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
    defang_url,
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


def make_third_party_risk_alert(assessments):
    alert = make_alert("third_party_risk", "Third Party Risk", summary={"assessments": assessments})
    alert["panel_status"].update(
        {
            "targets": [{"name": "Acme Corp"}],
            "tags": ["Critical Supplier"],
            "risk_score": 80,
            "assignee_name": "Aaron Soehnen",
            "alert_rule": {"name": "Third parties"},
        }
    )
    return alert


def tpr_assessment(evidence_type, data, level=3, added="2026-11-01T00:00:00Z", metadata=None):
    assessment = {
        "risk_rule": f"Rule for {evidence_type}",
        "level": level,
        "added": added,
        "evidence": {"type": evidence_type, "summary": f"Summary of {evidence_type}", "data": data},
    }
    if metadata:
        assessment["metadata"] = metadata
    return assessment


def test_third_party_risk_details(engine):
    assert PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING["third_party_risk"] == "Third Party Risk"
    html = render_details(
        engine,
        make_third_party_risk_alert(
            [
                tpr_assessment(
                    "reference",
                    [{"title": "Acme breached", "source": "News", "document_url": "https://news.example/a", "fragment": "frag"}],
                    metadata={"assessment_description": "A breach was reported", "action_to_consider": "Contact the vendor"},
                )
            ]
        ),
    )
    assert_rendered(
        html,
        "Third Party Risk",
        "Subject name",
        "Critical Supplier",
        "Acme Corp",
        "Aaron Soehnen",
        "Third parties",
        'href="https://app.recordedfuture.com/portal/playbook-alerts/task:test"',
        "rf-priority-level-High",
        "Security Incidents",
        "2026-11-01, 00:00",
        "Rule for reference",
        "Summary of reference",
        "A breach was reported",
        "Contact the vendor",
        "Acme breached",
        "https://news.example/a",
    )


@pytest.mark.parametrize(
    "evidence_type, data, texts",
    [
        (
            "insikt_note",
            [{"id": "doc:1", "title": "Note title", "topic": "Topic", "fragment": "Note text"}],
            ["Note title", "Note text", "doc:1"],
        ),
        (
            "hosts_communication",
            [{"recent_timestamp": "2026-11-02T00:00:00Z", "malware_family": "Emotet", "client_ip_address": "198.51.100.1"}],
            ["Malicious Network Activity", "2026-11-02, 00:00", "Emotet", "198.51.100.1", "N/A"],
        ),
        ("ip_rule", [{"name": "Recent C2", "criticality": 3, "number_of_ip_addresses": 4}], ["Recent C2", "4 IPs"]),
        ("cyber_trend", [{"date": "2026-11-03T00:00:00Z", "criticality": 2, "number_of_references": 7}], ["Cyber Trends", "7 references"]),
        (
            "exposed_credentials",
            [{"email": "bob@acme.example", "password": "$2y****", "document_title": "Dump", "document_publish_date": "2026-11-04T00:00:00Z"}],
            ["Exposed Credentials", "bob@acme.example", "$2y****", "Dump", "2026-11-04, 00:00"],
        ),
        ("brand_new_type", [], ["Unsupported evidence type: brand_new_type"]),
    ],
)
def test_third_party_risk_evidence_types(engine, evidence_type, data, texts):
    assert_rendered(render_details(engine, make_third_party_risk_alert([tpr_assessment(evidence_type, data)])), *texts)


def test_third_party_risk_level_names_and_newest_first(engine):
    html = render_details(
        engine,
        make_third_party_risk_alert(
            [
                tpr_assessment("summary_string", [], level=1, added="2026-10-01T00:00:00Z"),
                tpr_assessment("ip_rule", [], level=2, added="2026-11-01T00:00:00Z"),
            ]
        ),
    )
    assert html.index("Rule for ip_rule") < html.index("Rule for summary_string")
    assert_rendered(html, "rf-priority-level-Moderate", "rf-priority-level-Informational")
    assert "Unsupported evidence type" not in html


def test_third_party_risk_without_assessments(engine):
    assert_rendered(render_details(engine, make_third_party_risk_alert([])), "No assessments")


def test_malware_report_details(engine):
    assert PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING["malware_report"] == "Malware Report"
    sha256 = "1012529307d89ecb678d0b5f1495db20a21ccfb4ae0726358cb32817ca0dd540"  # pragma: allowlist secret
    alert = make_alert(
        "malware_report",
        "Ransomware samples",
        summary={
            "notification_title": "LockBit sandbox reports",
            "number_of_reports": 2,
            "report_limit_reached": True,
            "matched_hashes": [{"sha256": sha256, "risk_score": 89, "report_overviews": [{}, {}]}],
            "detected_malwares": [{"name": "LockBit", "count": 2}],
            "sandbox_scores": [{"score": 10, "count": 2}],
        },
    )
    alert["panel_status"]["alert_rule"] = {"name": "Ransomware samples"}
    html = render_details(engine, alert)
    assert_rendered(
        html,
        "Malware Report",
        "LockBit sandbox reports",
        "Ransomware samples",
        "report limit reached",
        "LockBit (2)",
        sha256,
        "Risk score: 89",
        "Reports: 2",
    )


def test_malware_report_details_fall_back_to_case_rule_label(engine):
    html = render_details(engine, make_alert("malware_report", "Rule from label"))
    assert_rendered(html, "Rule from label")


def make_dark_web_alert(details):
    alert = make_alert(
        "dark_web",
        "Dark Web Brand",
        summary={
            "matched_assets": [{"type": "brand", "entity_id": "x", "name": "Acme Corp"}, {"type": "domain", "entity_id": "idn:acme.example"}],
            "assessments": [{"name": "Credential Sale", "criticality": "High"}],
            "details": details,
        },
        panel_triage={"rationale": "Initial access broker.", "assessment": {"name": "Likely Malicious", "criticality": "Moderate"}},
        panel_analysis_report={
            "title": "Analyst report",
            "source": {"entity_id": "src:1", "name": "Insikt Group"},
            "created": "2026-11-02T00:00:00Z",
            "content": "Report body",
        },
        panel_cached_content={
            "title": "Cached thread",
            "downloaded": "2026-11-03T00:00:00Z",
            "original_url": "http://forum.example.onion/t/1",
            "content": "Cached body <script>alert(1)</script>",
        },
    )
    alert["panel_status"].update({"assignee_name": "Aaron Soehnen", "alert_rule": {"name": "Dark web brand"}})
    return alert


FORUM_DETAILS = {
    "type": "dark_web_forum_mention",
    "source": {"entity_id": "s", "name": "XSS Forum"},
    "post_title": "Selling Acme Corp VPN access",
    "post": "DM for details",
    "post_date": "2026-11-01T00:00:00Z",
    "post_url": "https://forum.example.onion/t/1?p=2",
}


def test_dark_web_details(engine):
    assert PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING["dark_web"] == "Dark Web"
    html = render_details(engine, make_dark_web_alert(FORUM_DETAILS))
    assert_rendered(
        html,
        "Dark Web",
        "Acme Corp (brand)",
        "idn:acme.example (domain)",
        "rf-priority-level-High",
        "Credential Sale",
        "Aaron Soehnen",
        "Dark web brand",
        'href="https://app.recordedfuture.com/portal/playbook-alerts/task:test"',
        "rf-priority-level-Moderate",
        "Likely Malicious",
        "Initial access broker.",
        "Analyst report",
        "Insikt Group",
        "2026-11-02, 00:00",
        "hxxp://forum[.]example[.]onion/t/1",
        "2026-11-03, 00:00",
        "Cached body &lt;script&gt;",
    )
    assert "https://forum.example.onion" not in html
    assert "<script>" not in html


def mention_rows(html):
    """(label, value) pairs of the rendered mention rows."""
    rows = {}
    for label, value in re.findall(r'row-title">([^<]+)</div>\s*<div[^>]*>([^<]*)</div>', html):
        rows.setdefault(label, value.strip())
    return rows


@pytest.mark.parametrize(
    "details, heading, expected",
    [
        (
            FORUM_DETAILS,
            "Forum Details",
            {
                "Post Title": "Selling Acme Corp VPN access",
                "Source": "XSS Forum",
                "Post": "DM for details",
                "Post Date": "2026-11-01, 00:00",
                "Post URL": "hxxps://forum[.]example[.]onion/t/1?p=2",
            },
        ),
        (
            {
                "type": "telegram_mention",
                "telegram_channel_title": "Leaks channel",
                "source": {"entity_id": "s"},
                "post": "msg",
                "publish_date": "2026-11-01T00:00:00Z",
                "message_url": "https://t.me/leaks/1",
            },
            "Channel Details",
            {
                "Telegram Channel": "Leaks channel",
                "Source": "s",
                "Post": "msg",
                "Publish Date": "2026-11-01, 00:00",
                "Message URL": "hxxps://t[.]me/leaks/1",
            },
        ),
        (
            {
                "type": "ransomware_extortion_site",
                "ransomware_group": {"entity_id": "g", "name": "LockBit"},
                "source": {"entity_id": "s", "name": "LockBit blog"},
                "post_details": "Data posted",
                "post_date": "2026-11-01T00:00:00Z",
                "incident_url": "http://lock.onion/acme",
            },
            "Incident Details",
            {
                "Ransomware Group": "LockBit",
                "Source": "LockBit blog",
                "Post Details": "Data posted",
                "Post Date": "2026-11-01, 00:00",
                "Incident URL": "hxxp://lock[.]onion/acme",
            },
        ),
        (
            {
                "type": "dark_web_market_mention",
                "source": {"entity_id": "s", "name": "Market"},
                "listing_title": "Acme logins",
                "post_date": "2026-11-01T00:00:00Z",
                "market_url": "http://market.onion",
            },
            "Listing Details",
            {
                "Listing Title": "Acme logins",
                "Source": "Market",
                "Listing Content": "N/A",
                "Post Date": "2026-11-01, 00:00",
                "Market URL": "hxxp://market[.]onion",
                "Post URL": "N/A",
            },
        ),
    ],
)
def test_dark_web_mention_types(engine, details, heading, expected):
    html = render_details(engine, make_dark_web_alert(details))
    assert_rendered(html, heading)
    rows = mention_rows(html)
    for label, value in expected.items():
        assert rows[label] == value, label
    assert "{&#x27;entity_id&#x27;" not in html


def test_dark_web_rendering_twice_does_not_defang_twice(engine):
    alert = make_dark_web_alert(dict(FORUM_DETAILS))
    render_details(engine, alert)
    rows = mention_rows(render_details(engine, alert))
    assert rows["Post URL"] == "hxxps://forum[.]example[.]onion/t/1?p=2"


def test_dark_web_unsupported_mention_type(engine):
    html = render_details(engine, make_dark_web_alert({"type": "brand_new_mention"}))
    assert_rendered(html, "Mention Details", "Unsupported mention type: brand_new_mention")


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://t.me/chat/1", "hxxps://t[.]me/chat/1"),
        ("hxxps://t[.]me/chat/1", "hxxps://t[.]me/chat/1"),
        ("ftp://a.b/c.d", "ftp://a[.]b/c.d"),
        ("not a url.example", "not a url[.]example"),
        ("", ""),
        (None, ""),
    ],
)
def test_defang_url(url, expected):
    assert defang_url(url) == expected
