# Copyright (c) 2025-2026 Splunk Inc.
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
"""Tests for the playbook alert detail view model.

The Malicious Sites branch is the only one that computes a view model in Python rather than
in the template, because Django templates cannot group a list.
"""

import copy

import pytest

from recordedfuture_view import (
    MALICIOUS_SITES_RISK_GROUP_FALLBACK_LABEL,
    PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING,
    format_playbook_alert_details_result,
    group_malicious_sites_attackers,
    malicious_sites_asset_label,
    strip_entity_prefix,
)


APEX = "idn:apex.example.com"
SUBDOMAIN = "idn:sub.apex.example.com"


class FakeActionResult:
    """Stands in for a SOAR ActionResult, which only the platform can construct."""

    def __init__(self, data, param=None):
        self._data = data
        self._param = param or {}

    def get_data(self):
        return self._data

    def get_param(self):
        return self._param


def malicious_sites_payload():
    return {
        "category": "malicious_sites",
        "playbook_alert_id": "task:test",
        "images": ["<base64>"],
        "panel_status": {
            "status": "New",
            "priority": "High",
            "created": "2026-07-21T16:21:59.820000+00:00",
            "updated": "2026-07-21T16:21:59.820000+00:00",
            "entity_id": APEX,
            "entity_name": "apex.example.com",
            "alert_rule": {"name": "Malicious Sites"},
            "attackers": [APEX, SUBDOMAIN],
            "assessments": [{"name": "Login Form", "priority": "Moderate"}],
            "targets": [],
        },
        "panel_evidence_summary": {
            "explanation": "Alert was created as a result of a logotype detection",
            "assessments": [{"name": "Suggested Takedown", "priority": "High"}],
            "attackers": [
                {
                    "attacker": SUBDOMAIN,
                    "priority": "Moderate",
                    "cause": "logotype_high_interest",
                    "created_at": "2026-07-21T16:21:45.831000+00:00",
                    "assets": [{"type": "company", "company_id": "FNESDXtz6VK"}],
                    "assessments": [{"name": "Logo Detection", "priority": "Informational"}],
                },
                {
                    "attacker": APEX,
                    "priority": "High",
                    "cause": "logotype",
                    "created_at": "2026-07-21T16:21:46.236000+00:00",
                    "assets": [{"type": "client_domain", "domain_id": "idn:volvo.com"}],
                    "assessments": [{"name": "Suggested Takedown", "priority": "High"}],
                    "phishing_verdicts": [{"url": "url:http://apex.example.com/", "severity": "very_malicious"}],
                },
            ],
            "screenshots": [
                {
                    "image_id": "img:one",
                    "domain": APEX,
                    "created": "2026-07-21T16:21:38.809000+00:00",
                    "tag": "Login Form",
                    "availability": "Available",
                }
            ],
        },
        "panel_evidence_dns": {"ip_list": [], "mx_list": [], "ns_list": []},
        "panel_evidence_whois": {"body": []},
        "panel_log": [],
        "panel_log_v2": [],
    }


def format_payload(payload):
    return format_playbook_alert_details_result(FakeActionResult([copy.deepcopy(payload)]))["data"]


class TestCategoryDisplayMapping:
    def test_malicious_sites_has_a_display_label(self):
        assert PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING["malicious_sites"] == "Malicious Sites"


class TestStripEntityPrefix:
    @pytest.mark.parametrize(
        "identity,expected",
        [
            ("idn:evil.com", "evil.com"),
            ("url:http://evil.com/", "http://evil.com/"),
            ("no-prefix", "no-prefix"),
            (None, None),
        ],
    )
    def test_strips_the_type_prefix(self, identity, expected):
        assert strip_entity_prefix(identity) == expected


class TestMaliciousSitesAssetLabel:
    def test_client_domain_shows_the_domain(self):
        asset = {"type": "client_domain", "domain_id": "idn:volvo.com"}
        assert malicious_sites_asset_label(asset) == "volvo.com"

    def test_term_carrying_asset_shows_the_term(self):
        asset = {"type": "similar_domain_term", "term": {"text": "volvo"}}
        assert malicious_sites_asset_label(asset) == "volvo"

    def test_opaque_asset_falls_back_to_its_type_label(self):
        """A company id is not a brand name, so show what kind of asset matched instead."""
        asset = {"type": "company", "company_id": "FNESDXtz6VK"}
        assert malicious_sites_asset_label(asset) == "Company"

    def test_unknown_asset_type_is_shown_verbatim(self):
        assert malicious_sites_asset_label({"type": "brand_new_type"}) == "brand_new_type"


class TestMaliciousSitesRiskGrouping:
    def test_groups_are_ordered_by_descending_risk(self):
        groups = group_malicious_sites_attackers(malicious_sites_payload())
        assert [group["label"] for group in groups] == [
            "High Risk Domains",
            "Moderate Risk Domains",
        ]

    def test_mid_group_is_labelled_moderate_not_medium(self):
        groups = group_malicious_sites_attackers(malicious_sites_payload())
        labels = [group["label"] for group in groups]
        assert "Moderate Risk Domains" in labels
        assert "Medium Risk Domains" not in labels

    def test_group_counts(self):
        groups = group_malicious_sites_attackers(malicious_sites_payload())
        assert [group["count"] for group in groups] == [1, 1]

    def test_apex_is_flagged_and_others_are_not(self):
        groups = group_malicious_sites_attackers(malicious_sites_payload())
        by_domain = {attacker["attacker"]: attacker for group in groups for attacker in group["attackers"]}
        assert by_domain[APEX]["is_apex"] is True
        assert by_domain[SUBDOMAIN]["is_apex"] is False

    def test_empty_groups_are_omitted(self):
        groups = group_malicious_sites_attackers(malicious_sites_payload())
        assert all(group["count"] for group in groups)
        assert "Informational Risk Domains" not in [group["label"] for group in groups]

    def test_unknown_priority_lands_in_the_fallback_group(self):
        """MaliciousSitesAttacker.priority is an unconstrained string in the API spec."""
        payload = malicious_sites_payload()
        payload["panel_evidence_summary"]["attackers"][0]["priority"] = "Severe"
        groups = group_malicious_sites_attackers(payload)
        assert groups[-1]["label"] == MALICIOUS_SITES_RISK_GROUP_FALLBACK_LABEL
        assert groups[-1]["attackers"][0]["attacker"] == SUBDOMAIN

    def test_no_attacker_is_dropped(self):
        payload = malicious_sites_payload()
        payload["panel_evidence_summary"]["attackers"][0]["priority"] = "Severe"
        groups = group_malicious_sites_attackers(payload)
        assert sum(group["count"] for group in groups) == 2

    def test_cause_is_given_a_human_label(self):
        groups = group_malicious_sites_attackers(malicious_sites_payload())
        by_domain = {attacker["attacker"]: attacker for group in groups for attacker in group["attackers"]}
        assert by_domain[APEX]["cause_label"] == "Logo detection"
        assert by_domain[SUBDOMAIN]["cause_label"] == "High interest logo detection"

    def test_unknown_cause_falls_back_to_readable_text(self):
        payload = malicious_sites_payload()
        payload["panel_evidence_summary"]["attackers"][0]["cause"] = "brand_new_cause"
        groups = group_malicious_sites_attackers(payload)
        causes = [attacker["cause_label"] for group in groups for attacker in group["attackers"]]
        assert "Brand new cause" in causes

    def test_absent_summary_panel_yields_no_groups(self):
        assert group_malicious_sites_attackers({"panel_status": {}}) == []

    def test_absent_attackers_yields_no_groups(self):
        assert group_malicious_sites_attackers({"panel_evidence_summary": {}}) == []


class TestFormatMaliciousSitesDetails:
    def test_domains_included_count_comes_from_panel_status(self):
        assert format_payload(malicious_sites_payload())["domains_included_count"] == 2

    def test_summary_assessments_prefer_the_summary_panel(self):
        data = format_payload(malicious_sites_payload())
        assert data["summary_assessments"] == [{"name": "Suggested Takedown", "priority": "High"}]

    def test_summary_assessments_fall_back_to_the_status_panel(self):
        payload = malicious_sites_payload()
        payload["panel_evidence_summary"]["assessments"] = []
        data = format_payload(payload)
        assert data["summary_assessments"] == [{"name": "Login Form", "priority": "Moderate"}]

    def test_matched_assets_are_collected_and_deduplicated(self):
        data = format_payload(malicious_sites_payload())
        assert data["matched_assets"] == ["Company", "volvo.com"]

    def test_phishing_verdict_severity_is_readable(self):
        data = format_payload(malicious_sites_payload())
        apex = next(attacker for group in data["risk_groups"] for attacker in group["attackers"] if attacker["is_apex"])
        assert apex["phishing_verdicts"][0]["severity_label"] == "very malicious"

    def test_screenshots_are_labelled_with_their_domain(self):
        data = format_payload(malicious_sites_payload())
        screenshot = data["panel_evidence_summary"]["screenshots"][0]
        assert screenshot["domain_label"] == "apex.example.com"

    def test_screenshot_count_matches_the_image_count(self):
        data = format_payload(malicious_sites_payload())
        assert len(data["panel_evidence_summary"]["screenshots"]) == len(data["images"])

    def test_panel_status_timestamps_are_formatted(self):
        data = format_payload(malicious_sites_payload())
        assert data["panel_status"]["created"] == "2026-07-21, 16:21"


class TestFormatPlaybookAlertDetailsResultIsCategoryAgnostic:
    def test_no_data_returns_early(self):
        assert format_playbook_alert_details_result(FakeActionResult([]))["data"] == []

    def test_a_missing_panel_status_does_not_raise(self):
        """An exception in the formatter blanks the entire widget, so it must not raise."""
        result = format_playbook_alert_details_result(FakeActionResult([{"category": "domain_abuse", "playbook_alert_id": "task:x"}]))
        assert result["data"]["playbook_alert_id"] == "task:x"

    def test_a_panel_status_without_timestamps_does_not_raise(self):
        result = format_playbook_alert_details_result(FakeActionResult([{"category": "domain_abuse", "panel_status": {"status": "New"}}]))
        assert result["data"]["panel_status"]["status"] == "New"

    def test_non_list_whois_body_is_normalised(self):
        result = format_playbook_alert_details_result(
            FakeActionResult(
                [
                    {
                        "category": "domain_abuse",
                        "panel_status": {},
                        "panel_evidence_whois": {"body": "not a list"},
                    }
                ]
            )
        )
        assert result["data"]["panel_evidence_whois"]["body"] == []

    def test_other_categories_get_no_malicious_sites_view_model(self):
        result = format_playbook_alert_details_result(FakeActionResult([{"category": "domain_abuse", "panel_status": {}}]))
        assert "risk_groups" not in result["data"]

    def test_each_screenshot_is_paired_with_its_image(self):
        data = format_payload(malicious_sites_payload())
        screenshot = data["panel_evidence_summary"]["screenshots"][0]
        assert screenshot["image"] == "<base64>"

    def test_a_screenshot_without_a_matching_image_is_not_rendered(self):
        """Guards the index alignment between `images` and the screenshot records."""
        payload = malicious_sites_payload()
        payload["images"] = []
        data = format_payload(payload)
        assert data["panel_evidence_summary"]["screenshots"][0]["image"] is None
