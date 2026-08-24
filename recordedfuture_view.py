# File: recordedfuture_view.py
#
# Copyright (c) Recorded Future, Inc, 2019-2026
#
# This unpublished material is proprietary to Recorded Future. All
# rights reserved. The methods and techniques described herein are
# considered trade secrets and/or confidential. Reproduction or
# distribution, in whole or in part, is forbidden except by express
# written permission of Recorded Future.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
from datetime import datetime

from recordedfuture_consts import RF_PLAYBOOK_STATUS_MAP


APP_URL = "https://app.recordedfuture.com/live/sc/entity/%s%%3A%s"
VULN_APP_URL = "https://app.recordedfuture.com/live/sc/entity/%s"

ENTITY_LIST_STATUS_VALUE_TO_LITERAL_MAPPING = {
    "ready": "Ready (no pending updates)",
    "pending": "Processing update",
    "processing": "Processing update",
    "added": "added",
    "unchanged": "is already in list",
    "not_in_list": "is not in list",
    "removed": "removed from list",
}

PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING = {
    "domain_abuse": "Domain Abuse",
    "cyber_vulnerability": "Vulnerability",
    "code_repo_leakage": "Code Repo Leakage",
    "malicious_sites": "Malicious Sites",
}

PLAYBOOK_ALERT_CATEGORY_MALICIOUS_SITES = "malicious_sites"

# Risk groups of the Malicious Sites "Domains Included" panel, in display order. The payload
# calls the middle priority "Moderate", which is also the term this app uses for priority
# everywhere else, so the heading follows the payload rather than the portal's "Medium".
MALICIOUS_SITES_RISK_GROUP_ORDER = ("High", "Moderate", "Informational")

# MaliciousSitesAttacker.priority is an unconstrained string in the API spec, unlike every
# other priority field, so an unrecognised value has to land somewhere.
MALICIOUS_SITES_RISK_GROUP_FALLBACK_LABEL = "Other Risk Domains"

MALICIOUS_SITES_CAUSE_LABEL_MAPPING = {
    "manual": "Added manually",
    "typosquat": "Typosquat",
    "similar_domains": "Similar domain",
    "logotype": "Logo detection",
    "logotype_high_interest": "High interest logo detection",
    "phishing_verdict": "Phishing verdict",
    "screenshot_mention": "Screenshot mention",
    "screenshot_custom_keyword": "Custom keyword in screenshot",
    "login_form": "Login form",
    "suggested_takedown": "Suggested takedown",
}

# DrpAsset is a union discriminated on "type". Only these subtypes carry readable text; the
# rest expose an opaque entity id, so the type name is shown instead of a brand name.
MALICIOUS_SITES_ASSET_VALUE_FIELDS = ("domain_id", "hostname")

MALICIOUS_SITES_ASSET_TYPE_LABEL_MAPPING = {
    "client_domain": "Monitored domain",
    "similar_domain_term": "Similar domain term",
    "screenshot_ocr_keyword": "Screenshot keyword",
    "code_repo_keyword": "Code repository keyword",
    "logotype": "Logotype",
    "image_hash": "Image hash",
    "company": "Company",
    "organization": "Organization",
    "product": "Product",
    "executive": "Executive",
}


def format_datetime_string(datetime_string):
    try:
        return datetime.strptime(datetime_string, "%Y-%m-%dT%H:%M:%S.%f%z").strftime("%Y-%m-%d, %H:%M")
    except ValueError:
        return datetime_string


def strip_entity_prefix(entity_identity):
    """Turn a Recorded Future entity identity such as "idn:evil.com" into "evil.com"."""
    if not isinstance(entity_identity, str):
        return entity_identity
    _, _, value = entity_identity.partition(":")
    return value or entity_identity


def malicious_sites_asset_label(asset):
    """Describe a matched asset of a Malicious Sites attacker.

    Only two DrpAsset subtypes carry readable text: a client domain, and the three
    term-carrying subtypes. Everything else holds an opaque entity id, so the asset type is
    shown rather than a meaningless identifier.
    """
    if not isinstance(asset, dict):
        return None

    for field in MALICIOUS_SITES_ASSET_VALUE_FIELDS:
        if asset.get(field):
            return strip_entity_prefix(asset[field])

    term = asset.get("term")
    if isinstance(term, dict) and term.get("text"):
        return term["text"]

    asset_type = asset.get("type")
    return MALICIOUS_SITES_ASSET_TYPE_LABEL_MAPPING.get(asset_type, asset_type)


def format_malicious_sites_attacker(attacker, apex_entity_id):
    """Build the display fields of one attacker domain row."""
    assets = [malicious_sites_asset_label(asset) for asset in attacker.get("assets") or []]
    cause = attacker.get("cause")

    attacker["domain"] = strip_entity_prefix(attacker.get("attacker"))
    attacker["is_apex"] = bool(apex_entity_id) and attacker.get("attacker") == apex_entity_id
    attacker["cause_label"] = MALICIOUS_SITES_CAUSE_LABEL_MAPPING.get(cause, cause.replace("_", " ").capitalize() if cause else None)
    attacker["matched_assets"] = sorted({asset for asset in assets if asset})
    attacker["created_at"] = format_datetime_string(attacker.get("created_at"))

    for verdict in attacker.get("phishing_verdicts") or []:
        severity = verdict.get("severity")
        verdict["severity_label"] = severity.replace("_", " ") if severity else None

    return attacker


def group_malicious_sites_attackers(data):
    """Group the attacker domains of a Malicious Sites alert into risk sections.

    Returns the sections in priority order, each with the rows that belong to it, so the
    template only has to iterate. Django templates cannot group, which is why this is done
    here. Priorities outside the known set land in a trailing fallback section rather than
    being dropped, because the API spec does not constrain the value.
    """
    panel_evidence_summary = data.get("panel_evidence_summary") or {}
    apex_entity_id = (data.get("panel_status") or {}).get("entity_id")

    grouped = {priority: [] for priority in MALICIOUS_SITES_RISK_GROUP_ORDER}
    fallback = []
    for attacker in panel_evidence_summary.get("attackers") or []:
        row = format_malicious_sites_attacker(attacker, apex_entity_id)
        grouped.get(attacker.get("priority"), fallback).append(row)

    groups = [
        {
            "label": f"{priority} Risk Domains",
            "count": len(grouped[priority]),
            "attackers": grouped[priority],
        }
        for priority in MALICIOUS_SITES_RISK_GROUP_ORDER
        if grouped[priority]
    ]
    if fallback:
        groups.append(
            {
                "label": MALICIOUS_SITES_RISK_GROUP_FALLBACK_LABEL,
                "count": len(fallback),
                "attackers": fallback,
            }
        )
    return groups


def format_malicious_sites_details(data):
    """Add the Malicious Sites view model to a playbook alert detail payload."""
    panel_status = data.get("panel_status") or {}
    panel_evidence_summary = data.get("panel_evidence_summary") or {}

    data["risk_groups"] = group_malicious_sites_attackers(data)
    data["domains_included_count"] = len(panel_status.get("attackers") or [])

    # The summary panel is the better source of assessments; fall back to the status panel.
    data["summary_assessments"] = panel_evidence_summary.get("assessments") or panel_status.get("assessments")

    data["matched_assets"] = sorted(
        {asset for group in data["risk_groups"] for attacker in group["attackers"] for asset in attacker["matched_assets"]}
    )

    # The BFI returns the base64 images index aligned with the screenshot records. Pair them
    # up here, because a Django template cannot index a list by a loop variable.
    images = data.get("images") or []
    screenshots = panel_evidence_summary.get("screenshots") or []
    for index, screenshot in enumerate(screenshots):
        screenshot["domain_label"] = strip_entity_prefix(screenshot.get("domain"))
        screenshot["created"] = format_datetime_string(screenshot.get("created"))
        screenshot["image"] = images[index] if index < len(images) else None

    return data


def format_playbook_alert_details_result(result):
    """Prepare one playbook alert detail action result for the detail widget.

    Shared by every category. The datetime fields are formatted defensively because a
    category may omit a panel entirely, and an exception here blanks the whole widget.
    """
    retval = {"param": result.get_param()}

    data = result.get_data()
    if data:
        data = data[0]
    else:
        retval["data"] = data
        return retval

    panel_status = data.get("panel_status") or {}
    for field in ("created", "updated"):
        if panel_status.get(field):
            panel_status[field] = format_datetime_string(panel_status[field])

    panel_evidence_whois = data.get("panel_evidence_whois", {})
    if panel_evidence_whois and not isinstance(panel_evidence_whois.get("body"), list):
        panel_evidence_whois["body"] = []

    if data.get("category") == PLAYBOOK_ALERT_CATEGORY_MALICIOUS_SITES:
        data = format_malicious_sites_details(data)

    retval["data"] = data
    return retval


def format_result(result, all_data=False):
    retval = {"param": result.get_param()}

    data = result.get_data()
    if data:
        retval["data"] = data[0]

    try:
        # assemble the string needed for an URL to Recorded Future portal
        if data and "risk" in retval["data"] and retval["data"]["risk"]["score"] is not None:
            if "domain" in retval["param"]:
                retval["intelCard"] = APP_URL % ("idn", retval["param"]["domain"])
            elif "ip" in retval["param"]:
                retval["intelCard"] = APP_URL % ("ip", retval["param"]["ip"])
            elif "hash" in retval["param"]:
                retval["intelCard"] = APP_URL % ("hash", retval["param"]["hash"])
            elif "url" in retval["param"]:
                retval["intelCard"] = APP_URL % ("url", retval["param"]["url"])
            elif "vulnerability" in retval["param"]:
                retval["intelCard"] = VULN_APP_URL % (retval["data"]["entity"]["id"])

            for rule in retval["data"]["risk"]["evidenceDetails"]:
                rule["timestampShort"] = rule["timestamp"][:10]

        # add cvss info only if present (should only be applicable by vulnerabilities)
        if data and "cvss" in retval["data"] and "published" in retval["data"]["cvss"]:
            retval["data"]["cvss"]["publishedShort"] = retval["data"]["cvss"]["published"][:10]
            retval["data"]["cvss"]["lastModifiedShort"] = retval["data"]["cvss"]["lastModified"][:10]

        # format date and time to be shorter and easier to read
        retval["data"]["timestamps"]["firstSeenShort"] = retval["data"]["timestamps"]["firstSeen"][:10]
        retval["data"]["timestamps"]["lastSeenShort"] = retval["data"]["timestamps"]["lastSeen"][:10]
    except Exception:
        retval["data"] = None

    # set summary, status and message for the action
    summary = result.get_summary()
    if summary:
        retval["summary"] = summary

    status = result.get_status()
    if status:
        retval["status"] = "Success"
    else:
        retval["status"] = "Failure"

    message = result.get_message()
    if message:
        retval["message"] = message

    return retval


def format_reputation_result(result, all_data=False):
    retval = {"param": result.get_param()}

    data = result.get_data()
    if data:
        retval["data"] = data[0]

    if data and retval["data"]["riskscore"] is not None:
        if "domain" in retval["param"]:
            retval["intelCard"] = APP_URL % ("idn", retval["param"]["domain"])
        elif "ip" in retval["param"]:
            retval["intelCard"] = APP_URL % ("ip", retval["param"]["ip"])
        elif "hash" in retval["param"]:
            retval["intelCard"] = APP_URL % ("hash", retval["param"]["hash"])
        elif "url" in retval["param"]:
            retval["intelCard"] = APP_URL % ("url", retval["param"]["url"])
        elif "vulnerability" in retval["param"]:
            retval["intelCard"] = VULN_APP_URL % (retval["data"]["id"])

    summary = result.get_summary()
    if summary:
        retval["summary"] = summary

    status = result.get_status()
    if status:
        retval["status"] = "Success"
    else:
        retval["status"] = "Failure"

    message = result.get_message()
    if message:
        retval["message"] = message

    return retval


def format_contexts_result(result, all_data=False):
    retval = {"param": result.get_param()}

    data = result.get_data()
    if data:
        retval["data"] = data

    summary = result.get_summary()
    if summary:
        retval["summary"] = summary

    status = result.get_status()
    if status:
        retval["status"] = "Success"
    else:
        retval["status"] = "Failure"

    message = result.get_message()
    if message:
        retval["message"] = message

    return retval


def intelligence_results(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = format_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return "views/intelligence_results.html"


def reputation_results(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = format_reputation_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return "views/reputation_results.html"


def contexts_results(provides, all_app_runs, context):
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = format_contexts_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return "views/contexts_results.html"


def format_alert_result(result):
    return format_result(result)


def alert_lookup_results(provides, all_app_runs, context):
    """Setup the view for an alert."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = {"param": result.get_param(), "data": result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return "views/alert_lookup_results.html"


def alert_update_results(provides, all_app_runs, context):
    """Setup the view for an alert."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = {"param": result.get_param(), "data": result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return "views/alert_update_results.html"


def alert_search_results(provides, all_app_runs, context):
    """Setup the view for alert results."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = {"param": result.get_param(), "data": result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return "views/alert_search_results.html"


def alert_rule_search_results(provides, all_app_runs, context):
    """Render the list of Alert Rules that match the search."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = {"param": result.get_param(), "data": result.get_data()}
            if not formatted:
                continue
            results.append(formatted)

    return "views/alert_rule_search_results.html"


def format_threat_assessment_result(result, all_data=False):
    retval = {"param": result.get_param()}

    data = result.get_data()
    if data:
        ret_data = {key: data[0][key] for key in data[0].keys() if key != "entities"}

        entities = data[0]["entities"]
        entities.sort(key=lambda x: int(x.get("riskscore", "0")))
        ret_data["entities"] = [entity for entity in entities if entity["riskscore"]]
        retval["data"] = ret_data
    else:
        retval["data"] = "NO DATA"

    summary = result.get_summary()
    if summary:
        retval["summary"] = summary

    status = result.get_status()
    if status:
        retval["status"] = "Success"
    else:
        retval["status"] = "Failure"

    message = result.get_message()
    if message:
        retval["message"] = message

    return retval


def threat_assessment_results(provides, all_app_runs, context):
    """Setup the view for Threat Assessment results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = format_threat_assessment_result(result)
            if not formatted:
                continue
            results.append(formatted)

    return "views/threat_assessment_results.html"


def list_search_results(provides, all_app_runs, context):
    """Setup the view for list search results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                # When searching by list_id the API returns a single list object
                # (GET /list/{id}/info); a name/type search returns an array
                # (POST /list/search). Normalize the single object into a list so
                # the template can iterate over it uniformly.
                if isinstance(result_data, dict):
                    result_data = [result_data]
            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_search_results.html"


def list_create_results(provides, all_app_runs, context):
    """Setup the view for list create result"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_create_results.html"


def list_details_results(provides, all_app_runs, context):
    """Setup the view for list details result"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                result_data["created"] = format_datetime_string(result_data["created"])
                result_data["updated"] = format_datetime_string(result_data["updated"])

            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_details_results.html"


def list_status_results(provides, all_app_runs, context):
    """Setup the view for list status info"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                result_data["status"] = ENTITY_LIST_STATUS_VALUE_TO_LITERAL_MAPPING.get(result_data["status"])
            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_status_results.html"


def list_entities_results(provides, all_app_runs, context):
    """Setup the view for list status info"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                for entity in result_data:
                    entity["added"] = format_datetime_string(entity["added"])
                    entity["status"] = ENTITY_LIST_STATUS_VALUE_TO_LITERAL_MAPPING.get(entity["status"])
            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_entities_results.html"


def list_entities_management_results(provides, all_app_runs, context):
    """Setup the view for list status info"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                result_data["result"] = ENTITY_LIST_STATUS_VALUE_TO_LITERAL_MAPPING.get(result_data["result"])
            results.append({"param": result.get_param(), "data": result_data})

    return "views/list_entities_management_results.html"


def playbook_alert_search_results(provides, all_app_runs, context):
    """Setup the view for Playbook alerts search result"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                for search_result in result_data:
                    search_result["created"] = format_datetime_string(search_result["created"])
                    search_result["updated"] = format_datetime_string(search_result["updated"])
                    search_result["status"] = RF_PLAYBOOK_STATUS_MAP.get(search_result["status"], search_result["status"])
                    search_result["category_display"] = PLAYBOOK_ALERT_CATEGORY_DISPLAY_MAPPING.get(
                        search_result["category"], search_result["category"]
                    )

            results.append({"param": result.get_param(), "data": result_data})

    return "views/playbook_alert_search_results.html"


def playbook_alert_update_results(provides, all_app_runs, context):
    """Setup the view for Playbook alert update"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
            results.append({"param": result.get_param(), "data": result_data})

    return "views/playbook_alert_update_results.html"


def playbook_alert_details_results(provides, all_app_runs, context):
    """Setup the view for Playbook alert details"""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            results.append(format_playbook_alert_details_result(result))

    return "views/playbook_alert_details_results.html"


def entity_search_results(provides, all_app_runs, context):
    """Setup the view for entity search results."""

    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
            results.append({"param": result.get_param(), "data": result_data})

    return "views/entity_search_results.html"


def links_search_results(provides, all_app_runs, context):
    """Setup the view for links search results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
            results.append({"param": result.get_param(), "data": result_data})
    return "views/links_search_results.html"


def detection_rule_search_results(provides, all_app_runs, context):
    """Setup the view for detection rule search results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
            results.append({"param": result.get_param(), "data": result_data})
    return "views/detection_rule_search_results.html"


def threat_actor_intelligence_results(provides, all_app_runs, context):
    """Setup the view for threat actor intelligence results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                result_data["categories"] = [category.get("name") for category in result_data.get("categories", [])]
            results.append({"param": result.get_param(), "data": result_data})
    return "views/threat_actor_intelligence_results.html"


def threat_map_results(provides, all_app_runs, context):
    """Setup the view for threat map results."""
    context["results"] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()
            if result_data:
                result_data = result_data[0]
                for actor in result_data.get("threatActor", []):
                    actor["categories"] = [category.get("name") for category in actor.get("categories", [])]
            results.append({"param": result.get_param(), "data": result_data})
    return "views/threat_map_results.html"


def identity_leaked_credentials_results(provides, all_app_runs, context):
    """Setup the view for leaked credentials results."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            result_data = result.get_data()

            if not result_data:
                continue

            response_obj = result_data[0]
            detections = response_obj.get("detections", [])

            formatted_detections = []
            for detection in detections:
                detection_entry = {
                    "id": detection.get("id"),
                    "organization_id": detection.get("organization_id"),
                    "novel": detection.get("novel"),
                    "type": detection.get("type"),
                    "subject": detection.get("subject"),
                    "authorization_service": detection.get("authorization_service") or {},
                    "malware_family": detection.get("malware_family") or {},
                    "dump": detection.get("dump") or {},
                    "created": detection.get("created"),
                }
                formatted_detections.append(detection_entry)

            results.append(
                {
                    "param": result.get_param(),
                    "detections": formatted_detections,
                    "summary": result.get_summary(),
                }
            )

    return "views/identity_leaked_credentials_results.html"


def collective_insights_submission_results(provides, all_app_runs, context):
    """Setup the view for collective insights submission."""
    return "views/collective_insights_submission_results.html"


def fetch_analyst_notes_results(provides, all_app_runs, context):
    """Setup the view for displaying fetched analyst notes."""
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            formatted = {
                "param": result.get_param(),
                "data": result.get_data(),
                "summary": result.get_summary(),
            }
            if not formatted.get("data"):
                continue
            results.append(formatted)

    return "views/fetch_analyst_notes_results.html"
