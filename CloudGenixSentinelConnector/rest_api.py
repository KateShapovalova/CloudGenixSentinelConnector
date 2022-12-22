import requests
from requests.adapters import HTTPAdapter, Retry
import logging
from datetime import datetime, timezone
import re

descriptions = {
    "DEVICESW_FLOWS_DISCONNECTED_FROM_CONTROLLER": "Device flows connection has remained disconnected from the Controller for a prolonged duration.",
    "DEVICESW_ANALYTICS_DISCONNECTED_FROM_CONTROLLER": "Device analytics connection has remained disconnected from the Controller for a prolonged duration.",
    "DEVICESW_DISCONNECTED_FROM_CONTROLLER": "Device has remained disconnected from the Controller for a prolonged duration.",
    "DEVICEHW_POWER_LOST": "Power Supply Unit (PSU) on a device is indicating fault. Power to that PSU may be interrupted or the PSU may have failed.",
    "DEVICEHW_DISKUTIL_PARTITIONSPACE": "Disk Storage Utilization on a device has reached 85% of capacity. Non-critical functions including logging and statistics export might be impacted.",
    "DEVICEHW_INTERFACE_DOWN": "A configured admin-up interface is either not receiving a signal or has an error that is causing lack of data flow through that interface.",
    "DEVICEIF_ADDRESS_DUPLICATE": "Another device in the local network is using an IPv4 address assigned to this device.",
    "DEVICESW_GENERAL_PROCESSRESTART": "A software process on the device has restarted either due to an error or as a self-recovery method. Process restart as a self-recovery does not impact long-term functions on the device but can cause short term sub-optimal functions and errors.",
    "DEVICESW_SYSTEM_BOOT": "Device rebooted either due to recovery on a fault condition or as part of normal operational procedures including user initiated reboots and software upgrades. Reboots due to fault conditions can cause sub-optimal or significantly reduced functionality on the device.",
    "DEVICESW_NTP_NO_SYNC": "Unable to sync up with all configured NTP servers for more than 24 hours.",
    "DEVICEHW_INTERFACE_ERRORS": "Number of transmission and/or reception errors seen on an interface over the last one hour period has exceeded the threshold (0.5% of received or transmitted packet counts in the same one hour period).",
    "DEVICESW_SNMP_AGENT_RESTART": "SNMP agent on device has restarted and recovered from an error.",
    "DEVICESW_IPFIX_COLLECTORS_DOWN": "The software process responsible to export IPFIX records has observed that there are no active connections to the IPFIX collectors. The process will continue to monitor the connection status and resume exporting of the IPFIX records once the connections are re-established.",
    "NETWORK_DIRECTPRIVATE_DOWN": "For remote office (branch) sites, all data center sites with ion 7000x deployed have been declared unreachable on Private WAN. If there are no alternate paths in the application policy, the fault is traffic impacting and should be attended to immediately.",
    "NETWORK_DIRECTINTERNET_DOWN": "For remote office (branch) sites, reachability on an Internet circuit has been declared to be down. If there are no alternate paths in the application policy, the fault is traffic impacting and should be attended to immediately.",
    "NETWORK_POLICY_RULE_CONFLICT": "Two or more policy rules in a network policy set conflict, potentially resulting in incorrect policy being applied to some flows.",
    "SITE_CONNECTIVITY_DEGRADED": "Multiple issues are present impacting site WAN connectivity.",
    "SITE_CONNECTIVITY_DOWN": "All site WAN connectivity is down.",
    "SITE_CIRCUIT_ABSENT_FOR_POLICY": "Site is missing all circuit definitions specified in the Policy Set assigned to the site. Applications at the site will be affected since there are no circuits to forward the traffic.",
    "APPLICATION_PROBE_DISABLED": "Application probes are disabled either due to incomplete configuration or invalid state. Element will no longer issue application probe to detect application reachability unless the issue is resolved. Consequently, if application probes are disabled then application will no longer switch to alternative paths in case it fails on its current path.",
    "APPLICATION_CUSTOM_RULE_CONFLICT": "An application rule conflict has been detected.",
    "NAT_POLICY_STATIC_NATPOOL_OVERRUN": "Configured Nat pool range cannot map 1:1 with matching traffic selector prefix.",
    "NETWORK_SECUREFABRICLINK_DEGRADED": "Secure Fabric Link is degraded with atleast 1 VPNlink UP from the active spoke and 1 or more VPNlinks DOWN from the active spoke.",
    "DEVICESW_SYSLOGSERVERS_DOWN": "A Syslog Export daemon failed to connect with remote syslog server.",
    "DEVICEHW_ION9000X722FW_OUTOFDATE": "A very important firmware update is required for stable operation of ports 9 through 12 on this device.",
    "SPOKEHA_STATE_UPDATE": "Device changed its state from active to backup or backup to active. If the device changed its state to backup, and there is no other device eligible to become active, then network connectivity at the site will be affected.",
    "DEVICESW_CRITICAL_PROCESSRESTART": "A critical software process on the device has restarted either due to an error or as a self-recovery method. Process restart as a self-recovery does not impact long-term functions on the device but can cause short term sub-optimal data plane functions and errors.",
    "NETWORK_ANYNETLINK_DEGRADED": "Link is degraded with at least 1 VPNlink UP from the active spoke and 1 or more VPNlinks DOWN from the active spoke.",
    "NETWORK_ANYNETLINK_DOWN": "Link is down with all VPNLinks DOWN from the active spoke.",
    "SPOKEHA_CLUSTER_DEGRADED": "One of the element in the SpokeCluster has effective priority 0.",
    "SPOKEHA_MULTIPLE_ACTIVE_DEVICES": "A critical alarm will be raised on the spoke HA cluster resource by the controller when both elements declare themselves to be 'active' (split brain).",
    "PEERING_BGP_DOWN": "Routing peer session is down. If alternate paths are available traffic is not affected; else the fault is critical."
}


def login(email, password, server_url):
    login_url = server_url + "/v2.0/api/login"
    body = {
        "email": email,
        "password": password
    }
    try:
        result = requests.post(url=login_url, data=body)
        hood_url = result.json()["api_endpoint"]
        hood_login_url = hood_url + "/v2.0/api/login"
        result = requests.post(url=hood_login_url, data=body)
        token = result.json()["x_auth_token"]
        return token, hood_url
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
        raise err


def get_profile(headers, hood_url):
    profile_url = hood_url + "/v2.0/api/profile"
    result = {}
    try:
        result = requests.get(url=profile_url, headers=headers).json()
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    return result


def auditlog_query(headers, hood_url, start_time, end_time, profile, operators, api_version="v2.0", limit=200):
    start_time_timestamp = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    end_time_timestamp = datetime.strptime(end_time, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    audit_logs = []

    result = {}
    url = hood_url + "/" + api_version + "/api/tenants/" + profile["tenant_id"] + "/auditlog/query"

    body = {
        "query_params": {
            "and": {
                "response_ts": {
                    "gte": start_time_timestamp * 1000,
                    "lte": end_time_timestamp * 1000}
            }
        },
        "sort_params": {
            "response_ts": "asc"
        },
        "limit": limit
    }

    try:
        result = requests.post(url=url, headers=headers, json=body)
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    if 200 <= result.status_code <= 299:
        audit_logs = result.json()["items"]
        while result.json()["total_count"] != 0:
            start_time = int(str(result.json()["items"][-1]["_created_on_utc"])[:10])
            body = {
                "query_params": {
                    "and": {
                        "response_ts": {
                            "gte": start_time,
                            "lte": end_time_timestamp}
                    }
                },
                "sort_params": {
                    "response_ts": "asc"
                },
                "limit": limit
            }
            try:
                result = requests.post(url=url, headers=headers, json=body)
            except Exception as err:
                logging.error("Something wrong. Exception error text: {}".format(err))
            if 200 <= result.status_code <= 299:
                audit_logs.extend(result.json()["items"])
    for audit_log in audit_logs:
        operator = [x for x in operators["items"] if x["id"] == audit_log["operator_id"]]
        if len(operator) != 1:
            audit_log["operator_name"] = "N/A"
        else:
            audit_log["operator_name"] = operator[0]["name"]
        audit_log["_created_on_utc"] = datetime.utcfromtimestamp(int(str(audit_log["_created_on_utc"])[:10]))\
            .strftime('%Y-%m-%dT%H:%M:%SZ')
        audit_log["_updated_on_utc"] = datetime.utcfromtimestamp(int(str(audit_log["_updated_on_utc"])[:10]))\
            .strftime('%Y-%m-%dT%H:%M:%SZ')
        if audit_log["request_body"].find("password=") != -1:
            request_body = audit_log["request_body"].split("&")
            audit_log["request_body"] = "&".join([request_body[0], request_body[1].replace(request_body[1],
                                                                                           "password=*****")])
    return audit_logs


def get_operators(headers, hood_url, profile):
    operators_url = hood_url + "/v2.1/api/tenants/" + profile["tenant_id"] + "/operators"
    operators = {}
    try:
        operators = requests.get(url=operators_url, headers=headers).json()
        for operator in operators["items"]:
            if "last_name" in operator:
                operator["name"] = " ".join([operator["first_name"], operator["last_name"]])
            else:
                operator["name"] = operator["first_name"]
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    return operators


def get_events(headers, profile, start_time, end_time, hood_url):
    events_data = []
    events = {}
    body = {
        "severity": ["critical", "major", "minor"],
        "query": {"type": ["alarm", "alert"]},
        "_offset": None,
        "view": {
            "summary": False
        },
        "start_time": start_time,
        "end_time": end_time
    }
    events_url = hood_url + "/v3.0/api/tenants/" + profile["tenant_id"] + "/events/query"
    s = requests.Session()
    retries = Retry(total=5,
                    backoff_factor=0.4,
                    status_forcelist=[500, 502, 503, 504])
    s.mount('https://', HTTPAdapter(max_retries=retries))
    try:
        events = s.post(url=events_url, headers=headers, json=body)
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    if 200 <= events.status_code <= 299:
        events_data = events.json()["items"]
        while events.json()["_offset"] is not None:
            body = {
                "severity": ["critical", "major", "minor"],
                "query": {"type": ["alarm", "alert"]},
                "_offset": events.json()["_offset"],
                "view": {
                    "summary": False
                },
                "start_time": start_time
            }
            try:
                events = s.post(url=events_url, headers=headers, json=body)
            except Exception as err:
                logging.error("Something wrong. Exception error text: {}".format(err))
            if 200 <= events.status_code <= 299:
                events_data.extend(events.json()["items"])
    return events_data


def transform_events(events, elements, sites, appdefs):
    for event in events:
        event["event_id"] = event["id"]
        if event["code"] in descriptions:
            event["description"] = descriptions[event["code"]]
        if event["site_id"]:
            event["site"] = next(item for item in sites if item["id"] == event["site_id"])["name"]
        if event["element_id"]:
            event["element"] = next(item for item in elements if item["id"] == event["element_id"])["name"]
        if event["entity_ref"].find('appdefs') != -1:
            event["application"] = next(item for item in appdefs if item["id"] == event["entity_ref"].split("/")[3])[
                "display_name"]
        event.pop("id")
        event.pop("entity_ref")
        event.pop("site_id")
        event.pop("element_id")
    return events


def get_elements(headers, profile, hood_url):
    elements_url = hood_url + "/v2.0/api/tenants/" + profile["tenant_id"] + "/elements"
    result = []
    try:
        result = requests.get(url=elements_url, headers=headers).json()["items"]
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    return result


def get_sites(headers, profile, hood_url):
    sites_url = hood_url + "/v4.1/api/tenants/" + profile["tenant_id"] + "/sites"
    result = []
    try:
        result = requests.get(url=sites_url, headers=headers).json()["items"]
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    return result


def get_appdefs(headers, profile, hood_url):
    appdefs_url = hood_url + "/v2.0/api/tenants/" + profile["tenant_id"] + "/appdefs"
    result = []
    try:
        result = requests.get(url=appdefs_url, headers=headers).json()["items"]
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    return result
