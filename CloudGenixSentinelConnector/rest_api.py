import requests
from requests.adapters import HTTPAdapter, Retry
from dateutil import parser
import logging

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
    "DEVICESW_CRITICAL_PROCESSRESTART": "A critical software process on the device has restarted either due to an error or as a self-recovery method. Process restart as a self-recovery does not impact long-term functions on the device but can cause short term sub-optimal data plane functions and errors."
}


def login(email, password, server_url):
    login_url = server_url + "/v2.0/api/login"
    body = {
        "email": email,
        "password": password
    }
    try:
        result = requests.post(url=login_url, data=body)
        hood_login_url = result.json()["api_endpoint"] + "/v2.0/api/login"
        result = requests.post(url=hood_login_url, data=body)
        token = result.json()["x_auth_token"]
        logging.info("second login: {}".format(result))
        return token
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))


def get_profile(headers):
    profile_url = "https://api.hood.cloudgenix.com/v2.0/api/profile"
    result = {}
    try:
        result = requests.get(url=profile_url, headers=headers).json()
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    return result


def get_events(headers, profile, start_time, end_time):
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
    events_url = "https://api.hood.cloudgenix.com/v3.0/api/tenants/" + profile["tenant_id"] + "/events/query"
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
            start_time = parser.parse(events.json()["_offset"], fuzzy=True).strftime("%d-%m-%yT%H:%M:%SZ")
            body = {
                "severity": ["critical", "major", "minor"],
                "query": {"type": ["alarm", "alert"]},
                "_offset": None,
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
                events_data.append(events.json()["items"])
    return events_data


def transform_events(events, elements, sites, appdefs):
    for event in events:
        event["event_id"] = event.pop("id")
        if event["code"] in descriptions:
            event["description"] = descriptions[event["code"]]
        if event["site_id"]:
            event["site"] = next(item for item in sites if item["id"] == event["site_id"])["name"]
        if event["element_id"]:
            event["element"] = next(item for item in elements if item["id"] == event["element_id"])["name"]
        if event["entity_ref"].find('appdefs') != -1:
            event["application"] = next(item for item in appdefs if item["id"] == event["entity_ref"].split("/")[3])[
                "display_name"]
        event.pop("entity_ref")
        event.pop("site_id")
        event.pop("element_id")
    return events


def get_elements(headers, profile):
    elements_url = "https://api.hood.cloudgenix.com/v2.0/api/tenants/" + profile["tenant_id"] + "/elements"
    result = []
    try:
        result = requests.get(url=elements_url, headers=headers).json()["items"]
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    return result


def get_sites(headers, profile):
    sites_url = "https://api.hood.cloudgenix.com/v4.1/api/tenants/" + profile["tenant_id"] + "/sites"
    result = []
    try:
        result = requests.get(url=sites_url, headers=headers).json()["items"]
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    return result


def get_appdefs(headers, profile):
    appdefs_url = "https://api.hood.cloudgenix.com/v2.0/api/tenants/" + profile["tenant_id"] + "/appdefs"
    result = []
    try:
        result = requests.get(url=appdefs_url, headers=headers).json()["items"]
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))
    return result
