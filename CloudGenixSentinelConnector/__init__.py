import requests
import datetime
import hashlib
import hmac
import base64
import logging
from rest_api import login, get_profile, get_elements, get_sites, get_events, get_appdefs, transform_events
import os
from datetime import datetime, timedelta
import json
from .state_manager import StateManager
import re
import azure.functions as func

dispatcher = os.environ['CloudGenixServerURL']
email = os.environ['CloudGenixEmail']
password = os.environ['CloudGenixPassword']
customer_id = os.environ['WorkspaceID']
shared_key = os.environ['WorkspaceKey']
log_type = "CloudGenix"
connection_string = os.environ['AzureWebJobsStorage']
chunksize = 2000
logAnalyticsUri = os.environ.get('logAnalyticsUri')

if dispatcher == "":
    raise Exception("CloudGenixServerURL is missing")

if ((logAnalyticsUri in (None, '') or str(logAnalyticsUri).isspace())):
    logging.warning("logAnalyticsUri is None, used default value.")
    logAnalyticsUri = 'https://' + customer_id + '.ods.opinsights.azure.com'

pattern = r'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$'
match = re.match(pattern, str(logAnalyticsUri))
if (not match):
    raise Exception("CloudGenix: Invalid Log Analytics Uri.")


def generate_date():
    current_time = datetime.utcnow().replace(second=0, microsecond=0) - timedelta(minutes=10)
    state = StateManager(connection_string=connection_string)
    past_time = state.get()
    if past_time is not None:
        logging.info("The last time point is: {}".format(past_time))
    else:
        logging.info("There is no last time point, trying to get events for last hour.")
        past_time = (current_time - timedelta(minutes=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    state.post(current_time.strftime("%Y-%m-%dT%H:%M:%SZ"))
    return past_time, current_time.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization


def post_data(chunk):
    body = json.dumps(chunk)
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    try:
        response = requests.post(uri, data=body, headers=headers)

        if 200 <= response.status_code <= 299:
            logging.info("{} events was injected".format(len(chunk)))
            return response.status_code
        elif response.status_code == 401:
            logging.error(
                "The authentication credentials are incorrect or missing. Error code: {}".format(response.status_code))
        else:
            logging.error("Something wrong. Error code: {}".format(response.status_code))
        return None
    except Exception as err:
        logging.error("Something wrong. Exception error text: {}".format(err))


def gen_chunks_to_object(data, chunk_size=100):
    chunk = []
    for index, line in enumerate(data):
        if index % chunk_size == 0 and index > 0:
            yield chunk
            del chunk[:]
        chunk.append(line)
    yield chunk


def gen_chunks(data):
    for chunk in gen_chunks_to_object(data, chunk_size=chunksize):
        post_data(chunk)


def main(mytimer: func.TimerRequest) -> None:
    if mytimer.past_due:
        logging.info('The timer is past due!')
    logging.getLogger().setLevel(logging.INFO)
    logging.info('Starting program')
    start_time, end_time = generate_date()
    logging.info('Data processing. Period(UTC): {} - {}'.format(start_time, end_time))

    token = login(email=email, password=password, server_url=dispatcher)
    headers = {"x-auth-token": token}
    profile = get_profile(headers=headers)
    elements = get_elements(headers=headers, profile=profile)
    sites = get_sites(headers=headers, profile=profile)
    appdefs = get_appdefs(headers=headers, profile=profile)
    events = get_events(headers=headers, profile=profile, start_time=start_time, end_time=end_time)
    events = transform_events(events=events, elements=elements, sites=sites, appdefs=appdefs)

    # Send data via data collector API
    gen_chunks(events)
