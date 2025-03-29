SUPERSET_HOST = os.environ['SUPERSET_HOST'] # "http://127.0.0.1:8088" or https://superset.domain.com
import os

SUPERSET_SECRET_KEY = os.environ['SUPERSET_SECRET_KEY']
from api_client import SupersetApiClient
api_client = SupersetApiClient()
import jwt
SUPERSET_USER = os.environ['SUPERSET_USER'] # { "username": "api_admin", "first_name": "first_name", "last_name": "last_name"}
SUPERSET_PASSWORD = os.environ['SUPERSET_PASSWORD']
import datetime
import base64
import json
from cryptography.fernet import Fernet

def check_access_token():
    access_token = api_client.get_access_token()
    refresh_token = api_client.refresh_token
    decoded_refres_str = base64.urlsafe_b64decode(refresh_token.split(".")[1] + '===').decode('utf-8')
    print("decoded_refres_str", decoded_refres_str)
    decoded_refres = json.loads(decoded_refres_str)
    refres_exp= datetime.datetime.fromtimestamp(decoded_refres['exp'])
    print("decoded_refres_str expiration", refres_exp)
    print("api client", access_token)
    parts = access_token.split('.')
    header = parts[0]
    decoded_header = base64.urlsafe_b64decode(header + '===').decode('utf-8')
    print(decoded_header)
    decoded2_str = base64.urlsafe_b64decode(parts[1] + '===').decode('utf-8')
    print("decoded2", decoded2_str)
    decoded2 = json.loads(decoded2_str)
    expiration_time = decoded2["exp"]
    print(expiration_time)
    not_before_time = decoded2['nbf']

    print("Token Expiration and not before: ", datetime.datetime.fromtimestamp(expiration_time),
          datetime.datetime.fromtimestamp(not_before_time))

# to check what algorithm was used {'alg': 'HS256', 'typ': 'JWT'}
def decode_jwt_header(token):
    parts = token.split('.')
    header = parts[0]
    decoded_header = base64.urlsafe_b64decode(header + '===').decode('utf-8')
    return json.loads(decoded_header)


# Print the decoded header
# print(header)
SUPERSET_DASHBOARD_ID_1 = os.environ['SUPERSET_DASHBOARD_ID_1']
def guest_token_request_body():
    user = str(SUPERSET_USER['username'])
    return {
        'resources': [
            {
                'id': SUPERSET_DASHBOARD_ID_1,
                'type': 'dashboard'
            },

        ],
        "rls": [
            {
                "clause": "cast(database.table.client_id as varchar)='{{current_username()}}'"
            },
            {
                "clause": "database.table.status ='Closed'"
            },

        ],
        # 'rls': [],  # we don't require it as we already have it in the dashboard, though probably we could add here for the extra protection
        'user': {
            'first_name': SUPERSET_USER['first_name'],
            'last_name': SUPERSET_USER['last_name'],
            'username': user
        },
        'domain': SUPERSET_HOST
        }

def get_guest_token():
    access_token = api_client.get_access_token()
    print('body',guest_token_request_body())
    response = api_client.post('/api/v1/security/guest_token/', body=guest_token_request_body())
    print("response", response, access_token)

def encrypt(token):
    # SUPERSET_SECRET_KEY = Fernet.generate_key()
    SUPERSET_SECRET_KEY = ENV["GUEST_TOKEN_JWT_SECRET"]
    print("key", SUPERSET_SECRET_KEY)
    # access_token = api_client.get_access_token()
    fernet = Fernet(SUPERSET_SECRET_KEY)
    # Encode the token as bytes
    token_bytes = token.encode()
    encrypted_token = fernet.encrypt(token_bytes)
    print("Encrypted token:", encrypted_token)
    decrypted_token = fernet.decrypt(encrypted_token)
    print("Decrypted token:", decrypted_token.decode())


def test_key():
    import requests

    # Replace 'YOUR_JWK_URL' with the actual URL where your JWK set is hosted
    jwk_url = 'https://www.googleapis.com/oauth2/v3/certs'

    # Fetch the JWK set
    response = requests.get(jwk_url)
    jwk_set = response.json()

    # Inspect the retrieved JWK set
    print(jwk_set)

    def create_db_connection(session, db_port, db_user, db_name):

        url = SUPERSET_HOST + "api/v1/database/"
        presto_url = "awsathena+rest://athena.eu-central-1.amazonaws.com/athena.eu-central-1.amazonaws.com/AwsDataCatalog?s3_staging_dir=s3%3A%2F%2Faws-athena-query-results-id-eu-central-1"
        csrf = self.fetch_csrf_token()
        data_out = {
            "allow_csv_upload": True,
            "allow_ctas": True,
            "allow_cvas": True,
            "allow_dml": True,
            "allow_multi_schema_metadata_fetch": True,
            "allow_run_async": True,
            "cache_timeout": 0,
            "database_name": db_name,
            "expose_in_sqllab": True,
            "impersonate_user": True,
            "presto_url": presto_url
        }
        headers = {
            # 'Referrer': login_url,
            'X-CSRFToken': csrf['csrf_token'],
            'Cookie': csrf['session_cookie']
        }

        response = session.post(url=url, headers=headers, json=data_out)
        response.raise_for_status()

        head = {
            "Authorization": "Bearer " + json.loads(response.text)['access_token']
        }

        response = session.get(csrf_url, headers=head)
        response.raise_for_status()

        response = create_db_connection(session, db_ip=db_host, db_port=db_port, db_user=db_user, db_pass=db_password, db_name=db_name)

        print(str(response.text))
        return response

auth_error_encoded = ".."  # Replace this with an actual value

def error_decode(token):
    import urllib.parse

    # Example authError value from your URL
    auth_error_encoded = ".."
    # Decode the authError value
    auth_error_decoded = urllib.parse.unquote(auth_error_encoded)
    print(auth_error_decoded)

def request_access_token_check():
    import requests
    print('_request_access_token')
    return requests.post(
        'https://superset.domain.com/api/v1/security/login',
        json={
            'username': str(SUPERSET_USER['username']),
            'password': str(SUPERSET_USER['password']),
            'provider': 'db',
            'refresh': True
        },
        headers={
            'content-type': 'application/json'
        },
        # timeout=self.timeout()
    )

def result():
    response = request_access_token_check()
    data = response.json()
    print(data)

def warm_up_cache(chart_id):
    import requests
    data = {
        "chart_id": chart_id,
        "dashboard_id": 0,
        # "extra_filters": "rfi_type"
        "extra_filters": ""
    }
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        "Authorization": "Bearer test_value"
    }
    response=  requests.put(
        'http://127.0.0.1:8088/api/v1/chart/warm_up_cache',
        headers = headers,
        json = data
        # timeout=self.timeout()
    )
    print(response.status_code)
    print(response.json())

import requests
def check_charts():

    # url = 'http://127.0.0.1:8088/api/v1/chart/'
    url = 'https://superset.domain.com/api/v1/chart/'
    headers = {
        'accept': 'application/json',
        "Authorization": "Bearer test_value"
    }

    response = requests.get(url, headers=headers)
    print(response.status_code)
    print(response.text)


import requests

# Base URL for Superset API
base_url = 'http://127.0.0.1:8088/api/v1'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    "Authorization": "Bearer from_the_test"
}
def get_all_charts():
    charts = []
    page = 0
    page_size = 50  # Adjust page size as needed
    initial_url = f'{base_url}/chart/'
    count = 0
    params = {'page': page, 'page_size': page_size}
    initial_response = requests.get(initial_url, headers=headers, params=params).json()
    print('initial_response',  initial_response)
    total_count = initial_response['count']
    all_ids = []

    page = 0
    while count < total_count:
        params = {'q': f'(page:{page},page_size:{page_size})'}
        response = requests.get(f'{base_url}/chart/', params=params, headers=headers)
        if response.status_code != 200:
            print(f"Error fetching charts: {response.text}")
            break
        data = response.json()
        current_len = len(data['ids'])
        print(data['ids'], 'data_ids')
        print(current_len, 'current_len')
        count += current_len
        print(count, 'count')
        charts.extend(data['result'])
        all_ids.extend(data['ids'])
        page += 1

        # Check if the current page contains fewer results than page_size
        # if len(data['result']) < page_size:
        #     break  # No more charts to fetch

        # page += 1

    return (charts,all_ids)
    # print(len(charts))

def print_it():
    charts, all_ids = get_all_charts()
    print(f"charts", charts)
    print(f"Found {len(charts)} charts.")
    print(f"all charts {all_ids} charts.")


def warm_up_all_charts_cache():
    charts, all_ids = get_all_charts()
    for chart_id in all_ids:
        warm_up_cache(chart_id)
        print(f" chart cache for  {chart_id} updated.")



def get_charts():
    url = f'{base_url}/chart/'
    page = 0
    page_size = 50  # Adjust page size as needed

    params = {'page': page, 'page_size': page_size}
    response = requests.get(url, headers=headers, params=params)
    data = response.json()
    result = data
    print(result)
    print(type(result))

def get_chart_info():
    import requests
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        "Authorization": "Bearer from_the_test"
    }
    url = f'{base_url}/chart/16'
    initial_response = requests.get(url, headers=headers).json()
    print(initial_response)

def delete_chart():
    import requests
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        "Authorization": "Bearer from_the_test"
    }
    url = f'{base_url}/chart/14'
    initial_response = requests.delete(url, headers=headers).json()
    print(initial_response)

headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    "Authorization": "Bearer from_the_test"
}
def get_all_dashboards():
    import requests
    url = 'https://superset.domain.com/api/v1/dashboard/'
    response = requests.get(url, url, headers=headers).json()
    dashboards_list = response["ids"]
    return dashboards_list

import requests
def get_detail_dashboard():
    dashboards = get_all_dashboards()
    base_url = 'https://superset.domain.com/api/v1/dashboard'
    for d in dashboards[0:4]:
        url = f'{base_url}/{d}'
        dashboard_response = requests.get(url, headers=headers).json()
        print(dashboard_response)


if __name__ == "__main__":
    get_detail_dashboard()


# from cryptography.fernet import Fernet


