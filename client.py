from supersetapiclient.client import SupersetClient
from vars import ( SUPERSET_HOST, SUPERSET_USER, SUPERSET_PASSWORD, SUPERSET_DASHBOARD_ID_9,JWT_SECRET,SUPERSET_DASHBOARD_ID_10)
from api_client import SupersetApiClient
import json

login_url = SUPERSET_HOST + "api/v1/security/login"
csrf_url = SUPERSET_HOST + "api/v1/security/csrf_token"
class SupersetClient:
    def __init__(self, host, username, password):
    # Initialize SupersetClient with host, username, and password
        self.host = host
        self.username = username
        self.password = password
        self.client = SupersetApiClient()
        self.access_token = self.client.access_token

    def get_token(self):
        try:
            print('self.client.access_token', self.client.access_token)
            return self.client.access_token
        except Exception as e:
            # Log error
            print(f"Error occurred: {e}")

    def fetch_csrf_token(self):
        # Example of passing csrf_token to SupersetApiClient method
        return self.client.fetch_csrf_token()

    def create_guest_token(self):
        try:
            # create a guest token
            csrf = self.fetch_csrf_token()
            print('body',self.guest_token_request_body)
            return self.client.post_guest('/api/v1/security/guest_token/', body=self.guest_token_request_body())
        except Exception as e:
            # Log error
            print(f"Error occurred: {e}")

    def guest_token_request_body(self):
        user = str(SUPERSET_USER['username'])
        return {
            'resources': [
                {
                    'id': SUPERSET_DASHBOARD_ID_9,
                    'type': 'dashboard'
                },
                {
                    'id': SUPERSET_DASHBOARD_ID_10,
                    'type': 'dashboard'
                },

            ],
            "rls": [
                {
                    "clause": "cast(client as varchar)='{{current_username()}}' and cast(provider_id as integer) = 500"
                },
            ],
            'user': {
                'first_name': SUPERSET_USER['first_name'],
                'last_name': SUPERSET_USER['last_name'],
                'username': user
            },
            'headers': {
                         'content-type': 'application/json',
            },
            'domain': SUPERSET_HOST,
            'host': SUPERSET_HOST,
            "Referer": "http://127.0.0.1:5000"
        }


    def get_dynamic_plugins(self):
        try:
            return self.client.dynamic_plugins()
        except Exception as e:
            # Log error
            print(f"Error occurred: {e}")
