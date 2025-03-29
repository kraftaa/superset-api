import requests
import time
import datetime
import base64
import json
from vars import SUPERSET_HOST, SUPERSET_USER,SUPERSET_PASSWORD,JWT_SECRET

class SupersetApiClient:
    def __init__(self):
        self.access_token = None
        self.refresh_token = None
        self.csrf_token = None

    def api_client(self):
        print("superset api client", self)

        # Return the current instance of SupersetApiClient
        return self

    def get_access_token(self):
        if not self.access_token or self.is_refresh_token_expired():
            print("not self.access_token", self)

            response = self._request_access_token()
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get('access_token')
                self.access_token_expiration = json.loads(base64.urlsafe_b64decode(self.access_token.split(".")[1] + '===').decode('utf-8'))['exp']
                self.access_token_not_before = json.loads(base64.urlsafe_b64decode(self.access_token.split(".")[1] + '===').decode('utf-8'))['nbf']

                print("Access token obtained:", self.access_token)
                print("Access token expiration:", datetime.datetime.fromtimestamp(self.access_token_expiration))

                refresh_token = data.get('refresh_token')
                # store to reuse for getting new access token & expiration
                print('self.refresh_token', self.refresh_token)
                self.refresh_token = refresh_token
                self.refresh_token_expiration = json.loads(base64.urlsafe_b64decode(self.refresh_token.split(".")[1] + '===').decode('utf-8'))['exp']
                print("Refresh token expiration:", datetime.datetime.fromtimestamp(self.refresh_token_expiration))
        # else if response.json()['msg'] == 'Token has expired'
            #     self.refresh_access_token()
            else:
                self._log_error(response)
        elif self.is_access_token_expired() and not self.is_refresh_token_expired():
            print("access token expired, go for the refresh")
            self.refresh_access_token()
        elif self.is_access_token_expired() and self.is_refresh_token_expired():
            self._request_access_token
        return self.access_token

    def is_access_token_expired(self):
        # by time or message?
        # {'msg': 'Token has expired'}
        current_time = int(time.time())
        print(self.access_token_expiration < current_time)
        print(self.refresh_token_expiration < current_time)
        return (self.access_token_expiration < current_time)
        # return False  # just in case while not implemented

    def is_refresh_token_expired(self):
        current_time = int(time.time())
        return  (self.refresh_token_expiration < current_time)


    def refresh_access_token(self):
        print('refresh_access_token')
        if self.refresh_token:
            print("Refresh token expiration from refresh_access_token:", datetime.datetime.fromtimestamp(self.refresh_token_expiration))
            response = self._request_refresh_token(self.refresh_token)
            if response.status_code == 200:
                data = response.json()
                print('data', data)
                self.access_token = data.get('access_token')
                print("Access token refreshed:", self.access_token)
                return self.access_token
            else:
                self._log_error(response)

    def _request_access_token(self):
        print('_request_access_token')
        return requests.post(
            self.root_url() + '/api/v1/security/login',
            json=self.login_request_body(),
            headers={
                'content-type': 'application/json'
            },
            timeout=self.timeout()
        )

    def _request_refresh_token(self, refresh_token):
        print('_request_refresh_token should return access token')
        return requests.post(
            self.root_url() + '/api/v1/security/refresh',
            json={"refresh_token": refresh_token},
            headers={'content-type': 'application/json',
                     'authorization': f"Bearer {self.refresh_token}"},
            timeout=self.timeout()
        )


    def fetch_csrf_token(self):
        print('fetch_csrf_token')
        if not self.csrf_token:
            access_token = self.get_access_token()
            print('access_token', access_token)
            if access_token:
                response = self._request_csrf_token(access_token)
                if response.status_code == 200:
                    self.csrf_token = {
                        'csrf_token': response.json()['result'],
                        'session_cookie': response.headers['Set-Cookie']
                    }
                    print("CSRF token obtained:", self.csrf_token)
                else:
                    self._log_error(response)

        return self.csrf_token

    # def post(self, path, body):
    def post_guest(self, path, body):
        csrf_token = self.fetch_csrf_token()
        # access_token = self.access_token
        if self.is_access_token_expired() and not self.is_refresh_token_expired():
            print("access token expired, go for the refresh")
            self.access_token = self.refresh_access_token()
            print('after refresh self.access_token', self.access_token)
        elif self.is_access_token_expired() and self.is_refresh_token_expired():
            print("access token expired and refresh token expired, go for the refresh")
            self.access_token = self._request_access_token
        else:
            print("access token & refresh token are not expired")
            self.access_token = self.access_token
        print('self.access_token ', self.access_token)
        print('self.refresh_token ', self.refresh_token)
        headers = {
            'content-type': 'application/json',
            'authorization': f"Bearer {self.access_token}",
            'X-CSRFToken': csrf_token.get('csrf_token'),
            'Cookie': csrf_token.get('session_cookie'),
            "X-Frame-Options": "ALLOWALL",
            # "Content-Security-Policy": "frame-ancestors http://127.0.0.1:8088",
            'Access-Control-Allow-Origin': 'http://127.0.0.1:5000', # again -was it the reason for CORS issue?
            'Access-Control-Allow-Headers': '*'
        }
        print('headers', headers)
        response = requests.post(self.root_url() + path, json=body, headers=headers, timeout=self.timeout())
        if response.status_code == 200:
            print("Post request successful. Response:", response.json())
            print('response.json()', response.json())
            return response.json()
        else:
            self._log_error(response)

    def root_url(self):
        return SUPERSET_HOST

    def timeout(self):
        return 5


    def login_request_body(self):
        user = str(SUPERSET_USER['username'])
        return {
            'username': user,
            'password': SUPERSET_PASSWORD,
            'provider': 'db',
            'refresh': True
        }

    def _request_access_token(self):
        print('_request_access_token')
        return requests.post(
            self.root_url() + '/api/v1/security/login',
            json=self.login_request_body(),
            headers={
                'content-type': 'application/json'
            },
            timeout=self.timeout()
        )

    def _request_csrf_token(self, access_token):
        print('_request_csrf_token')
        return requests.get(
            self.root_url() + '/api/v1/security/csrf_token/',
            headers={
                # 'Content-Type': 'application/json',
                'content-type': 'application/json',
                # 'Authorization': f"Bearer {access_token}",
                'authorization': f"Bearer {access_token}",
            },
            timeout=self.timeout()
        )

    def _log_error(self, response):
        # Log errors here using a proper logging mechanism
        print(f"Error: {response.text}")


    def dynamic_plugins(self):
        access_token = self.get_access_token()

        return requests.get(
            self.root_url() + '/dynamic-plugins/api/read',
            headers={
                'content-Type': 'application/json',
                'authorization': f"Bearer {access_token}",
            },
            timeout=self.timeout()
        )