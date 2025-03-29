import flask
from flask import Flask, jsonify,request,render_template,send_from_directory
# from supersetapiclient.client import SupersetClient
from vars import SUPERSET_HOST, SUPERSET_USER, SUPERSET_PASSWORD
from client import SupersetClient
from vars import *
import requests
from flask_cors import CORS, cross_origin
import datetime
import base64
import json
app = Flask(__name__)


# Instantiate a SupersetClient object
client =SupersetClient(
    host=SUPERSET_HOST,
    username=SUPERSET_USER,
    password=SUPERSET_PASSWORD,
)
CORS(app, origins='http://127.0.0.1:5000')

@app.route("/guest-token", methods=["GET", "POST"])
def guest_token():
    with app.app_context():
        print('client', client.host)
        print('client', client.username)
        # print('client', client.password)
        print('get this token')
        response = client.create_guest_token()
        if 'token' in response:
            print('token', response)
            header_token = response['token'].split('.')[1]
            decoded_header = base64.urlsafe_b64decode(header_token + '===').decode('utf-8')
            print('decoded_header', decoded_header)
            decoded_header_json= json.loads(decoded_header)
            guest_token_exp = decoded_header_json['exp']
            exp = datetime.datetime.fromtimestamp(guest_token_exp)
            print('guest token', exp)
            return jsonify(guest_token_response(response))
        else:
            return jsonify({'error': 'Failed to create guest token'}), 500

def superset_client():
    return SupersetClient(
        host=SUPERSET_HOST,
        username=SUPERSET_USER,
        # password=SUPERSET_PASSWORD,
    )

def guest_token_response(result):
    return {
        'token': result.get('token'),
        'dashboard_id': app.config.get('SUPERSET_DASHBOARD_ID'),  # Access config variables correctly
        'domain': app.config.get('SUPERSET_API_URL')
    }
@app.route('/providers/<int:id>')
def provider_detail(id):
    # an HTML template named 'provider_detail.html'
    # You can pass the id to the template as a variable
    return render_template('provider_detail.html', provider_id=id)
@app.route('/')
def hello():
    print("Incoming request:")
    print(f"Method: {request.method}")
    print(f"Path: {request.path}")
    print(f"Headers: {request.headers}")
    print(f"Data: {request.data}")
    print(f"request full: {request}")
    return render_template('index.html', SUPERSET_USER=SUPERSET_USER)

if __name__ == "__main__":
    # guest_token()
    app.run(debug=True)
