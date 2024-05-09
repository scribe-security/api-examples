import requests
import json
import argparse


def send_post_request(url, token = None, body = None):
    try:
        headers = {}

        if token is not None:
            headers['Authorization'] = f'Bearer {token}'

        headers['Content-Type'] = 'application/json'

        response = requests.post(url = url, headers = headers, json = body)
        
        if response.status_code == 200:
            return response
        else:
            print(f"POST request failed with status code: {response.status_code}")
            print(response.text)
            return None

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

        return None

def send_get_request(url, token = None):
    try:
        headers = {}

        if token is not None:
            headers['Authorization'] = f'Bearer {token}'

        headers['Content-Type'] = 'application/json'
        
        response = requests.get(url = url, headers = headers)
        
        if response.status_code == 200:
            return response
        else:
            print(f"GET request failed with status code: {response.status_code}")
            print(response.text)
            return None

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

        return None



def login(api_token):
    url = "https://api.scribesecurity.com/v1/login"

    body = {"api_token": api_token}
    
    response = send_post_request(url = url, body = body)

    if 'token' in response.json():
        return response.json()['token']
    else:
        print("Token not found in the response.")

    return None


def get_superset_token(jwt_token):
    url = "https://api.scribesecurity.com/dataset/token"

    response = send_get_request(url = url, token = jwt_token)            

    response_json = json.loads(response.text)

    if 'access_token' in response_json:
        return response_json['access_token']
    else:
        print("Access token not found in the response.")

        return None


def get_dataset_ids(superset_token, jwt_token):
    url = "https://api.scribesecurity.com/dataset"

    body = {"superset_token": superset_token}

    data = send_post_request(url = url, token = jwt_token, body = body)

    try:
        response_json = json.loads(data.text)

        result = response_json.get("result", [])
        
        datasource_id_map = {}
        
        for entry in result:
            datasource_name = entry.get("datasource_name")

            datasource_id = entry.get("id")

            if datasource_name and datasource_id:
                datasource_id_map[datasource_name] = datasource_id
        
        return datasource_id_map
    
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")

        return {}


def get_component_vulns(superset_token, jwt_token):
    url = "https://api.scribesecurity.com/dataset/data"

    ids = get_dataset_ids(superset_token, jwt_token)

    body = {
        "superset_token": superset_token,
        "query": {
            "datasource": {
                "id": ids["CVE Impact v2"],
                "type": "table"
            },
            "force": False,
            "queries": [
                {
                    "columns": [
                        "vulnerability_id",
                        "severity",
                        "targetName",
                        "component_name"
                    ],
                    "filters": [
                    ],
                    "metrics": [],
                    "row_limit": 0
                }
            ],
            "result_format": "json",
            "result_type": "results"
        },
        "validate": False
    }

    r = send_post_request(url = url, token = jwt_token, body = body)

    with open("vulnerabilities_report.json", "w") as f:
        f.write(r.text)

def get_products(superset_token, jwt_token):
    url="https://api.scribesecurity.com/dataset/data"

    ids=get_dataset_ids(superset_token, jwt_token)

    body = {
        "superset_token": superset_token,
        "query": {
            "datasource": {
                "id": ids["asbom_filtered"],
                "type": "table"
            },
            "force": "false",
            "queries": [
                {
                    "columns": [
                        "logical_app"
                    ],
                    "filters": [],
                    "metrics": [],
                    "row_limit": 0
                }
            ],
            "result_format": "json",
            "result_type": "results"
        }
    }

    r = send_post_request(url = url, token = jwt_token, body = body)

    with open("products_report.json", "w") as f:
        f.write(r.text)


if __name__ == "__main__":
    parser=argparse.ArgumentParser()

    parser.add_argument("--api_call", choices = ["component-vulnerabilities", "get-products"])
    parser.add_argument("--api_token", help = "Your API token from Scribehub integrations page")

    args=parser.parse_args()

    jwt_token=login(args.api_token)

    superset_token=get_superset_token(jwt_token)

    if args.api_call=="component-vulnerabilities":
        get_component_vulns(superset_token, jwt_token)
    elif args.api_call=="get-products":
        get_products(superset_token, jwt_token)

