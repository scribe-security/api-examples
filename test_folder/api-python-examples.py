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

def login(api_token, base_url):
    url = f"{base_url}/v1/login"

    body = {"api_token": api_token}
    
    response = send_post_request(url = url, body = body)

    if 'token' in response.json():
        return response.json()['token']
    else:
        print("Token not found in the response.")

    return None


def get_superset_token(jwt_token, base_url):
    url = f"{base_url}/dataset/token"

    response = send_get_request(url = url, token = jwt_token)            

    response_json = json.loads(response.text)

    if 'access_token' in response_json:
        return response_json['access_token']
    else:
        print("Access token not found in the response.")

        return None


def get_dataset_ids(superset_token, jwt_token, base_url):
    url = f"{base_url}/dataset"

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


def get_component_vulns(superset_token, jwt_token, base_url):
    url = f"{base_url}/dataset/data"

    ids = get_dataset_ids(superset_token, jwt_token, base_url)

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

def get_products(superset_token, jwt_token, base_url):
    url=f"{base_url}/dataset/data"

    ids=get_dataset_ids(superset_token, jwt_token, base_url)

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

def get_datasets(superset_token, jwt_token, base_url):

    url=f"{base_url}/dataset"

    body = {
        "superset_token": superset_token
    }

    r = send_post_request(url = url, token = jwt_token, body = body)

    json.dump(r.json(), open("datasets.json", "w")) 

    
if __name__ == "__main__":
    parser=argparse.ArgumentParser()

    parser.add_argument("--api_call", choices = ["component-vulnerabilities", "get-products", "get-datasets"])
    parser.add_argument("--api_token", help = "Your API token from Scribehub integrations page")
    parser.add_argument("--env", choices=["prod","dev","test","ci"], help = "Which environment to use")

    args=parser.parse_args()

    base_url = "https://api.scribesecurity.com"
    if args.env!="prod":
        base_url=f"https://api.{args.env}.scribesecurity.com"


    jwt_token=login(args.api_token, base_url)

    superset_token=get_superset_token(jwt_token, base_url)

    if args.api_call=="component-vulnerabilities":
        get_component_vulns(superset_token, jwt_token, base_url)
    elif args.api_call=="get-products":
        get_products(superset_token, jwt_token, base_url)
    elif args.api_call=="get-datasets":
        get_datasets(superset_token, jwt_token, base_url)

