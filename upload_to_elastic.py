import requests
import os
from dotenv import load_dotenv
import tomllib
import json

load_dotenv()

ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY")
ELASTIC_HOST = os.getenv("ELASTIC_HOST")
HEADERS = {
    "Content-Type": "application/json;charset=UTF-8",
    "kbn-xsrf": "true",
    "Authorization": 'ApiKey ' + ELASTIC_API_KEY
}

def upload_toml(file):
    if not file.endswith(".toml"):
        print(f"Skipping non-TOML file: {file}")
        return False
        
    try:
        with open(file, "rb") as toml_file:
            alert = tomllib.load(toml_file)
            
            payload = {}
            
            if alert["rule"]["type"] == "query":
                required_fields = ["author", "description", "name", "risk_score", "severity", "type", "query", "index"]
            elif alert["rule"]["type"] == "eql":
                required_fields = ["author", "description", "name", "risk_score", "severity", "type", "query", "language", "index"]
            elif alert["rule"]["type"] == "threshold":
                required_fields = ["author", "description", "name", "risk_score", "severity", "type", "query", "threshold", "index"]
            else:
                print(f"Unsupported rule type found in file: {file}")
                return False

            for field in required_fields:
                if field in alert["rule"]:
                    payload[field] = alert["rule"][field]
            
            payload["enabled"] = True
            
            data = json.dumps(payload)
            
            response = requests.post(ELASTIC_HOST, headers=HEADERS, data=data)
            
            if response.status_code == 200:
                print(f"Successfully uploaded: {file}")
                return True
            else:
                print(f"Failed to upload {file}")
                print(f"Status: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
    except Exception as e:
        print(f"Error processing {file}: {e}")
        return False

