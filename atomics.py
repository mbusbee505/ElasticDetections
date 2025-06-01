import requests
import re
import json

url = "https://github.com/redcanaryco/atomic-red-team/tree/master/atomics"

response = requests.get(url)
match = re.search(r'<script type="application/json" data-target="react-app.embeddedData">(.*?)</script>', response.text)
json_string_data = match.group(1)
data = json.loads(json_string_data)
techniques = []

for item in data["payload"]["tree"]["items"]:
    if item["name"].startswith("T"):
        techniques.append(item["name"])

def get_atomic_techniques():
    return techniques

