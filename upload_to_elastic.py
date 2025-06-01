import requests
import os
from dotenv import load_dotenv

load_dotenv()

ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY")
ELASTIC_HOST = os.getenv("ELASTIC_HOST")



headers = {
    "Content-Type": "application/json;charset=UTF-8",
    "kbn-xsrf": "true",
    "Authorization": 'ApiKey ' + ELASTIC_API_KEY
}

data = """
{
  "id": "6541b99a-dee9-4f6d-a86d-dbd1869d73b1",
  "to": "now",
  "from": "now-70m",
  "name": "MS Office child process",
  "tags": [
    "child process",
    "ms office"
  ],
  "type": "query",
  "query": "process.parent.name:EXCEL.EXE or process.parent.name:MSPUB.EXE or process.parent.name:OUTLOOK.EXE or process.parent.name:POWERPNT.EXE or process.parent.name:VISIO.EXE or process.parent.name:WINWORD.EXE",
  "setup": "",
  "threat": [],
  "actions": [],
  "enabled": false,
  "filters": [
    {
      "query": {
        "match": {
          "event.action": {
            "type": "phrase",
            "query": "Process Create (rule: ProcessCreate)"
          }
        }
      }
    }
  ],
  "rule_id": "process_started_by_ms_office_program",
  "version": 1,
  "interval": "1h",
  "language": "kuery",
  "severity": "low",
  "immutable": false,
  "created_at": "2020-04-07T14:51:09.755Z",
  "created_by": "elastic",
  "references": [],
  "risk_score": 50,
  "updated_at": "2020-04-07T14:51:09.970Z",
  "updated_by": "elastic",
  "description": "Process started by MS Office program - possible payload",
  "max_signals": 100,
  "false_positives": [],
  "required_fields": [
    {
      "ecs": true,
      "name": "process.parent.name",
      "type": "keyword"
    }
  ],
  "related_integrations": [
    {
      "package": "o365",
      "version": "^2.3.2"
    },
    {
      "package": "azure",
      "version": "^1.11.4",
      "integration": "graphactivitylogs"
    }
  ]
}
"""

elastic_data = requests.post(ELASTIC_HOST, headers=headers, data=data).json()

