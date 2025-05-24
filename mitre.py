import requests
import ast


mitre_tactics_list = [
    ("TA0043", "reconnaissance"),
    ("TA0042", "resource development"),
    ("TA0001", "initial access"),
    ("TA0002", "execution"),
    ("TA0003", "persistence"),
    ("TA0004", "privilege escalation"),
    ("TA0005", "defense evasion"),
    ("TA0006", "credential access"),
    ("TA0007", "discovery"),
    ("TA0008", "lateral movement"),
    ("TA0009", "collection"),
    ("TA0011", "command and control"),
    ("TA0010", "exfiltration"),
    ("TA0040", "impact")
]

def get_tactics(technique):

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    headers = {
        "Accept": "application/json"

    }

    mitreData = requests.get(url, headers=headers).json()
    mitreMapped = {}

    for object in mitreData["objects"]:
        tactics = []
        if object["type"] == "attack-pattern":
            if 'external_references' in object:
                for reference in object["external_references"]:
                    if 'external_id' in reference:
                        if ((reference["external_id"].startswith("T"))):
                            if "kill_chain_phases" in object:
                                for tactic in object["kill_chain_phases"]:
                                    tactics.append(tactic["phase_name"])
                            current_technique = reference["external_id"]
                            name = object["name"]
                            url = reference["url"]
                        

                            if 'x_mitre_deprecated' in object:
                                deprecated = object["x_mitre_deprecated"]
                                filtered_object = {
                                    "tactics": str(tactics),
                                    "technique": current_technique,
                                    "name": name,
                                    "url": url,
                                    "deprecated": deprecated
                                }
                                mitreMapped[current_technique] = filtered_object
                            else:
                                filtered_object = {
                                    "tactics": str(tactics),
                                    "technique": current_technique,
                                    "name": name,
                                    "url": url,
                                    "deprecated": "False"
                                }
                                mitreMapped[current_technique] = filtered_object
    tactics_string = mitreMapped[technique]['tactics']
    tactics = ast.literal_eval(tactics_string)
    return tactics

def map_tactic_to_id(tactic_name):
    tactic_name = tactic_name.replace("-", " ")
    for item in mitre_tactics_list:
        if tactic_name == item[1]:
            return item[0]
    return None

def main():
    tactics = get_tactics('T1001.002')
    for tactic in tactics:
        print(map_tactic_to_id(tactic))


if __name__ == "__main__":
    main()
