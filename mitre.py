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

def pull_mitre_data():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    headers = {
        "Accept": "application/json"

    }

    mitreData = requests.get(url, headers=headers).json()
    return mitreData

def tactic_search(search_string):
    mitreData = pull_mitre_data()
    search_string = search_string.lower()
    results = []
    for object in mitreData["objects"]:
        if object["type"] == "attack-pattern":
            name_match = search_string in object["name"].lower()
            description_match = search_string in object["description"].lower()
            
            # Convert kill_chain_phases to string and check lowercase
            kill_chain_match = search_string in str(object["kill_chain_phases"]).lower()
            
            # Convert external_references to string and check lowercase  
            external_ref_match = search_string in str(object["external_references"]).lower()
            
            if name_match or description_match or kill_chain_match or external_ref_match:
                results.append(object["name"])
    return results

def get_tactics(technique):
    mitreData = pull_mitre_data()
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
                            technique = reference["external_id"]
                            name = object["name"]
                            url = reference["url"]
                        

                            if 'x_mitre_deprecated' in object:
                                deprecated = object["x_mitre_deprecated"]
                                filtered_object = {
                                    "tactics": str(tactics),
                                    "technique": technique,
                                    "name": name,
                                    "url": url,
                                    "deprecated": deprecated
                                }
                                mitreMapped[technique] = filtered_object
                            else:
                                filtered_object = {
                                    "tactics": str(tactics),
                                    "technique": technique,
                                    "name": name,
                                    "url": url,
                                    "deprecated": "False"
                                }
                                mitreMapped[technique] = filtered_object
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
    print(tactic_search("4688"))


if __name__ == "__main__":
    main()
