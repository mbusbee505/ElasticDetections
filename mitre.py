import requests

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


def get_tactics(technique):
    return mitreMapped[technique]['tactics']


def main():
    print(get_tactics('T1001.002'))

if __name__ == "__main__":
    main()
