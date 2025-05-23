import requests
import yaml
import uuid
import toml
import re
import os

DEFAULT_AUTHOR = ["AtomicRedTeam-Automation"]
DEFAULT_FROM = "now-9m"
DEFAULT_INDICES = ["logs-endpoint.events.*", "winlogbeat-*", "logs-windows.*", "logs-linux.*", "logs-macos.*"]
DEFAULT_RISK_SCORE = 50
DEFAULT_SEVERITY = "medium"
ATOMIC_REPO_BASE_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/refs/heads/master/atomics/"
MITRE_TECHNIQUE_BASE_URL = "https://attack.mitre.org/techniques/"


def create_detection_rule_toml_for_test(atomic_data, test_data):  
    if not atomic_data or not test_data:
        return None

    technique_id = atomic_data.get('attack_technique', 'T0000')
    display_name = atomic_data.get('display_name', 'Unnamed Atomic Collection')
    
    test_name = test_data.get('name', f"Test for {technique_id}")
    test_guid = test_data.get('auto_generated_guid', str(uuid.uuid4())[:8])
    test_description = test_data.get('description', '').strip()
    platforms = test_data.get('supported_platforms', atomic_data.get('supported_platforms', ['unknown']))
    input_arguments = test_data.get('input_arguments', {})
    
    command_to_detect = ""
    executor_name = ""

    if test_data.get('executor'):
        executor = test_data['executor']
        command_to_detect = executor.get('command', '')
        executor_name = executor.get('name', '')
        if not command_to_detect and executor.get('steps'):
             command_to_detect = executor.get('steps') # Handle API based tests command as steps
    else:
        executor_name = "unknown_executor"
        command_to_detect = "echo 'No command or steps found in this specific test structure'"

    if isinstance(command_to_detect, list): # For API based tests with steps
        command_to_detect = "; ".join(command_to_detect)


    kql_query = generate_kql_from_command(command_to_detect, executor_name, input_arguments)

    atomic_yaml_suffix = f"{technique_id}/{technique_id}.yaml" 

    rule_name = f"Atomic Test: {technique_id} - {test_name}"
    rule_description = f"Detection for specific test '{test_name}' (GUID: {test_guid}) of technique {technique_id} ({display_name})."
    if test_description:
        rule_description += f" Test Description: {test_description}."
    rule_description += f" Command/Steps: {command_to_detect[:150]}{'...' if len(command_to_detect) > 150 else ''}"


    rule = {
        'rule': {
            'author': DEFAULT_AUTHOR,
            'description': rule_description,
            'from': DEFAULT_FROM,
            'rule_id': str(uuid.uuid4()),
            'language': 'kql',
            'name': rule_name,
            'output_index': '.siem-signals-default',
            'references': [f"{ATOMIC_REPO_BASE_URL}{atomic_yaml_suffix}"],
            'risk_score': DEFAULT_RISK_SCORE,
            'severity': DEFAULT_SEVERITY,
            'tags': ["AtomicRedTeam", technique_id, test_guid] + platforms,
            'type': 'query',
            'query': kql_query,
            'threat': [
                {
                    'framework': 'MITRE ATT&CK',
                    'technique': [
                        {
                            'id': technique_id,
                            'name': test_data.get('name', atomic_data.get('display_name', 'Unknown Technique Name')),
                            'reference': f"{MITRE_TECHNIQUE_BASE_URL}{technique_id.split('.')[0]}/{technique_id.split('.')[1]}" if '.' in technique_id else f"{MITRE_TECHNIQUE_BASE_URL}{technique_id}"
                        }
                    ],
                }
            ],
            'version': 1,
        }
    }
    
    if kql_query:
        rule['rule']['index'] = DEFAULT_INDICES
    print(technique_id)
    if '.' in technique_id:
        rule['rule']['threat'][0]['tactic'] = {
             'id': 'TAXXXX',
             'name': 'Unknown Tactic',
             'reference': 'https://attack.mitre.org/tactics/TAXXXX/'
        }

    return toml.dumps(rule)

def generate_kql_from_command(command, executor_name, input_arguments):
    if not command:
        return ""

    processed_command = command.strip()
    for arg_name, arg_details in input_arguments.items():
        placeholder = f"#{{{arg_name}}}"
        default_value = arg_details.get("default", "*")
        processed_command = processed_command.replace(placeholder, str(default_value) if default_value is not None else "*")


    raw_keywords = re.split(r'\s|\\|/|=|\(|\)|\[|\]|\{|\}|;|"|\'|,', processed_command)
    keywords = [
        kw.strip('*') for kw in raw_keywords
        if len(kw.strip('*')) > 1 and kw.lower() not in [
            "the", "and", "for", "with", "is", "are", "of", "to", "in", "on", "at",
            "a", "an", "cmd", "exe", "bin", "sh", "tmp", "log", "mnt", "true", "false", "echo", "set", "new", "get", "sudo", "powershell"
            ]
    ]
    keywords = sorted(list(set(k for k in keywords if k)), key=keywords.index)


    query_parts = []
    executor_name_lower = executor_name.lower() if executor_name else ""

    if "powershell" in executor_name_lower:
        query_parts.append(
            '(process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") OR process.parent.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe"))'
        )
        if keywords:
            script_block_conditions = " AND ".join([f'powershell.script_block_text : "*{k}*"' for k in keywords[:3]])
            command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords[:3]])
            query_parts.append(f"({script_block_conditions} OR ({command_line_conditions}))")
    elif "command_prompt" in executor_name_lower or "cmd" in executor_name_lower:
        query_parts.append(
            '(process.name : ("cmd.exe", "cmmon32.exe") OR process.parent.name : ("cmd.exe", "cmmon32.exe"))'
        )
        if keywords:
            command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords[:3]])
            query_parts.append(command_line_conditions)
    elif "sh" in executor_name_lower or "bash" in executor_name_lower:
        query_parts.append(
            '(process.name : ("sh", "bash") OR process.parent.name : ("sh", "bash"))'
        )
        if keywords:
            command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords[:3]])
            query_parts.append(command_line_conditions)
    else:
        if keywords:
            command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords[:3]])
            query_parts.append(command_line_conditions)

    if not query_parts and keywords:
        command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords[:3]])
        query_parts.append(command_line_conditions)
    
    if not query_parts:
        sanitized_command_snippet = processed_command.replace('\\', '\\\\').replace('"', '\\"').replace(":", "\\:").replace("'", "\\'")[:60]
        return f'process.command_line : "*{sanitized_command_snippet}*"'

    return " AND ".join(query_parts)

def generate_toml(technique):
    url = f"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/refs/heads/master/atomics/{technique}/{technique}.yaml"
    response = requests.get(url)
    if response.status_code == 200:
        try:
            atomic_data = yaml.safe_load(response.text)
            generated_results = []

            if atomic_data and atomic_data.get('atomic_tests'):
                atomic_tests = atomic_data.get('atomic_tests', [])
                if not atomic_tests:
                    print(f"No 'atomic_tests' found in {url}")
                    return []
                
                num_tests = len(atomic_tests)
                
                for test in atomic_tests:
                    # Loops through each test in the Atomic YAML file
                    toml_output = create_detection_rule_toml_for_test(atomic_data, test)

                    if toml_output:
                        
                        technique_id_for_file = atomic_data.get('attack_technique', 'T0000').replace('.', '_')
                        test_name_for_file = re.sub(r'[^a-zA-Z0-9_-]', '_', test.get('name', f"Test_{test.get('auto_generated_guid', 'NOGUID')}")[:50])
                        output_filename = f"{technique_id_for_file}_{test_name_for_file}.toml"
                        output_filename = output_filename.replace(os.sep, "_").replace("/", "_").replace("\\\\", "_")
                        print(toml_output)
            return atomic_data
        





        except Exception as e:
            print(f"Error parsing YAML file {url}: {e}")
            return None
    else:
        return None




