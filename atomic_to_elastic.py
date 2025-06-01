import requests
import yaml
import uuid
import toml
import re
import os
import mitre
import atomics

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

    tactics = mitre.get_tactics(technique_id)
    tactic_list = []
    for tactic in tactics:
        tactic_id = mitre.map_tactic_to_id(tactic)
        if tactic_id:
            tactic_list.append({
                'id': tactic_id,
                'name': tactic.replace("-", " ").title(),
                'reference': f"{MITRE_TECHNIQUE_BASE_URL}{technique_id.split('.')[0]}/{technique_id.split('.')[1]}" if '.' in technique_id else f"{MITRE_TECHNIQUE_BASE_URL}{technique_id}"
            })
    
    if tactic_list:
        rule['rule']['threat'][0]['tactic'] = tactic_list

    return toml.dumps(rule)

def generate_kql_from_command(command, executor_name, input_arguments):
    if not command:
        return ""

    processed_command = command.strip()
    
    # Replace input argument placeholders
    for arg_name, arg_details in input_arguments.items():
        placeholder = f"#{{{arg_name}}}"
        default_value = arg_details.get("default", "*")
        processed_command = processed_command.replace(placeholder, str(default_value) if default_value is not None else "*")

    # Generalize test-specific paths using simple string replacement (no regex)
    test_generalizations = [
        ("PathToAtomicsFolder", "*"),
        ("ExternalPayloads", "*"),
        ("atomic-red-team", "*"),
        ("\\atomics\\", "\\*\\"),
        ("/atomics/", "/*/"),
        ("$env:PUBLIC", "*"),
        ("$env:TEMP", "*"),
        ("$env:TMP", "*"),
        ("C:\\Users\\", "C:\\Users\\*\\"),
        ("C:\\temp\\", "C:\\temp\\*\\"),
        ("/tmp/", "/tmp/*/"),
        ("/home/", "/home/*/"),
    ]
    
    # Apply generalizations
    for specific, general in test_generalizations:
        processed_command = processed_command.replace(specific, general)
    
    # Remove technique IDs from paths (T1001.002, etc.)
    words = processed_command.split()
    cleaned_words = []
    for word in words:
        # Remove technique IDs but keep the word structure
        if "T1" in word and "." in word:
            # Replace technique ID patterns with wildcards
            parts = word.split("T1")
            if len(parts) > 1:
                # Keep the prefix, replace the technique part
                cleaned_word = parts[0] + "*"
                # Add back any suffix after removing the technique pattern
                remaining = "T1" + parts[1]
                # Find where the technique ID ends (after the sub-technique)
                technique_end = 0
                for i, char in enumerate(remaining):
                    if char.isdigit() or char == ".":
                        technique_end = i + 1
                    else:
                        break
                if technique_end < len(remaining):
                    cleaned_word += remaining[technique_end:]
                cleaned_words.append(cleaned_word)
            else:
                cleaned_words.append(word)
        else:
            cleaned_words.append(word)
    
    processed_command = " ".join(cleaned_words)

    # Simple keyword extraction without complex regex that could hit escape sequences
    raw_keywords = processed_command.split()
    
    # Basic filtering
    excluded_words = [
        "the", "and", "for", "with", "is", "are", "of", "to", "in", "on", "at",
        "a", "an", "cmd", "exe", "bin", "sh", "tmp", "log", "mnt", "true", "false", 
        "echo", "set", "new", "get", "sudo", "powershell", "cd", "dir", "ls", "cat",
        "type", "out", "null", "dev", "Users", "user", "home", "temp", "var",
        "PathToAtomicsFolder", "ExternalPayloads", "atomics", "atomic-red-team",
        "Atomic", "atomic", "test", "Test", "demo", "Demo", "example", "Example",
        "env:PUBLIC", "env:TEMP", "env:TMP", "Downloads", "*"
    ]
    
    keywords = []
    for word in raw_keywords:
        clean_word = word.strip('*').strip('"').strip("'").strip().strip(',').strip(';')
        if (len(clean_word) > 3 and 
            clean_word.lower() not in excluded_words and 
            not clean_word.startswith(('T1', 'TA')) and
            not clean_word.isdigit() and
            "*" not in clean_word):  # Skip wildcarded terms
            keywords.append(clean_word)
    
    # Limit to most relevant keywords
    keywords = keywords[:3]

    query_parts = []
    executor_name_lower = executor_name.lower() if executor_name else ""

    if "powershell" in executor_name_lower:
        query_parts.append(
            '(process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") OR process.parent.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe"))'
        )
        if keywords:
            script_block_conditions = " AND ".join([f'powershell.script_block_text : "*{k}*"' for k in keywords])
            command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords])
            query_parts.append(f"({script_block_conditions} OR ({command_line_conditions}))")
    elif "command_prompt" in executor_name_lower or "cmd" in executor_name_lower:
        query_parts.append(
            '(process.name : ("cmd.exe", "cmmon32.exe") OR process.parent.name : ("cmd.exe", "cmmon32.exe"))'
        )
        if keywords:
            command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords])
            query_parts.append(command_line_conditions)
    elif "sh" in executor_name_lower or "bash" in executor_name_lower:
        query_parts.append(
            '(process.name : ("sh", "bash") OR process.parent.name : ("sh", "bash"))'
        )
        if keywords:
            command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords])
            query_parts.append(command_line_conditions)
    else:
        if keywords:
            command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords])
            query_parts.append(command_line_conditions)

    # Fallback: if no meaningful keywords, create a broader query
    if not query_parts:
        if executor_name_lower:
            if "powershell" in executor_name_lower:
                return '(process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") OR process.parent.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe"))'
            elif "cmd" in executor_name_lower:
                return '(process.name : ("cmd.exe", "cmmon32.exe") OR process.parent.name : ("cmd.exe", "cmmon32.exe"))'
            elif "sh" in executor_name_lower or "bash" in executor_name_lower:
                return '(process.name : ("sh", "bash") OR process.parent.name : ("sh", "bash"))'
        
        # Last resort: basic command line search
        return 'process.command_line : "*"'

    return " AND ".join(query_parts)

def sanitize_yaml_content(yaml_content):
    """Sanitize YAML content to handle various encoding and character issues"""
    
    # Remove control characters that YAML doesn't accept
    control_chars = {
        '\x00': '', '\x01': '', '\x02': '', '\x03': '', '\x04': '', '\x05': '', '\x06': '', '\x07': '',
        '\x08': '', '\x0b': '', '\x0c': '', '\x0e': '', '\x0f': '', '\x10': '', '\x11': '', '\x12': '',
        '\x13': '', '\x14': '', '\x15': '', '\x16': '', '\x17': '', '\x18': '', '\x19': '', '\x1a': '',
        '\x1b': '', '\x1c': '', '\x1d': '', '\x1e': '', '\x1f': ''
    }
    
    # Replace control characters
    for char, replacement in control_chars.items():
        yaml_content = yaml_content.replace(char, replacement)
    
    # Simple and direct approach: escape all single backslashes
    # This prevents any "bad escape" errors by making all backslashes literal
    yaml_content = yaml_content.replace('\\', '\\\\')
    
    return yaml_content

def generate_tomls_for_technique(technique):
    atomic_url = f"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/refs/heads/master/atomics/{technique}/{technique}.yaml"
    atomic_response = requests.get(atomic_url)
    if atomic_response.status_code == 200:
        try:
            atomic_data = yaml.safe_load(atomic_response.text)

            if atomic_data and atomic_data.get('atomic_tests'):
                atomic_tests = atomic_data.get('atomic_tests', [])
                if not atomic_tests:
                    print(f"No 'atomic_tests' found in {atomic_url}")
                    return []
                
                rule_tests = []
                for test in atomic_tests:
                    toml_output = create_detection_rule_toml_for_test(atomic_data, test)

                    if toml_output:
                        
                        technique_id_for_file = atomic_data.get('attack_technique', 'T0000').replace('.', '_')
                        test_name_for_file = re.sub(r'[^a-zA-Z0-9_-]', '_', test.get('name', f"Test_{test.get('auto_generated_guid', 'NOGUID')}")[:50])
                        output_filename = f"{technique_id_for_file}_{test_name_for_file}.toml"
                        output_filename = output_filename.replace(os.sep, "_").replace("/", "_").replace("\\\\", "_")
                        rule_tests.append((toml_output, output_filename))
                return rule_tests

        except Exception as e:
            print(f"Error parsing YAML file {atomic_url}: {e}")
            return None

