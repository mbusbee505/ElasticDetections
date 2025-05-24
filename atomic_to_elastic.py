import requests
import yaml
import uuid
import toml
import re
import os
# It's assumed 'mitre' is a custom or third-party module.
# If it's part of this project, ensure it's accessible.
# If it's a pip-installable library, ensure it's installed.
# Example: from mitre_attack.attack_to_sqlite import MitreAttackData
try:
    import mitre # Placeholder, replace with actual import if different
except ImportError:
    print("Warning: 'mitre' module not found. Tactic/Technique mapping might fail.")
    # Define dummy functions if mitre module is essential and not found,
    # or handle its absence gracefully.
    class mitre:
        @staticmethod
        def get_tactics(technique_id):
            print(f"Warning: mitre.get_tactics called with {technique_id} but module not loaded.")
            return [] # Return empty list or mock data
        @staticmethod
        def map_tactic_to_id(tactic_name):
            print(f"Warning: mitre.map_tactic_to_id called with {tactic_name} but module not loaded.")
            return None # Return None or mock data

DEFAULT_AUTHOR = ["AtomicRedTeam-Automation"]
DEFAULT_FROM = "now-9m"
DEFAULT_INDICES = ["logs-endpoint.events.*", "winlogbeat-*", "logs-windows.*", "logs-linux.*", "logs-macos.*"]
DEFAULT_RISK_SCORE = 50
DEFAULT_SEVERITY = "medium"
ATOMIC_REPO_BASE_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/refs/heads/master/atomics/"
MITRE_TECHNIQUE_BASE_URL = "https://attack.mitre.org/techniques/"
MITRE_TACTIC_BASE_URL = "https://attack.mitre.org/tactics/"

def create_detection_rule_toml_for_test(atomic_data, test_data):
    """
    Creates a TOML string for a detection rule based on Atomic Red Team test data.
    The technique information is generated once, and all associated tactics are listed under it.
    """
    if not atomic_data or not test_data:
        print("Error: atomic_data or test_data is missing.")
        return None

    technique_id = atomic_data.get('attack_technique', 'T0000')
    # Technique's display name from the atomic data
    display_name = atomic_data.get('display_name', 'Unnamed Atomic Collection')

    test_name = test_data.get('name', f"Test for {technique_id}")
    test_guid = test_data.get('auto_generated_guid', str(uuid.uuid4())[:8])
    test_description = test_data.get('description', '').strip()
    # Platforms from test_data, fallback to atomic_data, then to 'unknown'
    platforms = test_data.get('supported_platforms', atomic_data.get('supported_platforms', ['unknown']))
    input_arguments = test_data.get('input_arguments', {})

    command_to_detect = ""
    executor_name = ""

    executor_info = test_data.get('executor')
    if executor_info:
        command_to_detect = executor_info.get('command', '')
        executor_name = executor_info.get('name', '')
        # Handle API based tests where commands are in 'steps'
        if not command_to_detect and executor_info.get('steps'):
            command_to_detect = executor_info.get('steps')
    else:
        executor_name = "unknown_executor"
        command_to_detect = "echo 'No command or steps found in this specific test structure'"

    # If command_to_detect is a list (e.g., from 'steps'), join into a string
    if isinstance(command_to_detect, list):
        command_to_detect = "; ".join(command_to_detect)

    kql_query = generate_kql_from_command(command_to_detect, executor_name, input_arguments)
    atomic_yaml_suffix = f"{technique_id}/{technique_id}.yaml"

    rule_name = f"Atomic Test: {technique_id} - {test_name}"
    rule_description = (
        f"Detection for specific test '{test_name}' (GUID: {test_guid}) "
        f"of technique {technique_id} ({display_name})."
    )
    if test_description:
        rule_description += f" Test Description: {test_description}."

    # Truncate command/steps for brevity in description
    command_snippet = command_to_detect[:150]
    if len(command_to_detect) > 150:
        command_snippet += "..."
    rule_description += f" Command/Steps: {command_snippet}"

    # Define common technique information. This will become [[rule.threat.technique]]
    technique_reference_id = technique_id.split('.')[0] # For T1234.001, use T1234
    sub_technique_id = technique_id.split('.')[1] if '.' in technique_id else None
    technique_ref_url_part = f"{technique_reference_id}"
    if sub_technique_id:
        technique_ref_url_part += f"/{sub_technique_id}"

    # technique_info_list will result in an array of tables for technique, even if it's one.
    technique_info_list = [
        {
            'id': technique_id,
            'name': display_name, # Use the technique's display name
            'reference': f"{MITRE_TECHNIQUE_BASE_URL}{technique_ref_url_part}"
        }
    ]

    # Base structure for the rule
    rule = {
        'rule': {
            'author': DEFAULT_AUTHOR,
            'description': rule_description,
            'from': DEFAULT_FROM,
            'rule_id': str(uuid.uuid4()),
            'language': 'kql',
            'name': rule_name,
            'output_index': '.siem-signals-default', # Common output index
            'references': [f"{ATOMIC_REPO_BASE_URL}{atomic_yaml_suffix}"],
            'risk_score': DEFAULT_RISK_SCORE,
            'severity': DEFAULT_SEVERITY,
            'tags': ["AtomicRedTeam", technique_id, test_guid] + platforms,
            'type': 'query',
            'query': kql_query if kql_query else "process.command_line : \"*fallback_query_due_to_empty_kql*\"", # Ensure query is not empty
            'threat': [], # Initialize 'threat' as an empty list. It will hold one threat object.
            'version': 1,
        }
    }

    # Add 'index' field if KQL query is generated
    if kql_query:
        rule['rule']['index'] = DEFAULT_INDICES

    # Prepare list for all tactics associated with this technique
    processed_tactics_list = []
    tactics_names = mitre.get_tactics(technique_id) # Assumes this returns a list of tactic names

    if tactics_names:
        for tactic_str_name in tactics_names: # e.g., "defense-evasion"
            tactic_id_val = mitre.map_tactic_to_id(tactic_str_name) # e.g., "TA0005"
            if tactic_id_val:
                tactic_info = {
                    'id': tactic_id_val,
                    'name': tactic_str_name.replace("-", " ").title(), # Format name
                    'reference': f"{MITRE_TACTIC_BASE_URL}{tactic_id_val}/"
                }
                processed_tactics_list.append(tactic_info)
            else:
                print(f"Warning: Could not map tactic name '{tactic_str_name}' to an ID for technique '{technique_id}'.")

    # Create the single threat object that includes the one technique and all its tactics
    main_threat_object = {
        'framework': 'MITRE ATT&CK',
        'technique': technique_info_list # This will be [[rule.threat.technique]]
    }

    if processed_tactics_list: # Only add the 'tactic' key if there are tactics
        main_threat_object['tactic'] = processed_tactics_list # This will be [[rule.threat.tactic]]

    # Add the single, comprehensive threat object to the rule's threat list
    rule['rule']['threat'].append(main_threat_object)

    try:
        return toml.dumps(rule)
    except Exception as e:
        print(f"Error dumping TOML for rule '{rule_name}': {e}")
        return None

def generate_kql_from_command(command, executor_name, input_arguments):
    """
    Generates a KQL query string based on command, executor, and arguments.
    This is a simplified KQL generator.
    """
    if not command:
        return "" # Return empty if no command

    processed_command = command.strip()
    # Substitute input argument placeholders with their default values or wildcards
    for arg_name, arg_details in input_arguments.items():
        placeholder = f"#{{{arg_name}}}"
        # Use default value if provided, otherwise use a wildcard or skip
        default_value = arg_details.get("default", "*") # Default to wildcard if not specified
        processed_command = processed_command.replace(placeholder, str(default_value) if default_value is not None else "*")

    # Basic keyword extraction (very naive)
    # Remove common command prefixes, split by non-alphanumeric, filter short/common words
    raw_keywords = re.split(r'[\s\\/=\(\)\[\]\{\};:"\',]+', processed_command)
    common_words = {
        "the", "and", "for", "with", "is", "are", "of", "to", "in", "on", "at",
        "a", "an", "cmd", "exe", "bin", "sh", "tmp", "log", "mnt", "true", "false",
        "echo", "set", "new", "get", "sudo", "powershell", "c", "users", "appdata",
        "local", "temp", "program", "files", "windows", "system32"
    }
    keywords = [
        kw.strip('*') for kw in raw_keywords
        if len(kw.strip('*')) > 2 and kw.lower() not in common_words and not kw.isdigit()
    ]
    # Keep unique keywords while preserving order of first appearance, then sort for consistency
    keywords = sorted(list(dict.fromkeys(keywords)), key=lambda x: x.lower())


    query_parts = []
    executor_name_lower = executor_name.lower() if executor_name else ""

    # Tailor query based on executor
    if "powershell" in executor_name_lower:
        query_parts.append(
            '(process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") OR process.parent.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe"))'
        )
        if keywords:
            # Search in script block text OR command line for PowerShell
            script_block_conditions = " AND ".join([f'powershell.script_block_text : "*{k}*"' for k in keywords[:3]]) # Limit to 3 keywords
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
            '(process.name : ("sh", "bash", "zsh", "ksh") OR process.parent.name : ("sh", "bash", "zsh", "ksh"))'
        )
        if keywords:
            command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords[:3]])
            query_parts.append(command_line_conditions)
    else: # Generic case
        if keywords:
            command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords[:3]])
            query_parts.append(command_line_conditions)

    # Fallback if no specific executor logic applied but keywords exist
    if not query_parts and keywords:
        command_line_conditions = " AND ".join([f'process.command_line : "*{k}*"' for k in keywords[:3]])
        query_parts.append(command_line_conditions)
    
    # If still no query parts, use a snippet of the processed command as a last resort
    if not query_parts:
        # Sanitize snippet for KQL: escape backslashes, quotes, colons
        sanitized_command_snippet = processed_command.replace('\\', '\\\\').replace('"', '\\"').replace(":", "\\:").replace("'", "\\'")[:60]
        if sanitized_command_snippet: # Ensure snippet is not empty
             return f'process.command_line : "*{sanitized_command_snippet}*"'
        else:
            return "" # Return empty if command was empty or only contained placeholders

    return " AND ".join(query_parts)

def generate_toml_for_technique(technique_id):
    """
    Fetches Atomic YAML for a technique and generates TOML for each test.
    Returns a list of tuples: (toml_output, output_filename).
    """
    if not technique_id:
        print("Error: No technique ID provided to generate_toml_for_technique.")
        return []

    # Construct URL for the specific technique's YAML file
    url = f"{ATOMIC_REPO_BASE_URL}{technique_id}/{technique_id}.yaml"
    print(f"Fetching Atomic YAML from: {url}")

    try:
        response = requests.get(url, timeout=10) # Added timeout
        response.raise_for_status() # Raises HTTPError for bad responses (4XX or 5XX)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching YAML file {url}: {e}")
        return []

    try:
        atomic_data = yaml.safe_load(response.text)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file {url}: {e}")
        return []

    if not atomic_data or not atomic_data.get('atomic_tests'):
        print(f"No 'atomic_tests' found or data is invalid in {url}")
        return []
    
    atomic_tests = atomic_data.get('atomic_tests', [])
    generated_rules = []

    for test_index, test_data in enumerate(atomic_tests):
        if not test_data: # Skip if test_data is None or empty
            print(f"Warning: Empty test data at index {test_index} for technique {technique_id}.")
            continue

        toml_output = create_detection_rule_toml_for_test(atomic_data, test_data)

        if toml_output:
            # Sanitize technique_id and test_name for filename
            technique_id_for_file = technique_id.replace('.', '_')
            # Use test GUID if name is missing, ensure it's a string
            test_name_fallback = f"Test_{test_data.get('auto_generated_guid', f'UnknownTest_{test_index}')}"
            test_name_for_file = re.sub(r'[^a-zA-Z0-9_-]', '_', test_data.get('name', test_name_fallback)[:50])
            
            output_filename = f"{technique_id_for_file}_{test_name_for_file}.toml"
            # Further sanitize filename (though re.sub above handles most)
            output_filename = output_filename.replace(os.sep, "_").replace("/", "_").replace("\\", "_")
            
            generated_rules.append((toml_output, output_filename))
        else:
            print(f"Warning: Failed to generate TOML for a test in {technique_id}.")
            
    return generated_rules

# Example usage (optional, for testing this script directly)
if __name__ == '__main__':
    # Make sure the 'mitre' module is correctly set up if you run this directly.
    # For example, if 'mitre' is a local directory/file, ensure Python can find it.
    # You might need to adjust sys.path or install it if it's a package.

    # Test with a specific technique ID
    # example_technique = 'T1059.001' # PowerShell
    example_technique = 'T1003.001' # LSASS Memory
    # example_technique = 'T1071.001' # Web Protocols - often has multiple tactics
    
    print(f"Attempting to generate rules for technique: {example_technique}")
    rules = generate_toml_for_technique(example_technique)

    if rules:
        print(f"\nSuccessfully generated {len(rules)} rule(s) for {example_technique}:")
        for rule_toml, filename in rules:
            print(f"\n--- Filename: {filename} ---")
            print(rule_toml)
            # Optionally, save to file
            # with open(filename, 'w') as f:
            #     f.write(rule_toml)
            # print(f"Saved to {filename}")
    else:
        print(f"No rules generated for technique {example_technique}.")

