import tomllib
import sys
import re
import uuid

# --- Constants for Validation ---
EXPECTED_RULE_TYPE_VALUES = ["query", "eql", "threshold", "threat_match"]
EXPECTED_SEVERITY_VALUES = ["informational", "low", "medium", "high", "critical"]
EXPECTED_RISK_SCORE_MIN = 0
EXPECTED_RISK_SCORE_MAX = 100
EXPECTED_MITRE_FRAMEWORK = "MITRE ATT&CK"
MITRE_TACTIC_REGEX = re.compile(r"^TA\\d{4}$")
MITRE_TECHNIQUE_REGEX = re.compile(r"^T\\d{4}(\\.\\d{3})?$")
# Basic URL regex (simplified)
URL_REGEX = re.compile(
    r'^(?:http|ftp)s?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\\.)+(?:[A-Z]{2,6}\\.?|[A-Z0-9-]{2,}\\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})'  # ...or ip
    r'(?::\\d+)?'  # optional port
    r'(?:/?|[/?]\\S+)$', re.IGNORECASE)

# --- Helper Functions ---

def is_valid_uuid(val):
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False

def validate_field_present(data, field_path, errors_list):
    """Checks if a nested field is present in the data."""
    keys = field_path.split('.')
    current_data = data
    for key in keys:
        if isinstance(current_data, dict) and key in current_data:
            current_data = current_data[key]
        elif isinstance(current_data, list) and key.isdigit() and int(key) < len(current_data):
            current_data = current_data[int(key)]
        else:
            errors_list.append(f"Missing required field: '{field_path}'")
            return False
    return True

def validate_field_type(data, field_path, expected_type, errors_list):
    """Checks if a nested field has the expected type."""
    keys = field_path.split('.')
    current_data = data
    for i, key in enumerate(keys):
        if isinstance(current_data, dict) and key in current_data:
            if i == len(keys) - 1: # Last key
                if not isinstance(current_data[key], expected_type):
                    errors_list.append(f"Field '{field_path}' has incorrect type. Expected {expected_type}, got {type(current_data[key])}.")
                    return False
            current_data = current_data[key]
        elif isinstance(current_data, list) and key.isdigit():
            idx = int(key)
            if idx < len(current_data):
                if i == len(keys) - 1: # Last key
                     if not isinstance(current_data[idx], expected_type):
                        errors_list.append(f"Field '{field_path}' has incorrect type. Expected {expected_type}, got {type(current_data[idx])}.")
                        return False
                current_data = current_data[idx]
            else:
                # errors_list.append(f"Field '{field_path}' not found (index out of bounds).") # Covered by validate_field_present
                return False
        else:
            # errors_list.append(f"Field '{field_path}' not found.") # Covered by validate_field_present
            return False
    return True

def get_field_value(data, field_path, default=None):
    keys = field_path.split('.')
    current_data = data
    for key in keys:
        if isinstance(current_data, dict) and key in current_data:
            current_data = current_data[key]
        elif isinstance(current_data, list) and key.isdigit() and int(key) < len(current_data):
            current_data = current_data[int(key)]
        else:
            return default
    return current_data

# --- Main Validation Function ---

def validate_rule_toml(toml_path):
    errors = []
    try:
        with open(toml_path, "rb") as toml_file:
            try:
                rule_data = tomllib.load(toml_file)
            except tomllib.TOMLDecodeError as e:
                errors.append(f"Invalid TOML format: {e}")
                return errors
    except FileNotFoundError:
        errors.append(f"File not found: {toml_path}")
        return errors
    except Exception as e:
        errors.append(f"Could not read file: {e}")
        return errors

    # Rule level validation
    if not validate_field_present(rule_data, "rule", errors):
        return errors # Stop if basic rule structure is missing

    rule_block = rule_data["rule"]

    # Required fields at [rule] level
    required_rule_fields = [
        "rule_id", "author", "description", "name", "risk_score",
        "severity", "type", "from", "interval", "version"
        # "output_index" # Often optional or defaults
        # "references" # Recommended but can be empty list
        # "tags" # Recommended
    ]
    for field in required_rule_fields:
        if validate_field_present(rule_block, field, errors):
            if field == "rule_id":
                val = get_field_value(rule_block, field)
                if not is_valid_uuid(val):
                    errors.append(f"Field 'rule.rule_id' is not a valid UUID: {val}")
            elif field == "author":
                validate_field_type(rule_block, field, list, errors)
                # Could also check if list is not empty and contains strings
            elif field == "description":
                validate_field_type(rule_block, field, str, errors)
            elif field == "name":
                validate_field_type(rule_block, field, str, errors)
            elif field == "risk_score":
                validate_field_type(rule_block, field, int, errors)
                val = get_field_value(rule_block, field)
                if isinstance(val, int) and not (EXPECTED_RISK_SCORE_MIN <= val <= EXPECTED_RISK_SCORE_MAX):
                    errors.append(f"Field 'rule.risk_score' ({val}) out of range [{EXPECTED_RISK_SCORE_MIN}-{EXPECTED_RISK_SCORE_MAX}].")
            elif field == "severity":
                validate_field_type(rule_block, field, str, errors)
                val = get_field_value(rule_block, field)
                if isinstance(val, str) and val not in EXPECTED_SEVERITY_VALUES:
                    errors.append(f"Field 'rule.severity' ('{val}') is not one of {EXPECTED_SEVERITY_VALUES}.")
            elif field == "type":
                validate_field_type(rule_block, field, str, errors)
                val = get_field_value(rule_block, field)
                if isinstance(val, str) and val not in EXPECTED_RULE_TYPE_VALUES:
                    errors.append(f"Field 'rule.type' ('{val}') is not one of {EXPECTED_RULE_TYPE_VALUES}.")
            elif field == "from" or field == "interval": # Basic check, regex could be more robust
                 validate_field_type(rule_block, field, str, errors)
                 val = get_field_value(rule_block, field)
                 if isinstance(val, str) and not re.match(r"^(now|[\d]+[smhdMy])([\-\+][\d]+[smhdMy])?$", val.replace(" ","")): # Simple check for "now", "1m", "now-1d"
                     errors.append(f"Field 'rule.{field}' ('{val}') has an invalid time format.")
            elif field == "version":
                validate_field_type(rule_block, field, int, errors)


    # Optional but recommended fields
    if validate_field_present(rule_block, "references", errors):
        validate_field_type(rule_block, "references", list, errors)
        refs = get_field_value(rule_block, "references", [])
        for i, ref in enumerate(refs):
            if not isinstance(ref, str):
                errors.append(f"Field 'rule.references[{i}]' is not a string.")
            elif not URL_REGEX.match(ref):
                errors.append(f"Field 'rule.references[{i}]' ('{ref}') is not a valid URL.")

    if validate_field_present(rule_block, "tags", errors):
        validate_field_type(rule_block, "tags", list, errors)
        tags = get_field_value(rule_block, "tags", [])
        for i, tag in enumerate(tags):
            if not isinstance(tag, str):
                errors.append(f"Field 'rule.tags[{i}]' is not a string.")
            # Could add regex for tag format e.g. MITRE ones

    # Threat intelligence section validation `[[rule.threat]]`
    if validate_field_present(rule_block, "threat", errors):
        validate_field_type(rule_block, "threat", list, errors)
        threats = get_field_value(rule_block, "threat", [])
        if not threats:
            errors.append("Field 'rule.threat' should not be an empty list if present.")

        for i, threat_item in enumerate(threats):
            path_prefix = f"threat.{i}"
            if not isinstance(threat_item, dict):
                errors.append(f"Item 'rule.{path_prefix}' is not a dictionary.")
                continue

            if validate_field_present(threat_item, "framework", errors):
                 framework = get_field_value(threat_item, "framework")
                 if framework != EXPECTED_MITRE_FRAMEWORK:
                     errors.append(f"Field 'rule.{path_prefix}.framework' ('{framework}') is not '{EXPECTED_MITRE_FRAMEWORK}'.")

            # Tactic validation
            if validate_field_present(threat_item, "tactic", errors): # Note: ES schema shows tactic as an object, not list of objects.
                                                                    # but many examples show it as list. Adapting to common usage of single object.
                                                                    # If it is a list, this needs a loop.
                validate_field_type(threat_item, "tactic", dict, errors) # Assuming single object
                tactic_path = f"{path_prefix}.tactic"
                tactic_obj = get_field_value(threat_item, "tactic")
                if tactic_obj: # Check if tactic object itself is not None
                    for req_field in ["id", "name", "reference"]:
                        if validate_field_present(tactic_obj, req_field, errors):
                             validate_field_type(tactic_obj, req_field, str, errors)
                             if req_field == "id" and not MITRE_TACTIC_REGEX.match(get_field_value(tactic_obj, "id", "")):
                                 errors.append(f"'rule.{tactic_path}.id' ('{get_field_value(tactic_obj, 'id')}') is not a valid MITRE Tactic ID.")
                             elif req_field == "reference" and not URL_REGEX.match(get_field_value(tactic_obj, "reference", "")):
                                 errors.append(f"'rule.{tactic_path}.reference' ('{get_field_value(tactic_obj, 'reference')}') is not a valid URL.")

            # Technique validation (list of techniques)
            if validate_field_present(threat_item, "technique", errors):
                validate_field_type(threat_item, "technique", list, errors)
                techniques = get_field_value(threat_item, "technique", [])
                if not techniques:
                     errors.append(f"Field 'rule.{path_prefix}.technique' should not be an empty list if present.")

                for j, tech_item in enumerate(techniques):
                    tech_path = f"{path_prefix}.technique.{j}"
                    if not isinstance(tech_item, dict):
                        errors.append(f"Item 'rule.{tech_path}' is not a dictionary.")
                        continue
                    for req_field in ["id", "name", "reference"]:
                         if validate_field_present(tech_item, req_field, errors):
                            validate_field_type(tech_item, req_field, str, errors)
                            if req_field == "id" and not MITRE_TECHNIQUE_REGEX.match(get_field_value(tech_item, "id", "")):
                                errors.append(f"'rule.{tech_path}.id' ('{get_field_value(tech_item, 'id')}') is not a valid MITRE Technique ID.")
                            elif req_field == "reference" and not URL_REGEX.match(get_field_value(tech_item, "reference", "")):
                                errors.append(f"'rule.{tech_path}.reference' ('{get_field_value(tech_item, 'reference')}') is not a valid URL.")
                    # Sub-techniques (optional array within a technique)
                    if "subtechnique" in tech_item:
                        validate_field_type(tech_item, "subtechnique", list, errors)
                        subtechniques = get_field_value(tech_item, "subtechnique", [])
                        for k, subtech_item in enumerate(subtechniques):
                            subtech_path = f"{tech_path}.subtechnique.{k}"
                            if not isinstance(subtech_item, dict):
                                errors.append(f"Item 'rule.{subtech_path}' is not a dictionary.")
                                continue
                            for req_sub_field in ["id", "name", "reference"]:
                                if validate_field_present(subtech_item, req_sub_field, errors):
                                    validate_field_type(subtech_item, req_sub_field, str, errors)
                                    if req_sub_field == "id" and not MITRE_TECHNIQUE_REGEX.match(get_field_value(subtech_item, "id","")): # Sub-technique ID uses same format
                                        errors.append(f"'rule.{subtech_path}.id' ('{get_field_value(subtech_item, 'id')}') is not a valid MITRE Sub-Technique ID.")
                                    elif req_sub_field == "reference" and not URL_REGEX.match(get_field_value(subtech_item, "reference","")):
                                         errors.append(f"'rule.{subtech_path}.reference' ('{get_field_value(subtech_item, 'reference')}') is not a valid URL.")


    # Type-specific validations
    rule_type = get_field_value(rule_block, "type")

    if rule_type == "query":
        if validate_field_present(rule_block, "query", errors):
            validate_field_type(rule_block, "query", str, errors)
            if not get_field_value(rule_block, "query", "").strip():
                errors.append("Field 'rule.query' must not be empty for type 'query'.")
        if validate_field_present(rule_block, "index", errors): # index is common for query type
            validate_field_type(rule_block, "index", list, errors)
            indices = get_field_value(rule_block, "index", [])
            if not indices:
                errors.append("Field 'rule.index' should not be empty if present for type 'query'.")
            for i, idx_pattern in enumerate(indices):
                if not isinstance(idx_pattern, str):
                    errors.append(f"Field 'rule.index[{i}]' is not a string.")
                elif not idx_pattern.strip():
                    errors.append(f"Field 'rule.index[{i}]' should not be an empty string.")


    elif rule_type == "eql":
        if validate_field_present(rule_block, "query", errors):
            validate_field_type(rule_block, "query", str, errors)
            if not get_field_value(rule_block, "query", "").strip():
                errors.append("Field 'rule.query' must not be empty for type 'eql'.")
        if validate_field_present(rule_block, "language", errors):
            validate_field_type(rule_block, "language", str, errors)
            lang = get_field_value(rule_block, "language")
            if lang != "eql":
                errors.append(f"Field 'rule.language' must be 'eql' for type 'eql', got '{lang}'.")
        else: # language is mandatory for eql
            errors.append("Missing required field: 'rule.language' for type 'eql'.")

    elif rule_type == "threshold":
        if validate_field_present(rule_block, "query", errors):
             validate_field_type(rule_block, "query", str, errors)
             if not get_field_value(rule_block, "query", "").strip():
                errors.append("Field 'rule.query' must not be empty for type 'threshold'.")
        if validate_field_present(rule_block, "threshold", errors):
            validate_field_type(rule_block, "threshold", dict, errors)
            threshold_block = get_field_value(rule_block, "threshold")
            if threshold_block:
                if validate_field_present(threshold_block, "field", errors):
                    validate_field_type(threshold_block, "field", str, errors) # Can also be a list of strings
                if validate_field_present(threshold_block, "value", errors):
                    validate_field_type(threshold_block, "value", int, errors) # Or float
        else:
            errors.append("Missing required field: 'rule.threshold' for type 'threshold'.")

    # Add more type-specific checks like for 'threat_match' if needed

    return errors

def main():
    if len(sys.argv) != 2:
        print("Usage: python validate_rule.py <path_to_toml_file>")
        sys.exit(1)

    toml_path = sys.argv[1]
    validation_errors = validate_rule_toml(toml_path)

    if validation_errors:
        print(f"Validation Failed for {toml_path}:")
        for error in validation_errors:
            print(f"  - {error}")
        sys.exit(1)
    else:
        print(f"Validation Successful for {toml_path}!")
        sys.exit(0)

if __name__ == "__main__":
    main() 