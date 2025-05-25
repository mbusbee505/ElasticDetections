# Elastic Detections from Atomic Red Team

This project provides scripts to fetch Atomic Red Team techniques and generate corresponding detection rule TOML files compatible with Elastic Security. It also includes a validation script to ensure the generated TOML files adhere to the required format and content.

## Prerequisites

- Python 3.x
- `requests` library (`pip install requests`)
- `PyYAML` library (`pip install pyyaml`)
- `tomli` or `tomllib` (for Python < 3.11 or >= 3.11 respectively, for TOML parsing in the validation script)

## How to Use

The main entry point for using the scripts is `test.py`.

### 1. Fetching Atomic Red Team Data and Generating TOML Rules

This process downloads the YAML definitions for Atomic Red Team techniques and converts each atomic test into a separate TOML rule file.

**Steps:**

1.  Ensure your Python environment has the necessary libraries installed (see Prerequisites).
2.  Modify the `test.py` script if needed. By default, the `main` function is configured to first gather atomics and then validate them.
    ```python
    def main():
        gather_atomic_tomls() # Fetches atomics and generates TOML files
        validate_tomls()      # Validates the generated TOML files
    ```
3.  Run the `test.py` script:
    ```bash
    python test.py
    ```
4.  The script will:
    *   Fetch a list of all Atomic Red Team techniques.
    *   For each technique, download its YAML definition from the official Red Canary GitHub repository.
    *   Parse the YAML and, for each atomic test defined, generate a detection rule in TOML format.
    *   Save the generated TOML files into an `atomics/` directory, with subdirectories named after the technique ID (e.g., `atomics/T1059.001/`).
    *   The filenames for the TOML rules will be in the format `{TechniqueID}_{TestName}.toml`.

### 2. Validating Generated TOML Rule Files

After generating the TOML files, or if you have existing TOML rule files you wish to check, you can use the validation functionality. The validation script (`validate_rule.py`) is called by `test.py` to check all generated files.

**How Validation Works:**

The `test.py` script, through its `validate_tomls()` function, will automatically scan all `.toml` files within the `atomics/` directory and its subdirectories. It uses the `validate_rule_toml()` function from `validate_rule.py`.

**Manual Validation (Optional):**

If you wish to validate a single TOML file or integrate the validation into a different workflow, you can run `validate_rule.py` directly:

```bash
python validate_rule.py path/to/your/rule.toml
```

**What is Checked During Validation?**

The validation script performs a comprehensive check on various aspects of the TOML rule file to ensure its correctness and compatibility with Elastic Security detection rule standards. Key areas checked include:

**Rule Metadata:**
*   **Presence of Required Fields:**
    *   `rule_id` (must be a valid UUID)
    *   `author` (must be a list)
    *   `description` (must be a string)
    *   `name` (must be a string)
    *   `risk_score` (must be an integer between 0-100)
    *   `severity` (must be one of: "informational", "low", "medium", "high", "critical")
    *   `type` (must be one of: "query", "eql", "threshold", "threat_match")
    *   `from` (string, e.g., "now-5m")
    *   `interval` (string, e.g., "5m")
    *   `version` (must be an integer)
*   **Optional but Recommended Fields:**
    *   `references`: List of valid URLs.
    *   `tags`: List of strings (checks for MITRE ATT&CK tag formats like `Txxxx` or `TAxxxx`).
*   **Data Types:** Ensures all fields have the correct data type (string, integer, list, etc.).

**Threat Intelligence Section (`[[rule.threat]]`):**
*   **Framework:** Must be "MITRE ATT&CK".
*   **Tactics (`rule.threat[].tactic`):**
    *   Presence and string type for `id`, `name`, `reference`.
    *   `id` must match MITRE Tactic format (e.g., `TA0002`).
    *   `reference` must be a valid URL.
*   **Techniques (`rule.threat[].technique[]`):**
    *   Presence and string type for `id`, `name`, `reference`.
    *   `id` must match MITRE Technique format (e.g., `T1059.001`).
    *   `reference` must be a valid URL.
*   **Sub-techniques (`rule.threat[].technique[].subtechnique[]`):** (If present)
    *   Similar checks as for techniques (ID, name, reference, URL format).

**Query/Logic Section (Varies by `rule.type`):**
*   **For `type: "query"`:**
    *   `query` field must be present, a non-empty string.
    *   `index` field (if present) must be a non-empty list of non-empty strings.
*   **For `type: "eql"`:**
    *   `query` field must be present, a non-empty string.
    *   `language` field must be present and set to "eql".
*   **For `type: "threshold"`:**
    *   `query` field must be present, a non-empty string.
    *   `threshold` block must be present with `field` (string) and `value` (integer/float).

**General TOML Structure:**
*   Valid TOML syntax.
*   No unexpected or misplaced fields according to the general structure of an Elastic detection rule.

**Output:**
The validation script will print "Validation Successful" for each valid file or list specific errors found for files that fail validation. At the end, `test.py` will summarize if all files passed or if some failed.

## Project Structure

- `test.py`: Main script to orchestrate fetching atomics and validating rules.
- `atomics.py`: Contains logic to fetch Atomic Red Team technique lists.
- `atomic_to_elastic.py`: Handles fetching individual atomic technique YAML, parsing it, and generating TOML rule content.
- `validate_rule.py`: Contains the comprehensive validation logic for individual TOML rule files.
- `mitre.py`: (Assumed utility for MITRE ATT&CK lookups, e.g., tactics).
- `atomics/`: Directory where generated TOML rule files are stored.

## Contributing

Feel free to contribute by improving the scripts, adding more robust validation checks, or enhancing the documentation. 