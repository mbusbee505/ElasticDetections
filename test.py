import mitre
from atomics import get_atomics
from atomic_to_elastic import generate_toml_for_technique
import os
# import validate # Keep this line if validate.py is still used elsewhere, or remove if not.
from validate_rule import validate_rule_toml # Import the new validation function

def gather_atomic_tomls():
    techniques = get_atomics()
    for technique in techniques:
        # tactic = mitre.get_tactics(technique) # tactic variable is not used
        toml_result = generate_toml_for_technique(technique)
        # print(toml_result)
        for t in toml_result:
            os.makedirs(f"atomics/{technique}", exist_ok=True)
            with open(f"atomics/{technique}/{t[1]}", "w", encoding="utf-8") as f:
                f.write(t[0])
        

def validate_tomls():
    print("\nStarting TOML validation...")
    all_files_valid = True
    for root, dirs, files in os.walk("atomics"):
        for file in files:
            if file.endswith(".toml"):
                toml_file_path = os.path.join(root, file)
                print(f"\nValidating {toml_file_path}...")
                validation_errors = validate_rule_toml(toml_file_path)
                if validation_errors:
                    all_files_valid = False
                    print(f"Validation Failed for {toml_file_path}:")
                    for error in validation_errors:
                        print(f"  - {error}")
                else:
                    print(f"Validation Successful for {toml_file_path}.")
    
    if all_files_valid:
        print("\nAll TOML files passed validation.")
    else:
        print("\nSome TOML files failed validation.")


def main():
    # gather_atomic_tomls()
    validate_tomls() # Uncommented to run the validation

if __name__ == "__main__":
    main()
