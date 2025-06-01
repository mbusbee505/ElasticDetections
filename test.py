import mitre
from atomics import get_atomic_techniques
from atomic_to_elastic import generate_tomls_for_technique
import os
import validate
from upload_to_elastic import upload_toml
def gather_atomic_tomls():
    techniques = get_atomic_techniques()
    for technique in techniques:
        tactic = mitre.get_tactics(technique)
        toml_result = generate_tomls_for_technique(technique)
        
        # Only check if result is not None to prevent iteration error
        if toml_result is not None:
            for t in toml_result:   
                os.makedirs(f"atomics/{technique}", exist_ok=True)
                with open(f"atomics/{technique}/{t[1]}", "w", encoding="utf-8") as f:
                    f.write(t[0])
        

def validate_tomls():
    for root, dirs, files in os.walk("atomics"):
        for file in files:
            if file.endswith(".toml"):
                missing_fields = validate.contains_missing_fields(os.path.join(root, file))
                print(f"{file} missing fields: {missing_fields}")
                

def main():
    # gather_atomic_tomls()
    # validate_tomls()
    upload_toml("atomics/T1003/T1003_Credential_Dumping_with_NPPSpy.toml")
if __name__ == "__main__":
    main()
