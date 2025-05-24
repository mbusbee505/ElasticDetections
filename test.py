import mitre
from atomics import get_atomics
from atomic_to_elastic import generate_toml
import os


def main():
    techniques = get_atomics()
    for technique in techniques:
        tactic = mitre.get_tactics(technique)
        # print(f"{technique} - {tactic}")
        toml_result = generate_toml(technique)
        for toml_output_tuple in toml_result:
            os.makedirs(f"atomics/{technique}", exist_ok=True)
            with open(f"atomics/{technique}/{toml_output_tuple[1]}", "w", encoding='utf-8') as f:
                f.write(toml_output_tuple[0])    
        
        

if __name__ == "__main__":
    main()
