import mitre
from atomics import get_atomics
from atomic_to_elastic import generate_toml_for_technique
import os



def main():
    techniques = get_atomics()
    for technique in techniques:
        tactic = mitre.get_tactics(technique)
        toml_result = generate_toml_for_technique(technique)
        # print(toml_result)
        for t in toml_result:
            os.makedirs(f"atomics/{technique}", exist_ok=True)
            with open(f"atomics/{technique}/{t[1]}", "w") as f:
                f.write(t[0])
        break

if __name__ == "__main__":
    main()
