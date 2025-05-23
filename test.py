import mitre
from atomics import get_atomics
from atomic_to_elastic_TOML import generate_rules_from_atomic_file
from atomic_to_elastic import generate_toml




def main():
    techniques = get_atomics()
    for technique in techniques:
        tactic = mitre.get_tactics(technique)
        # generate_rules_from_atomic_file(technique)
        toml_result = generate_toml(technique)
        #print(toml_result)
        break

if __name__ == "__main__":
    main()
