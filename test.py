import mitre
from atomics import get_atomics
from atomic_to_elastic import generate_toml




def main():
    techniques = get_atomics()
    for technique in techniques:
        tactic = mitre.get_tactics(technique)
        toml_result = generate_toml(technique)
        # print(toml_result)
        break

if __name__ == "__main__":
    main()
