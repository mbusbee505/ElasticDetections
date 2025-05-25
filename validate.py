import tomllib
import sys

def contains_missing_fields(toml_path):
    try:
        with open(toml_path, "rb") as toml_file:
            rule = tomllib.load(toml_file)

        # required_fields = ["description", "name", "risk_score", "severity", "type", "query"]
        present_fields = []
        missing_fields = []

        if rule["rule"]["type"] == "query":
            required_fields = ["description", "name", "risk_score", "severity", "type", "query"]
        elif rule["rule"]["type"] == "eql":
            required_fields = ["description", "name", "risk_score", "severity", "type", "query", "language"]
        elif rule["rule"]["type"] == "threshold":
            required_fields = ["description", "name", "risk_score", "severity", "type", "query", "threshold"]
        else:
            required_fields = ["description", "name", "risk_score", "severity", "type"]

        for table in rule:
            for field in rule[table]:
                present_fields.append(field)

        for field in required_fields:   
            if field not in present_fields:
                missing_fields.append(field)
        
        if missing_fields:
            return True
        else:
            return False
    except tomllib.TOMLDecodeError as e:
        print(f"Error decoding TOML file: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python validate.py <path_to_toml_file>")
        sys.exit(1)

    toml_path = sys.argv[1]
    if not validate_toml(toml_path):
        sys.exit(1)

if __name__ == "__main__":
    main()