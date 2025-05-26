import argparse
import json
import sys
from jsonschema import validate, ValidationError


def main():
    parser = argparse.ArgumentParser(
        description="Validate a JSON file against a schema (input or output)."
    )
    parser.add_argument('--file', required=True, help='Path to the JSON file to validate')
    parser.add_argument('--schema', required=True, help='Path to the schema file (input or output)')
    parser.add_argument('--flag', required=True, choices=['input-schema', 'output-schema'], help='Specify which schema is being used')
    args = parser.parse_args()

    # Load the JSON file
    try:
        with open(args.file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        sys.exit(1)

    # Load the schema
    try:
        with open(args.schema, 'r') as f:
            schema = json.load(f)
    except Exception as e:
        print(f"Error loading schema file: {e}")
        sys.exit(1)

    # Validate
    try:
        validate(instance=data, schema=schema)
        print(f"✅ The file '{args.file}' is valid against the {args.flag}.")
    except ValidationError as ve:
        print(f"❌ Validation failed for '{args.file}' against the {args.flag}:")
        print(ve)
        sys.exit(2)

if __name__ == "__main__":
    main() 