import yaml
import json
import sys

def load_asset_types(yaml_path):
    with open(yaml_path, 'r') as f:
        return yaml.safe_load(f)

def validate_asset(asset, asset_types):
    asset_type = asset.get('type')
    provider = asset.get('provider')
    subtype = asset.get('subtype')

    for t in asset_types:
        if t['type'] == asset_type:
            if asset_type == 'Cloud Resource':
                if not provider:
                    return False, "Missing provider for Cloud Resource"
                for p in t['providers']:
                    if p['provider'] == provider:
                        if subtype and subtype not in p['permitted_values']:
                            return False, f"Invalid subtype '{subtype}' for provider '{provider}'"
                        return True, "Valid asset"
                return False, f"Invalid provider '{provider}' for Cloud Resource"
            else:
                if subtype and subtype not in t['permitted_values']:
                    return False, f"Invalid subtype '{subtype}' for type '{asset_type}'"
                return True, "Valid asset"
    return False, f"Invalid asset type '{asset_type}'"

if __name__ == "__main__":
    # Example usage: python validate_asset_type.py asset.json asset_types.yaml
    if len(sys.argv) != 3:
        print("Usage: python validate_asset_type.py <asset.json> <asset_types.yaml>")
        sys.exit(1)
    asset_file = sys.argv[1]
    types_file = sys.argv[2]
    with open(asset_file, 'r') as f:
        asset = json.load(f)
    asset_types = load_asset_types(types_file)
    valid, message = validate_asset(asset, asset_types)
    if valid:
        print("✅", message)
        sys.exit(0)
    else:
        print("❌", message)
        sys.exit(1) 