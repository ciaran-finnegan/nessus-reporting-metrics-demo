import os
import json
import pytest
from jsonschema import validate, ValidationError

# Load schemas once
with open(os.path.join(os.path.dirname(__file__), '..', 'schemas', 'input.schema.json')) as f:
    input_schema = json.load(f)
with open(os.path.join(os.path.dirname(__file__), '..', 'schemas', 'output.schema.json')) as f:
    output_schema = json.load(f)

def load_test_cases():
    test_dir = os.path.dirname(__file__)
    test_cases = []
    for fname in os.listdir(test_dir):
        if fname.startswith('test_') and fname.endswith('.json'):
            with open(os.path.join(test_dir, fname)) as f:
                data = json.load(f)
            test_cases.append((fname, data))
    return test_cases

test_cases = load_test_cases()

@pytest.mark.parametrize("fname, data", test_cases)
def test_input_schema(fname, data):
    try:
        validate(instance=data['input'], schema=input_schema)
    except ValidationError as e:
        pytest.fail(f"{fname} input validation failed: {e}")

@pytest.mark.parametrize("fname, data", test_cases)
def test_output_schema(fname, data):
    try:
        validate(instance=data['expected_output'], schema=output_schema)
    except ValidationError as e:
        pytest.fail(f"{fname} expected_output validation failed: {e}") 