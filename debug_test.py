import pytest
from tests.test_module_registry import TestModuleRegistry

def print_calls(*args, **kwargs):
    print(f"CALLED: {args} {kwargs}")

TestModuleRegistry().test_result_processors_handle_prompts_and_side_effects(pytest.MonkeyPatch())
