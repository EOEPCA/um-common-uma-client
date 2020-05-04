#!/usr/bin/env python3
from eoepca_uma import rpt

def test_valid_token_introspection_data():
    # Test that any data with "active" == "false" is not valid
    data = {"active": "false"}
    assert(rpt.valid_token_introspection_data(data) == False)
