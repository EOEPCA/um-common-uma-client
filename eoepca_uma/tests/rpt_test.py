#!/usr/bin/env python3
from eoepca_uma import rpt

def test_valid_token_intr_data():
    valid = [
        {"active": "true"}
    ]

    for i in valid:
        assert(rpt.valid_token_introspection_data(i) == True)


def test_invalid_token_intr_data():
    invalid = [
        [],
        {},
        {"active": "false"}
    ]
    
    for i in invalid:
        assert(rpt.valid_token_introspection_data(i) == False)
