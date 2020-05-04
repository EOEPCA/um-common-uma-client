#!/usr/bin/env python3
from time import time

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


def test_time_valid_token_intr_data():
    now = time()

    valid = [
        {"exp" : now+1_000_000},
        {"exp" : now+100},
        {"exp" : now+5},

        {"nbf" : now-5},
        {"nbf" : now-1000},

        {"iat" : now-5},
        {"iat" : now-1000},

        # Combination
        {
            "exp" : now+1000,
            "nbf" : now-100,
            "iat" : now-1000
        }
    ]

    for i in valid:
        i["active"] = "true"
        assert(rpt.valid_token_introspection_data(i) == True)


def test_time_invalid_token_intr_data():
    now = time()

    valid = [
        {"exp" : now-1_000_000},
        {"exp" : now-100},
        {"exp" : now-5},
        {"exp" : now},

        {"nbf" : now+5},
        {"nbf" : now+1000},

        {"iat" : now+5},
        {"iat" : now+1000},

        # Combination
        {
            "exp" : now-1000,
            "nbf" : now+100,
            "iat" : now+1000
        }
    ]

    for i in valid:
        # Check time validity, even with an active true
        i["active"] = "true"
        assert(rpt.valid_token_introspection_data(i) == False)
