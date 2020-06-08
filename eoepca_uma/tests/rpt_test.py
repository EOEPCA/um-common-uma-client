#!/usr/bin/env python3
from time import time

from eoepca_uma import rpt

def test_valid_token_intr_data():
    valid = [
        {"active": True, "permissions": [{"resource_id":"/simple/test", "resource_scopes": ["Auth"]}]},
        {"active": True, "permissions": [{"resource_id":"/simple/test/b", "resource_scopes": ["Auth", "Multiple", "Scopes"]}]},
    ]

    resources = [
        {"resource_id":"/simple/test",
         "resource_scopes": ["Auth"]},
        {"resource_id":"/simple/test/b",
         "resource_scopes": ["Auth","Multiple","Scopes"]},
        {"resource_id":"/simple/test/b",
         "resource_scopes": ["Auth","Scopes"]},
    ]

    for i in valid:
        assert(rpt.valid_token_introspection_data(i, resources=resources) == True)

def test_invalid_token_intr_data():
    invalid = [
        [],
        {},
        {"active": False },
        {"active": True, "permissions": [{"resource_id":"/simple/test", "resource_scopes": ["AAAAA"]}]},
        {"active": True, "permissions": [{"resource_id":"/simple/invalid", "resource_scopes": ["Auth"]}]},
        {"active": True, "permissions": [{"resource_id":"/simple/invalid", "resource_scopes": ["BBBB"]}]},
        {"active": True, "permissions": [{"resource_id":"/simple/test/b", "resource_scopes": ["Auth", "Multiple","Scopes"]}]},
        {"active": True, "permissions": [{"resource_id":"/simple/test/b", "resource_scopes": []}]},
        {"active": True, "permissions": [{"resource_id":"/simple/test/b", "resource_scopes": ["Auth"]}]},
    ]

    resources = [
        {"resource_id":"/simple/test",
         "resource_scopes": ["Auth"]},
        {"resource_id":"/simple/test/b",
         "resource_scopes": ["Auth","Multiple","Scopes","Invalid"]},
    ]


    for i in invalid:
        assert(rpt.valid_token_introspection_data(i,resources=resources) == False)


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

    resources = [
        {"resource_id":"/simple/test",
         "resource_scopes": ["Auth"]},
    ]

    for i in valid:
        # We are just testing time here
        i["active"] = True
        i["permissions"]= [{"resource_id":"/simple/test", "resource_scopes": ["Auth"]}]
        assert(rpt.valid_token_introspection_data(i, resources=resources) == True)


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

    resources = [
        {"resource_id":"/simple/test",
         "resource_scopes": ["Auth"]},
    ]

    for i in valid:
        # Check time validity, even with an active true
        i["active"] = True
        i["permissions"]= [{"resource_id":"/simple/test", "resource_scopes": ["Auth"]}]
        assert(rpt.valid_token_introspection_data(i, resources=resources) == False)
