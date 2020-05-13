#!/usr/bin/env python3
from typing import Any
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from requests import Response

def dict_insert_if_exists(d: dict, k: Any, v: Any):
    """
    Internal utility which adds a key and a value to a dictionary,
    given that the key and the value are not None or empty.

    Does nothing if any of the values is invalid.

    EDITS THE DICTIONARY BY REFERENCE
    """

    if k is None or k is "":
        return
    if v is None or v is "" or len(v) is 0:
        return
    
    d[k] = v

def disable_warnings_if_debug(secure: bool):
    """
    Deactivates warnings from Requests when not checking SSL certs, useful for debugging
    """
    if not secure:
        disable_warnings(InsecureRequestWarning)

def is_ok(response: Response):
    """
    Returns True or False depending on the response code of the server 
    """
    return response.status_code > 199 and response.status_code < 230 and "error" not in response.text.lower()
