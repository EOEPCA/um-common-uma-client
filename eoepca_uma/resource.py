#!/usr/bin/env python3
from requests import request
from typing import List

from eoepca_uma.utils import dict_insert_if_exists
from eoepca_uma.utils import disable_warnings_if_debug
from eoepca_uma.utils import is_ok

# Client utilities

def read(pat: str, resource_registration_endpoint: str,
         resource_id: str,
         secure: bool = False) -> dict:
    """
    Reads the information for a single resource, indicated by resource ID.

    Note that if an empty resource ID is given, this function is identical to 'list()', but please use each function
    for their respective intended use as this behaviour is not intended by design and may change at any time

    - CAN THROW EXCEPTIONS
    - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

    Args:
    - pat = String containing the pat (token)
    - resource_registration_endpoint = URL of the resource registration endpoint in the AS
    - resource_id = ID of the resource on the AS
    - secure = toggle checking of SSL certificates. Activating this is recommended on production environments
    
    Returns:
        JSON-formatted information about the resource
    """
    headers={"Authorization": "Bearer "+pat}

    disable_warnings_if_debug(secure)
    if resource_registration_endpoint[-1] is not "/":
        resource_registration_endpoint += "/"

    response = request("GET", resource_registration_endpoint + resource_id, headers=headers, verify=secure)
    if not is_ok(response):
        raise Exception("An error occurred while getting a resource's information: "+str(response.status_code)+":"+str(response.reason)+":"+str(response.text))

    return response.json()

def list(pat: str, resource_registration_endpoint: str,
         secure: bool = False) -> List[str]:
    """
    Lists all previously registered resources by ID for this resource owner.
    - CAN THROW EXCEPTIONS
    - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

    Args:
    - pat = String containing the pat (token)
    - resource_registration_endpoint = URL of the resource registration endpoint in the AS
    - secure = toggle checking of SSL certificates. Activating this is recommended on production environments
    
    Returns:
        List of IDs (str) registered
    """
    headers={"Authorization": "Bearer "+pat}

    disable_warnings_if_debug(secure)
    response = request("GET", resource_registration_endpoint, headers=headers, verify=secure)

    if not is_ok(response):
        raise Exception("An error occurred while listing resources: "+str(response.status_code)+":"+str(response.reason)+":"+str(response.text))

    return response.json()

def create(pat: str, resource_registration_endpoint: str,
             name: str, scopes: List[str],
             description: str = None, icon_uri: str = None, typ: str = None,
             secure: bool = False) -> str:
    """
    Registers a new resource in the AS.
    - CAN THROW EXCEPTIONS
    - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

    Args:
    - pat = String containing the pat (token)
    - resource_registration_endpoint = URL of the resource registration endpoint in the AS
    - name = Name given to the new resource
    - scopes = List of scopes (strings) assigned to this resource
    - description (Optional) = Description for the resource
    - icon_uri (Optional) = URI to an icon representing this resource
    - typ (Optional) = Type (string/URI) of this resource
    - secure = toggle checking of SSL certificates. Activating this is recommended on production environments
    
    Returns:
        Resource ID given by the AS associated with the newly created resource, or an error
    """

    payload = {"name": name , "resource_scopes": scopes }
    dict_insert_if_exists(payload, "description", description)
    dict_insert_if_exists(payload, "icon_uri", icon_uri)
    dict_insert_if_exists(payload, "type", typ)

    headers = {
        'Content-Type': "application/json",
        'Authorization': "Bearer "+pat,
    }

    disable_warnings_if_debug(secure)
    response = request("POST", resource_registration_endpoint, json=payload, headers=headers, verify=secure)

    if not is_ok(response):
        raise Exception("An error occurred while registering the resource: "+str(response.status_code)+":"+str(response.reason)+":"+str(response.text))


    try:
        return response.json()["_id"]
    except Exception as e:
        raise Exception("Call to registration endpoint returned unexpected value: '"+response.text+"'"+". Error: "+str(e))

def delete(pat: str, resource_registration_endpoint: str,
           resource_id: str,
           secure: bool = False):
    """
    Deletes a resource from the AS.
    - CAN THROW EXCEPTIONS
    - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

    Args:
    - pat = String containing the pat (token)
    - resource_registration_endpoint = URL of the resource registration endpoint in the AS
    - resource_id = ID of the resource
    - secure = toggle checking of SSL certificates. Activating this is recommended on production environments
    
    Returns:
        Nothing. If no exceptions are raised, the operation completed succesfully.
    """
    headers={"Authorization": "Bearer "+pat}

    disable_warnings_if_debug(secure)
    response = request("DELETE", resource_registration_endpoint + resource_id, headers=headers, verify=secure)

    if not is_ok(response):
        raise Exception("An error occurred while deleting the resource: "+str(response.status_code)+":"+str(response.reason)+":"+str(response.text))

def update(pat: str, resource_registration_endpoint: str,
            resource_id: str,
            name: str, scopes: List[str],
            description: str = None, icon_uri: str = None, typ: str = None,
            secure: bool = False) -> str:
    """
    Updates one or more aspects of the resource indicated by id.
    
    The entirety of the resource will be overwritten with these values as per UMA 2.0's standard.
    https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#update-resource-set
 
    - CAN THROW EXCEPTIONS
    - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

    Args:
    - pat = String containing the pat (token)
    - resource_registration_endpoint = URL of the resource registration endpoint in the AS
    - resource_id = ID of the resource
    - name (Optional) = Name given to the new resource
    - scopes (Optional) = List of scopes (strings) assigned to this resource
    - description (Optional) = Description for the resource
    - icon_uri (Optional) = URI to an icon representing this resource
    - typ (Optional) = Type (string/URI) of this resource
    - secure = toggle checking of SSL certificates. Activating this is recommended on production environments
    
    Returns:
        Resource ID given by the AS associated with the edited resource
    """
    payload = {}
    dict_insert_if_exists(payload, "name", name)
    dict_insert_if_exists(payload, "resource_scopes", scopes)
    dict_insert_if_exists(payload, "description", description)
    dict_insert_if_exists(payload, "icon_uri", icon_uri)
    dict_insert_if_exists(payload, "type", typ)

    if len(payload) == 0:
        raise Exception("No attribute to update the resource with, payload empty")

    headers = {
        'content-type': "application/json",
        'authorization': "Bearer "+pat,
    }

    disable_warnings_if_debug(secure)
    response = request("PUT", resource_registration_endpoint + resource_id, json=payload, headers=headers, verify=secure)

    if not is_ok(response):
        raise Exception("An error occurred while registering the resource: "+str(response.status_code)+":"+str(response.reason)+":"+str(response.text))

    try:
        return response.json()["_id"]
    except Exception as e:
        raise Exception("Call to registration endpoint returned unexpected value: '"+response.text+"'"+". Error: "+str(e))

def delete_all(pat: str, resource_registration_endpoint: str, secure: bool = False):
    """
    Deletes ALL resources that this resource owner owns from the AS.

    Note that the deletion can stop mid-process in case of an error, and thus only deleting part
    or none of the resources.

    - CAN THROW EXCEPTIONS
    - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

    Args:
    - pat = String containing the pat (token)
    - resource_registration_endpoint = URL of the resource registration endpoint in the AS
    - secure = toggle checking of SSL certificates. Activating this is recommended on production environments
    
    Returns:
        Nothing. If no exceptions are raised, the operation completed succesfully.
    """
    
    all_resources = list(pat,resource_registration_endpoint,secure)

    for resource_id in all_resources:
        delete(pat, resource_registration_endpoint, resource_id, secure)

# Resource Server utilities

def request_access_ticket(pat: str, permission_endpoint: str,
                        resources: List[dict],
                        secure: bool = False) -> str:
    """
    As a Resource Server, request permission to the AS to access a resource,
    generating a ticket as a result.

    - CAN THROW EXCEPTIONS
    - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

    Args:
    - pat = String containing the pat (token)
    - permission_endpoint = URL of the token permission endpoint in the AS 
    - resources = List of resources to request permission to.
                            Format:
                            [
                                {
                                    "resource_id": <str resource id>,
                                    "resource_scopes": [ <scope 1>, <scope 2>, ...]
                                },
                                ...
                            ]
    - secure = toggle checking of SSL certificates. Activating this is recommended on production environments
    
    Returns:
        A string containing the ticket for accessing those resources.
    """

    headers = {
        'content-type': "application/json",
        'authorization': "Bearer "+pat,
    }

    if len(resources) == 1:
        resources = resources[0] # Use a single dict instead of a list for 1 resource

    disable_warnings_if_debug(secure)
    response = request("POST", permission_endpoint , json=resources, headers=headers, verify=secure)

    if not is_ok(response):
        raise Exception("An error occurred while requesting permission for a resource: "+str(response.status_code)+":"+str(response.reason)+":"+str(response.text))

    try:
        return response.json()["ticket"]
    except Exception as e:
        raise Exception("Call to permission endpoint returned unexpected value or error: '"+response.text+"'"+". Error: "+str(e))
