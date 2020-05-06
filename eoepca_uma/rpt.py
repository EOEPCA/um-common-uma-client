#!/usr/bin/env python3
from requests import request
from time import time
from typing import List

from eoepca_uma.utils import disable_warnings_if_debug, is_ok

def introspect(rpt: str, pat: str, introspection_endpoint: str, secure: bool = False) -> dict:
    """
    Gets information about an RPT, using the AS' introspection endpoint.
    - CAN THROW EXCEPTIONS
    - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

    Args:
    - rpt = String containing the rpt (token)
    - pat = String containing the pat (token)
    - introspection_endpoint = String containing the url to the AS' introspection endpoint
    - secure = toggle checking of SSL certificates. Activating this is recommended on production environments
    
    Returns:
        JSON-formatted data about the RPT, or an error from the AS
    """

    headers = {
        'content-type': "application/x-www-form-urlencoded",
        'authorization': "Bearer "+pat,
        }

    payload = "token="+rpt

    disable_warnings_if_debug(secure)
    r = request("POST", introspection_endpoint, headers=headers, data=payload, verify=secure)

    if not is_ok(r):
        raise Exception("An error occurred while registering the resource: "+str(r.code)+":"+str(r.reason))

    try:
        return r.json()
    except Exception as e:
        raise Exception("Call to introspection point returned unexpected value: "+str(e))

def valid_token_introspection_data(rpt_info: dict, time_margin: float = 0.0) -> bool:
    """
    Asserts if a given rpt is valid at this time, using the introspection data from it.

    This validation is done in compliance with RFC7662 'OAuth 2.0 Token Introspection'.

    Keep in mind that if the data analyzed is outdated, this function may return the wrong answer, since it doesn't
    update with the AS.
    More precisely, this function WILL detect when a token is outdated or otherwise not usable at this specific date,
    but NOT when scopes have changed, or any other remote action the AS might have taken or changed.

    It is crucial for the time-checking to work that this code is executed on a time-synced server, otherwise the
    time meassurements could be off.

    Time check uses the following fields: exp, iat, nbf

    Alternatively, you can use 'is_valid_now' to get updated RPT information and check it in a single call. 

    Args:
    - rpt_info = Dict containing the data from an RPT, obtained from a correct 'introspect' call
    - time_margin (Optional) = A time difference to add to the current timestamp, to ensure this token will be valid _at least until_ now + time_margin
   
    Note that there might not be time information in the data, and thus 'time_margin' would do nothing.


    Returns:
        True if the token is valid at this time given this information, False otherwise.
    """
    now = time()

    if "exp" in rpt_info:
        if rpt_info["exp"] < (now - time_margin) : return False

    # Not a time validity check per se, but a sanity check for corrupt / invalid data nontheless
    if "iat" in rpt_info:
        if rpt_info["iat"] > (now + time_margin) : return False
    
    if "nbf" in rpt_info:
        if rpt_info["nbf"] > (now + time_margin) : return False

    # Actual check of validity using the AS' criteria
    return "active" in rpt_info and rpt_info["active"] == "true"

def is_valid_now(rpt: str, pat: str, introspection_endpoint: str, time_margin: float = 0.0, secure: bool = False) -> dict:
    """
    Uses the introspection from the AS to get updated data about the RPT, then returns True/False
    if the RPT is valid or not at the moment of the call of this function.

    This is equal to calling 'introspect' and then 'valid_token_introspection_data'.

    - CAN THROW EXCEPTIONS
    - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

    Args:
    - rpt = String containing the rpt (token)
    - pat = String containing the pat (token)
    - introspection_endpoint = String containing the url to the AS' introspection endpoint
    - time_margin (Optional) = A time difference to add to the current timestamp, to ensure this token will be valid _at least until_ now + time_margin
    - secure = toggle checking of SSL certificates. Activating this is recommended on production environments
    Note that there might not be time information in the data, and thus 'time_margin' would do nothing.
    
    Returns:
        True if the token is valid at this time given this information, False otherwise.
    """

    try:
        introspection_data = introspect(rpt, pat, introspection_endpoint, secure)
    except:
        return False
    
    return valid_token_introspection_data(introspection_data, time_margin)


def request_for_rpt(client_creds_token: str,
                    token_endpoint: str, ticket: str,
                    claim_token: str = None, claim_token_format: str = None,
                    scopes: List[str] = None,
                    secure: bool = True) -> dict:
    """
    (NOTE: TODO: Missing PCT, RPT option)

    Requests the AS for an RPT given the arguments used.

    - CAN THROW EXCEPTIONS
    - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

    Args:
    - client_creds_token = token obtained from AS with client credentials
    - token_endpoint = String containing the url to the AS' token endpoint
    - ticket = Ticket obtained from Resource Server for this request
    - claim_token (Optional) = A string containing directly pushed claim information in the indicated format. It MUST be base64url encoded unless specified otherwise by the claim token format
    - claim_token_format (Optional) = If this parameter is used, it MUST appear together with the claim_token parameter. A string specifying the format of the claim token in which the client is directly pushing claims to the authorization server. The string MAY be a URI
    - scopes (Optional) = List of requested scopes
    - secure = toggle checking of SSL certificates. Activating this is recommended on production environments
    
    Returns:
        A dictionary with at least an access_token and a 'token_type', or an exception
    """
    grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket" # Fixed value according to https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#uma-grant-type

    headers = {"Authorization": "Basic "+ client_creds_token}

    payload = "grant_type="+grant_type+"&ticket="+ticket
    if claim_token:
        payload+="&claim_token="+claim_token
        # Format only allowed when claim token is given.
        if claim_token_format:
            payload+="&claim_token_format="+claim_token_format
    
    if scopes and len(scopes) > 0:
        payload+="&scope="+" ".join(scopes)

    disable_warnings_if_debug(secure)
    response = request("POST", token_endpoint , data=payload, headers=headers, verify=secure)

    if not is_ok(response):
        raise Exception("An error occurred while requesting RPT: "+str(response.code)+":"+str(response.reason))

    return response.json()

