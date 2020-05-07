#!/usr/bin/env python3
from requests import request, Response
from WellKnownHandler import WellKnownHandler, TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT
from WellKnownHandler import TYPE_UMA_V2, KEY_UMA_V2_TOKEN_ENDPOINT
from eoepca_oidc import OpenIDClient

from eoepca_uma.utils import is_ok
from eoepca_uma.rpt import request_for_rpt

class Client:
    """
    UMA Client implementation,
    acting on behalf of the requesting party.

    Example:
    c = Client(<parameters>)
    img = c.request_resource("/my/image.jpg",<...>)
    """

    def __init__(self, resource_server_url: str, auth_server_url: str, OIDClient: OpenIDClient, secure: bool = True):
        """
        Creates a new UMA Client instance.

        - CAN THROW EXCEPTIONS
        - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

        Args:
        - resource_server_url = URL of the resource server
        - auth_server_url = URL of the Authorization Server
        - OIDClient = Instance of a OpenIDClient (from eoepca_oidc), configured for the same Auth server.
        - secure (Optional) = toggle checking of SSL certificates. Activating this is recommended on production environments
        
        Returns:
            A configured UMA Client, or an exception
        """
        self.resource_server = resource_server_url

        self.wkh = WellKnownHandler(auth_server_url, secure=secure)
        self.oidc_client = OIDClient

    def request_resource(self, uri: str, rpt: str = None, secure: bool = True) -> bytes:
        """
        Requests a resource from the resource server.

        If you have an RPT token for this resource, you can try to re-use it calling
        this function with your RPT, but please notice this function wont try to re-generate
        an RPT via ticket if one is given.

        If you have no RPT but you have initialized this client with the proper credentials,
        this function call will auto-authenticate, handling ticket and RPT calls until the
        resource is obtained.

        - CAN THROW EXCEPTIONS
        - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

        Args:
        - uri = URI to the resource you want to access inside the resource server.
        - rpt (Optional) = String containing the rpt (token)
        - secure (Optional) = toggle checking of SSL certificates. Activating this is recommended on production environments
        
        Returns:
            The resource requested in bytes, or an exception if something went wrong.
        """
        headers = {}
        if rpt:
            headers = {"Authorization": "Bearer "+rpt}

        # Request resource
        ret = request("GET", self.resource_server + uri, headers=headers, secure=secure)

        # Handle ticket
        if ret.status_code == 401:
            rpt = self._handle_ticket_request(ret)
            # Re-try with an rpt obtained from ticket
            return self.request_resource(uri, rpt, secure)

        # Any error other than a 401 is an error that this client cannot automatically solve
        elif not is_ok(ret):
            raise Exception("Resource server denied access with an unexpected error: "+str(ret.status_code)+": "+str(ret.reason))
                
        # Return resource when access is achieved
        return ret.content

    def _handle_ticket_request(self, response: Response, secure: bool = True) -> str:
        """
        Handles the ticket answer when attempting to access to a resource.

        - CAN THROW EXCEPTIONS
        - MAKES A CONNECTION TO AN EXTERNAL ENDPOINT

        Args:
        - response = Response object from requests package, after requesting access to a resource.
        - secure (Optional) = toggle checking of SSL certificates. Activating this is recommended on production environments
        
        Returns:
            RPT for this resource, or an exception
        """
        if "WWW-Authenticate" not in response.headers:
            raise Exception("Response from server does not include necessary header: 'WWW-Authenticate'")

        data = response.headers["WWW-Authenticate"]
        # Get ticket
        data = data.strip().split(",")
        ticket= [x.split("=")[1].strip('"') for x in data if "ticket" in x ]

        # Get OIDC token
        token_endpoint = self.wkh.get(TYPE_OIDC , KEY_OIDC_TOKEN_ENDPOINT)
        self.oidc_client.postRequestToken({"token_endpoint": token_endpoint}, verify=secure)
        client_creds_token= self.oidc_client.token

        token_endpoint = self.wkh.get(TYPE_UMA_V2, KEY_UMA_V2_TOKEN_ENDPOINT)
        rpt_res = request_for_rpt(client_creds_token, token_endpoint, ticket, secure=secure)
        
        return rpt_res["access_token"]

    