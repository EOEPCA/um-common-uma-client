#!/usr/bin/env python3
from requests import request

from eoepca_uma.utils import is_ok

class Client:
    """
    UMA Client implementation,
    acting on behalf of the requesting party.

    Example:
    c = Client(<parameters>)
    img = c.request_resource("/my/image.jpg",<...>)
    """

    def __init__(self, resource_server_url: str) -> Client:
        self.resource_server = resource_server_url

    def request_resource(self, uri: str, rpt: str = None, secure: bool = True) -> bytes:
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

    def _handle_ticket_request(self, response: request.response) -> str:
        """
        Returns rpt
        """
        # 

        pass

    