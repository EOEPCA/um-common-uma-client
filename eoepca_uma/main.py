#!/usr/bin/env python3
from eoepca_oidc import OpenIDClient

from client import Client

def main():

    # Create your client:
    # Parameters:
    resource_server_url = "my-RS-url.com"
    auth_server_url = "my-AS-url.com"
    OIDClient = OpenIDClient() # Configure OIDC with client creds!
    uma_cli = Client(resource_server_url, auth_server_url, OIDClient)

    uma_cli.request_resource("my/example/image.img",secure=False) # Use secure=True in production!


if __name__ == "__main__":
    main()
