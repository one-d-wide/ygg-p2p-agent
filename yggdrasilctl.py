import json
import socket

class APIError(Exception):
    "Base class for Yggdrasil admin API related errors."

class APIUnreachable(APIError):
    "Exception raised in case of unsucessful attemption to connect to API."

class AdminAPI:
    def __init__(self, address: str):
        self.address = address

    def _get_connection(self):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(self.address)
        except Exception as err:
            raise APIUnreachable(f"Can't connect to {self.address}: {err}")
        return connection

    def request(self, method: str, **kwargs)->dict:
        req = {'request': method, 'arguments': kwargs}

        connection = self._get_connection()
        try:
            json.dump(req, connection.makefile('w'))
            response = json.load(connection.makefile('r'))
        finally:
            connection.close()

        if not response['status']=='success':
            if 'error' in response:
                response = response['error']
            raise APIError(response)
        return response['response']
