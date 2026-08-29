import socket


class HostDiscovery:

    @staticmethod
    def is_alive(host):
        try:
            socket.gethostbyname(host)
            return True
        except:
            return False
