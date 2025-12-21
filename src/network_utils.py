import socket
import ipaddress

class NetworkUtils:
    @staticmethod
    def validate_ip(ip):
        """Checks if the provided string is a valid IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def resolve_host(hostname):
        """Resolves a domain name (e.g., google.com) to an IP address."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None