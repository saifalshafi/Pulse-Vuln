import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:

    @staticmethod
    def scan(host, full_scan=False):

        if full_scan:
            ports = range(1, 65536)
        else:
            ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]

        open_ports = {}

        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.3)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        service, version = PortScanner.identify_service(sock, host, port)
                        return port, service, version
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=500) as executor:
            futures = [executor.submit(scan_port, p) for p in ports]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    port, service, version = result
                    open_ports[port] = {
                        "service": service,
                        "version": version
                    }

        return open_ports

    @staticmethod
    def identify_service(sock, host, port):

        service = "unknown"
        version = ""

        try:
            # Try banner grab
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
            banner = sock.recv(1024).decode(errors="ignore")

            if "Server:" in banner:
                for line in banner.split("\n"):
                    if "Server:" in line:
                        version = line.split("Server:")[1].strip()
                        service = "http"
                        break

            elif "SSH" in banner:
                service = "ssh"
                version = banner.strip()

        except:
            pass

        # Fallback service detection
        if port == 21:
            service = "ftp"
        elif port == 22:
            service = "ssh"
        elif port in [80, 8080]:
            service = "http"
        elif port == 443:
            service = "https"
        elif port == 445:
            service = "smb"
        elif port == 3389:
            service = "rdp"

        return service, version
