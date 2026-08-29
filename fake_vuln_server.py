import socket

HOST = "0.0.0.0"
PORT = 8080

response = b"""HTTP/1.1 200 OK
Server: Apache/2.4.49
Content-Type: text/html
Connection: close

<html>
<head><title>Vulnerable Server</title></head>
<body>
<h1>Apache 2.4.49 Test Server</h1>
<p>This server simulates a vulnerable Apache version.</p>
</body>
</html>
"""

def start_server():
    print("[+] Fake Vulnerable Apache Server Started")
    print(f"[+] Listening on http://127.0.0.1:{PORT}")
    print("[+] Server Header: Apache/2.4.49")
    print("[+] Ready for PULSE scan...\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)

        while True:
            conn, addr = s.accept()
            with conn:
                conn.recv(1024)
                conn.sendall(response)

if __name__ == "__main__":
    start_server()
