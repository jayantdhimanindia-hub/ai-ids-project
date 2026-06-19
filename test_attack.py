import socket
import requests
import threading
import time

TARGET = "127.0.0.1"

def test_ddos():
    print("[*] DDoS Test shuru...")
    for i in range(200):
        try:
            requests.get(f"http://{TARGET}:5000", timeout=0.5)
        except:
            pass
    print("[✓] DDoS Test complete")

def test_port_scan():
    print("[*] Port Scan Test shuru...")
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 
             143, 443, 445, 3306, 3389, 8080]
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(0.3)
            s.connect((TARGET, port))
            s.close()
        except:
            pass
    print("[✓] Port Scan Test complete")

def test_brute_force():
    print("[*] Brute Force Test shuru...")
    for i in range(50):
        try:
            s = socket.socket()
            s.settimeout(0.3)
            s.connect((TARGET, 22))
            s.close()
        except:
            pass
    print("[✓] Brute Force Test complete")

def test_sql_injection():
    print("[*] SQL Injection Test shuru...")
    payloads = [
        "' OR 1=1 --",
        "UNION SELECT username, password FROM users",
        "DROP TABLE users; --",
    ]
    for payload in payloads:
        try:
            requests.get(
                f"http://{TARGET}:5000",
                params={"q": payload},
                timeout=0.5
            )
        except:
            pass
    print("[✓] SQL Injection Test complete")

if __name__ == "__main__":
    print("=" * 40)
    print("   AI IDS - Local Attack Testing")
    print("=" * 40)

    test_port_scan()
    time.sleep(2)

    test_brute_force()
    time.sleep(2)

    test_ddos()
    time.sleep(2)

    test_sql_injection()

    print("\n[✓] Saare tests complete — Dashboard check karo!")