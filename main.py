import whois
import socket
import subprocess
import nmap
import dns.resolver
import platform
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify, request
import threading

app = Flask(__name__)

@app.route('/')
def home():
    return "Welcome to AutoReconn"

def cmd(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("Response:")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return e.stderr

def nmap_scan(domain):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=domain, arguments='-sV')
    result = []
    for host in scanner.all_hosts():
        result.append(f"Host: {host} ({scanner[host].hostname()})")
        result.append(f"State: {scanner[host].state()}")
        
        for protocol in scanner[host].all_protocols():
            result.append(f"Protocol: {protocol}")
            ports = scanner[host][protocol].keys()
            for port in ports:
                result.append(f"Port: {port}, State: {scanner[host][protocol][port]['state']}")
    return result

def dns_dumpster(domain):
    result = {}
    for rdata in dns.resolver.resolve(domain, 'A'):
        result["A Records:"].append(rdata)
    for rdata in dns.resolver.resolve(domain, 'MX'):
        result["MX Records:"].append(rdata)
    for rdata in dns.resolver.resolve(domain, 'NS'):
        result["NS Records:"].append(rdata)
    for record in dns.resolver.resolve(domain, 'TXT'):
        result["TXT Records (Text):"].append(record.to_text())
    try:
        for record in dns.resolver.resolve(domain, 'CNAME'):
            result["CNAME Record (Alias):"].append(record.to_text())
    except dns.resolver.NoAnswer:
        result["CNAME Record (Alias):"].append("No CNAME Record found.")
    try:
        for record in dns.resolver.resolve(domain, 'SOA'):
            result["SOA Record (Authority):"].append(record.to_text())
    except dns.resolver.NoAnswer:
        result["SOA Record (Authority):"].append("No SOA Records found.")
    return result


def tracerout(domain):
    if platform.system() == 'Darwin':
        return cmd(['traceroute', domain])
    else : 
        return cmd(['tracert', domain])

def check_url(domain, word, timeout):
    url = f"{domain}/{word}"
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            return f"[FOUND] {url} (Status: 200)"
        elif response.status_code == 403:
            return f"[FORBIDDEN] {url} (Status: 403)"
        else:
            return None  # No output for non-200/403 status codes
    except requests.exceptions.RequestException as e:
        return f"[ERROR] {url} - {e}"

def directory_buster(domain, wordlist, max_threads=10, timeout=5):
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "http://" + domain

    print(f"Starting directory buster for: {domain} with {max_threads} threads.")
    found = []

    with ThreadPoolExecutor(max_threads) as executor:
        # Create a future for each word
        futures = {executor.submit(check_url, domain, word, timeout): word for word in wordlist}

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)
                found.append(result)

    return found

@app.route('/reconn/<string:domain_name>', methods=['POST'])
def imp(domain_name):
    results = {
        "domain": domain_name,
        "ip": None,
        "whois": None,
        "ipinfo": None,
        "NMap": None,
        "DNS": None,
        "Trace Route": None,
    }

    def resolve_ip():
        try:
            results["ip"] = socket.gethostbyname(domain_name)
        except socket.gaierror:
            results["ip"] = "Unable to resolve IP"

    def fetch_whois():
        try:
            results["whois"] = whois.whois(domain_name)
        except Exception as e:
            results["whois"] = f"Error fetching whois: {str(e)}"

    def fetch_ipinfo():
        try:
            if results["ip"]:
                results["ipinfo"] = cmd(["curl", "-X", "GET", f"ipinfo.io/{results['ip']}?token=fb0a46bcf7cadb"])
        except Exception as e:
            results["ipinfo"] = f"Error fetching IP info: {str(e)}"

    def perform_nmap_scan():
        try:
            results["NMap"] = nmap_scan(domain_name)
        except Exception as e:
            results["NMap"] = f"Error in Nmap scan: {str(e)}"

    def fetch_dns_info():
        try:
            results["DNS"] = dns_dumpster(domain_name)
        except Exception as e:
            results["DNS"] = f"Error fetching DNS info: {str(e)}"

    def perform_traceroute():
        try:
            results["Trace Route"] = tracerout(domain_name)
        except Exception as e:
            results["Trace Route"] = f"Error in traceroute: {str(e)}"

    # Create threads
    threads = [
        threading.Thread(target=resolve_ip),
        threading.Thread(target=fetch_whois),
        threading.Thread(target=fetch_ipinfo),
        threading.Thread(target=perform_nmap_scan),
        threading.Thread(target=fetch_dns_info),
        threading.Thread(target=perform_traceroute),
    ]

    # Start all threads
    for thread in threads:
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    return jsonify(results), 200

    

if __name__ == '__main__':
    #whois_info = whois.whois(domain_name)
    #ip_info = cmd(["curl", "-X", "GET", "ipinfo.io/"+domain_ip+"?token=fb0a46bcf7cadb"])
    #nmap_scan(domain_name)
    #dns_dumpster(domain_name)
    #print(tracerout(domain_name))
    #wordlist_file = '/Users/home/Documents/AutoReconV2/directory-list-2.3-medium.txt' #input("Enter the path to the wordlist file: ").strip()
    #max_threads = 50
    #with open(wordlist_file, "r") as f:
    #    wordlist = [line.strip() for line in f.readlines() if line.strip()]
    #found_urls = directory_buster(domain_name, wordlist, max_threads=max_threads)
    app.run(debug=True)