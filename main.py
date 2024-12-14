import whois
import socket
import subprocess
import nmap
import dns.resolver
import platform
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify, request
from flask_cors import CORS
from fpdf import FPDF
import os

class PDF(FPDF):
    def header(self):
        self.image('/Users/home/Documents/AutoReconV2/apple-touch-icon.png', 5, 5, 20)
        self.set_font('helvetica', 'B', 20)
        self.set_text_color(25, 202, 25)
        self.cell(80)
        self.cell(30, 10, 'Automated Recon-Report', ln=1, align='R')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_text_color(190, 190, 190)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

app = Flask(__name__)
CORS(app)
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
    
@app.route("/nmap_scan", methods=["GET"])
def nmap_scan(temp = None):
    domain = request.args.get('domain_name', '').strip() 
    if not domain and temp:
        domain = temp
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
    if temp:
        return result
    else:
        return jsonify(result)

@app.route("/dns_dumpster", methods=["GET"])
def dns_dumpster(temp = None):
    domain = request.args.get('domain_name', '').strip() 
    if not domain and temp:
        domain = temp
    result = {
        "A Records" : [],
        "MX Records" : [],
        "NS Records" : [],
        "TXT Records (Text)" : [],
        "CNAME Record (Alias)" : [],
        "SOA Record (Authority)" : []
    }
    for rdata in dns.resolver.resolve(domain, 'A'):
        result["A Records"].append(rdata.to_text())
    for rdata in dns.resolver.resolve(domain, 'MX'):
        result["MX Records"].append(rdata.to_text())
    for rdata in dns.resolver.resolve(domain, 'NS'):
        result["NS Records"].append(rdata.to_text())
    for record in dns.resolver.resolve(domain, 'TXT'):
        result["TXT Records (Text)"].append(record.to_text())
    try:
        for record in dns.resolver.resolve(domain, 'CNAME'):
            result["CNAME Record (Alias)"].append(record.to_text())
    except dns.resolver.NoAnswer:
        result["CNAME Record (Alias)"].append("No CNAME Record found.")
    try:
        for record in dns.resolver.resolve(domain, 'SOA'):
            result["SOA Record (Authority)"].append(record.to_text())
    except dns.resolver.NoAnswer:
        result["SOA Record (Authority)"].append("No SOA Records found.")
    if temp:
        return result
    else:
        return jsonify(result)


@app.route("/tracerout", methods=["GET"])
def tracerout(temp = None):
    domain = request.args.get('domain_name', '').strip() 
    if not domain and temp:
        domain = temp
    if platform.system() == 'Darwin':
        if temp:
            return cmd(['traceroute', domain])
        else:
            return jsonify(cmd(['traceroute', domain]))
    else : 
        if temp:
            return cmd(['tracert', domain])
        else:
            return jsonify(cmd(['tracert', domain]))

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
        futures = {executor.submit(check_url, domain, word, timeout): word for word in wordlist}

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)
                found.append(result)

    return found

@app.route('/getip', methods=['GET'])
def getIP():
    domain = request.args.get('domain_name', '').strip() 
    domain_ip = socket.gethostbyname(domain)
    return jsonify(domain_ip)

@app.route('/whois', methods=['GET'])
def whois_info():
    domain = request.args.get('domain_name', '').strip() 
    whois_info = whois.whois(domain)
    return jsonify(whois_info)

@app.route('/ipinfo', methods=['GET'])
def ip_info():
    domain = request.args.get('domain_name', '').strip() 
    domain_ip = socket.gethostbyname(domain)
    ip_info = cmd(["curl", "-X", "GET", "ipinfo.io/"+domain_ip+"?token=fb0a46bcf7cadb"])
    return jsonify(ip_info)

@app.route('/subdomain', methods=['GET'])
def find_subdomains(temp = None):
    domain = request.args.get('domain_name', '').strip() 
    if not domain and temp:
        domain = temp
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            print("Error fetching data from crt.sh")
            return []

        subdomains = set()
        for entry in response.json():
            name = entry.get("name_value")
            if name:
                subdomains.update(name.split("\n"))  # Some entries may contain multiple subdomains
        if temp:
            return sorted(subdomains)
        else:
            return jsonify(sorted(subdomains)) 
    
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def create_pdf(domain,results):
    output_dir = '/Users/home/Documents/AutoReconV2/output'  # Adjust this path
    os.makedirs(output_dir, exist_ok=True)
    
    pdf = PDF('P', 'mm', 'A4')
    # Add the cover page
    pdf.add_page()
    pdf.set_font('helvetica', 'B', 36)
    pdf.set_text_color(0, 0, 0)
    page_width = pdf.w - 10  # Page width minus margin
    page_height = pdf.h - 10  # Page height minus margin
    pdf.set_xy(page_width - 190, page_height - 140)
    pdf.cell(180, 20, "Reconnaissance Report", align='R', ln=True)

    # Add a new page for the index
    pdf.add_page()

    # Set up the index page
    pdf.set_font('helvetica', 'B', 24)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 20, 'Index', ln=True, align='L')

    pdf.set_font('helvetica', '', 12)
    pdf.ln(10)  # Add some space

    # Example index items
    index_items = [
    ('1. About', 2),
    ('2. Domain, IP address', 3),
    ('3. Geo-Location and Hosting', 4),
    ('4. Port Information', 5),
    ('5. WhoIs Information', 6),
    ('6. DNS Information', 7),
    ('7. trace route', 8),
    ('8. Subdomain Information', 9),
    ]

    # Add index items with page numbers aligned to the right
    for item, page_num in index_items:
        pdf.set_x(10)  # Reset X position for each line
        pdf.cell(0, 10, item, ln=0, align='L')
        pdf.cell(-30)  # Move the cursor to the right end of the page
        pdf.cell(30, 10, str(page_num), ln=True, align='R')

    # Add a title page
    pdf.add_page()
    pdf.set_font('helvetica', 'B', 20)
    pdf.cell(0, 10, 'Reconnaissance Report', ln=True, align='L')
    pdf.set_font('helvetica', '', 12)
    pdf.cell(0, 10, 'This report contains various analyses of the provided URL.', ln=True, align='L')
    pdf.set_font('helvetica', 'BU', 16)
    pdf.cell(0, 10, 'The tools used.', ln=True, align='L')
    pdf.set_font('helvetica', '', 12)
    pdf.cell(0, 10, 'Nmap (nmap.PortScanner): A tool for network discovery and security auditing, integrated for scanning ports and services.', ln=True, align='L')
    pdf.cell(0, 10, 'Socket: Python’s built-in module to perform network-related tasks like resolving domain names to IP addresses.', ln=True, align='L')
    pdf.cell(0, 10, 'Subprocess: Used to execute shell commands (e.g., traceroute/tracert, curl) from within the Python script.', ln=True, align='L')
    pdf.cell(0, 10, 'DNS Resolver (dnspython): A library to perform DNS lookups for record types like A, MX, NS, TXT, and SOA.', ln=True, align='L')
    pdf.cell(0, 10, 'IPinfo.io API: A third-party service used to fetch geolocation and IP-related information.', ln=True, align='L')
    pdf.cell(0, 10, 'Requests: A Python library for making HTTP requests, used for fetching data from APIs and web endpoints.', ln=True, align='L')
    pdf.cell(0, 10, 'Whois (python-whois): Retrieves WHOIS information about a domain for administrative and contact details.', ln=True, align='L')
    pdf.cell(0, 10, 'crt.sh API: A web-based API used to fetch subdomains by querying Certificate Transparency logs.', ln=True, align='L')
    pdf.cell(0, 10, 'Platform: Used to identify the underlying operating system and adapt commands (traceroute or tracert) accordingly.', ln=True, align='L')

    # Add a new page for each section of results
    for section, content in results.items():
        pdf.add_page()
        pdf.set_font('helvetica', 'B', 16)
        pdf.cell(0, 10, section, ln=True)
        pdf.ln(10)
        
        pdf.set_font('helvetica', '', 10)
        if isinstance(content, dict):
            for key, value in content.items():
                pdf.multi_cell(0, 10, f'{key}: {value}')
        elif isinstance(content, list):
            for item in content:
                pdf.multi_cell(0, 10, str(item))
        else:
            pdf.multi_cell(0, 10, str(content))
    
    # Save PDF
    pdf_path = os.path.join(output_dir, domain+'_recon_report.pdf')
    pdf.output(pdf_path)
    
    return pdf_path


@app.route('/reconn', methods=['GET'])
def imp():
    try:
        domain_name = request.args.get('domain_name','')
        domain_ip = socket.gethostbyname(domain_name)
        whois_info = whois.whois(domain_name)
        ip_info = cmd(["curl", "-X", "GET", "ipinfo.io/"+domain_ip+"?token=fb0a46bcf7cadb"])
        nmap_scan_info = nmap_scan(domain_name)
        dns_info = dns_dumpster(domain_name)
        trace = tracerout(domain_name)
        subdomains = find_subdomains(domain_name)
        result = {
            "domain": domain_name,
            "ip": domain_ip,
            "ipinfo":ip_info,
            "NMap":nmap_scan_info,
            "whois":whois_info,
            "DNS":dns_info,
            "Trace Route":trace,
            "Subdomain":subdomains
        }
        path = create_pdf(domain_name,result)
        return jsonify({'pdf stored at ':path})
    except socket.gaierror:
        return jsonify({"error": f"Unable to resolve domain: {domain_name}"}), 400
    

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