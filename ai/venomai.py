from flask import Flask, render_template, request, jsonify
from phi.agent import Agent
from phi.model.openai import OpenAIChat
import os
import subprocess
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import time
import whois

# Load environment variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
openai_api_key = os.getenv("OPENAI_API_KEY")
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")

if not openai_api_key:
    raise ValueError("OPENAI_API_KEY not set in .env file or environment")
if not virustotal_api_key:
    raise ValueError("VIRUSTOTAL_API_KEY not set in .env file or environment")

# Initialize Flask app
app = Flask(__name__, template_folder="../homepage", static_folder="../static")

# AI Agent setup
web_agent = Agent(
    name="VenomAI",
    model=OpenAIChat(id="gpt-4o"),
    instructions=["Provide intelligent responses for cybersecurity queries."],
    show_tool_calls=False,
    markdown=True,
)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/process_plugin", methods=["POST"])
def process_plugin():
    data = request.json
    user_input = data.get("message")
    selected_plugin = data.get("plugin")

    if not user_input:
        return jsonify({"response": "No input provided."})

    try:
        if selected_plugin == "port_scanner":
            return run_nmap_scan(user_input)
        elif selected_plugin == "Whois Lookup":
            return jsonify({"response": get_whois_data(user_input)})
        elif selected_plugin == "DNS lookup":
            return jsonify({"response": dns_lookup(user_input)})
        elif selected_plugin == "IP address to lookup":
            return jsonify({"response": get_ip_info(user_input)})
        elif selected_plugin == "find_pages":
            return jsonify({"response": find_pages(user_input)})
        elif selected_plugin == "ssl_checker":
            return jsonify({"response": ssl_checker(user_input)})
        elif selected_plugin == "security_headers":
            return jsonify({"response": check_security_headers(user_input)})
        elif selected_plugin == "virus_check":
            return jsonify({"response": virus_check(user_input)})
        elif selected_plugin == "subdomain_finder":
            return jsonify({"response": subdomain_finder(user_input)})
        else:
            response = web_agent.run(message=user_input)
            response_text = response if isinstance(response, str) else response.content
            return jsonify({"response": response_text})

    except Exception as e:
        return jsonify({"response": f"Error: {str(e)}"})

# Nmap Scan
def run_nmap_scan(target):
    try:
        result = subprocess.run(["nmap", "-p-", target], capture_output=True, text=True)
        return jsonify({"response": f"```bash\n{result.stdout}\n```"})
    except Exception as e:
        return jsonify({"response": f"Error running Nmap: {str(e)}"})


def get_whois_data(domain):
    try:
        # First, try to fetch WHOIS data using the domain
        whois_url = f'https://www.whois.com/whois/{domain}'
        response = requests.get(whois_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        whois_info = soup.find('pre')
        if whois_info:
            return whois_info.text.strip()
        else:
            # If the website doesn't have the WHOIS data, use the whois command-line tool
            result = subprocess.run(["whois", domain], capture_output=True, text=True)
            return result.stdout
    except Exception as e:
        return f"Error fetching Whois data: {e}"



# DNS Lookup
def dns_lookup(domain):
    try:
        url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
        response = requests.get(url)
        return response.text
    except Exception as e:
        return f"Error performing DNS lookup: {e}"

# IP Info
def get_ip_info(ip_address):  
    try:  
        ipinfo_url = f'https://ipinfo.io/{ip_address}/json'  
        response = requests.get(ipinfo_url)  
        if response.status_code == 401:  
            return "Invalid API key or unauthorized request."  
        ip_info = response.json()

        # Format the key info
        formatted_info = "\n".join(f"**{key.capitalize()}**: {value}" for key, value in ip_info.items())
        return formatted_info

    except Exception as e:  
        return f"Error fetching IP info: {e}"  


# Page Links
def find_pages(domain):
    try:
        response = requests.get(f"https://api.hackertarget.com/pagelinks/?q={domain}")
        return response.text
    except Exception as e:
        return f"Error fetching page links: {e}"

# SSL Checker
def ssl_checker(domain):
    try:
        api_url = "https://api.ssllabs.com/api/v3/analyze"
        response = requests.get(api_url, params={"host": domain, "all": "done"})
        analysis = response.json()

        while analysis.get("status") == "IN_PROGRESS":
            time.sleep(5)
            analysis = requests.get(api_url, params={"host": domain}).json()

        if "endpoints" not in analysis:
            return "SSL analysis failed."

        endpoint = analysis["endpoints"][0]
        ip = endpoint.get("ipAddress", "N/A")
        grade = endpoint.get("grade", "Unknown")

        certs = analysis.get("certs", [])
        chain_info = ""
        for i, cert in enumerate(certs, 1):
            chain_info += (
                f"🔗 Certificate #{i}:\n"
                f"- Subject: {cert.get('subject')}\n"
                f"- Valid from: {cert.get('notBefore')}\n"
                f"- Valid until: {cert.get('notAfter')}\n"
                f"- Issuer: {cert.get('issuer')}\n"
                f"- Signature: {cert.get('sigAlg')}\n"
                f"- SHA256 Fingerprint: {cert.get('sha256')}\n\n"
            )

        return (
            f"🔐 **IP Address**: {ip}\n"
            f"🏷️ **SSL Labs Grade**: {grade}\n\n"
            f"🧾 **Certificate Chain**:\n{chain_info if chain_info else 'N/A'}"
        )
    except Exception as e:
        return f"Error fetching SSL data: {e}"

# Security Headers
def check_security_headers(domain):
    try:
        url = f"https://securityheaders.com/?q={domain}&followRedirects=on"
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        summary = soup.select_one("div.summary")
        grade = summary.get_text(strip=True) if summary else "Ouch, you should work on your security posture immediately"

        headers_section = soup.select_one("div#headers")
        raw_headers = headers_section.get_text(strip=True) if headers_section else "Unavailable"

        missing_tags = soup.select("div#missingHeaders ul li code")
        missing_summary = "\n".join(tag.get_text(strip=True) for tag in missing_tags) if missing_tags else "None"

        return (
            f"🛡️ **Security Headers Summary**: {grade}\n\n"
            f"📛 **Missing Headers**:\n{missing_summary}\n\n"
            f"📦 **Raw Headers**:\n```http\n{raw_headers}\n```"
        )
    except Exception as e:
        return f"Error fetching security headers: {e}"

# Virus Checker
def virus_check(domain):
    try:
        headers = {"x-apikey": virustotal_api_key}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return "Failed to retrieve virus data from VirusTotal."

        data = response.json()["data"]
        stats = data["attributes"]["last_analysis_stats"]
        categories = data["attributes"].get("categories", {})
        votes = data["attributes"].get("total_votes", {})

        summary = (
            f"🦠 **VirusTotal Report for {domain}**\n"
            f"🔎 Malicious: {stats['malicious']}\n"
            f"⚠️ Suspicious: {stats['suspicious']}\n"
            f"✅ Harmless: {stats['harmless']}\n"
            f"🧩 Undetected: {stats['undetected']}\n"
            f"🏷️ Categories: {', '.join(categories.values()) if categories else 'N/A'}\n"
            f"🗳️ Community Votes - Harmless: {votes.get('harmless', 0)}, Malicious: {votes.get('malicious', 0)}"
        )
        return summary
    except Exception as e:
        return f"Error checking virus status: {e}"

# Subdomain Finder using crt.sh
def subdomain_finder(domain):
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url)
        data = response.json()
        subdomains = set(entry['name_value'] for entry in data)
        return "🔍 **Subdomains Found:**\n" + "\n".join(sorted(subdomains))
    except Exception as e:
        return f"Error fetching subdomains: {e}"

# Run Flask app
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3841, debug=True)
