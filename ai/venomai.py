from flask import Flask, render_template, request, jsonify
from phi.agent import Agent
from phi.model.openai import OpenAIChat
import os
import subprocess
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import time

# Load environment variables from ai/.env
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
openai_api_key = os.getenv("OPENAI_API_KEY")
vt_api_key = "b9ed4f9ef22d2ffa5546270d24087a2a5c2a42afd36ae832f2314c8a2dd4f3c0"

if not openai_api_key:
    raise ValueError("OPENAI_API_KEY not set in .env file or environment")

app = Flask(__name__, template_folder="../homepage", static_folder="../static")

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
        elif selected_plugin == "security_headers":
            return jsonify({"response": security_headers_check(user_input)})
        elif selected_plugin == "virus_check":
            return jsonify({"response": virus_total_domain_check(user_input)})
        elif selected_plugin == "subdomain_finder":
            return jsonify({"response": find_subdomains_crtsh(user_input)})
        else:
            response = web_agent.run(message=user_input)
            response_text = response if isinstance(response, str) else response.content
            return jsonify({"response": response_text})

    except Exception as e:
        return jsonify({"response": f"Error: {str(e)}"})

def run_nmap_scan(target):
    try:
        result = subprocess.run(["nmap", "-p-", target], capture_output=True, text=True)
        if result.returncode == 0:
            return jsonify({"response": f"```bash\n{result.stdout}\n```"})
        else:
            return jsonify({"response": "Error running Nmap scan."})
    except Exception as e:
        return jsonify({"response": f"Error running Nmap: {str(e)}"})

def get_whois_data(domain):  
    try:  
        whois_url = f'https://www.whois.com/whois/{domain}'  
        response = requests.get(whois_url)  
        soup = BeautifulSoup(response.text, 'html.parser')  
        whois_info = soup.find('pre')
        return whois_info.text.strip() if whois_info else "WHOIS information is not publicly available."
    except Exception as e:  
        return f"Error fetching Whois data: {e}"  

def find_pages(website):  
    try:  
        info = requests.get(f'https://api.hackertarget.com/pagelinks/?q={website}')  
        info.raise_for_status()
        return info.text
    except requests.exceptions.RequestException as err:  
        return f"Error fetching page links: {err}"  

def get_ip_info(ip_address):  
    try:  
        ipinfo_url = f'https://ipinfo.io/{ip_address}/json'  
        response = requests.get(ipinfo_url)  
        if response.status_code == 401:  
            return "Invalid API key or unauthorized request."  
        return response.json()
    except Exception as e:  
        return f"Error fetching IP info: {e}"  

def dns_lookup(website):  
    try:  
        info = requests.get(f'https://api.hackertarget.com/dnslookup/?q={website}')  
        info.raise_for_status()
        return info.text  
    except requests.exceptions.RequestException as err:  
        return f"Error performing DNS lookup: {err}"  

def security_headers_check(domain):
    try:
        url = f"https://securityheaders.com/?q={domain}&followRedirects=on"
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers)
        soup = BeautifulSoup(resp.text, "html.parser")

        summary = soup.find("div", class_="summary").text.strip() if soup.find("div", class_="summary") else "Unknown"
        missing = soup.find_all("tr", class_="grade-F")
        missing_headers = [m.find_all("td")[0].text.strip() for m in missing] if missing else []

        raw_table = soup.find("table", class_="table table-striped table-bordered")
        raw_data = []
        if raw_table:
            for row in raw_table.find_all("tr")[1:]:
                cols = row.find_all("td")
                if len(cols) >= 2:
                    raw_data.append(f"{cols[0].text.strip()}: {cols[1].text.strip()}")

        missing_summary = "\n".join(missing_headers)
        raw_headers = "\n".join(raw_data)

        return (
            f"🛡️ Security Headers Summary: {summary}\n\n"
            f"📛 Missing Headers:\n{missing_summary if missing_summary else 'None'}\n\n"
            f"📦 Raw Headers:\nhttp\n{raw_headers}"
        )
    except Exception as e:
        return f"Error fetching security headers: {e}"

def virus_total_domain_check(domain):
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": vt_api_key}
        response = requests.get(url, headers=headers)
        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]
        categories = data["data"]["attributes"].get("categories", {})
        reputation = data["data"]["attributes"].get("reputation", "N/A")
        ranks = data["data"]["attributes"].get("popularity_ranks", {})

        categories_text = "\n".join(f"- {k}: {v}" for k, v in categories.items())
        ranks_text = "\n".join(f"- {k}: {v.get('rank', 'N/A')}" for k, v in ranks.items())

        return (
            f"🔍 **VirusTotal Domain Check for {domain}**\n\n"
            f"🛡️ **Reputation Score**: {reputation}\n\n"
            f"📊 **Detection Stats**:\n"
            f"- Harmless: {stats.get('harmless', 0)}\n"
            f"- Malicious: {stats.get('malicious', 0)}\n"
            f"- Suspicious: {stats.get('suspicious', 0)}\n"
            f"- Undetected: {stats.get('undetected', 0)}\n"
            f"- Timeout: {stats.get('timeout', 0)}\n\n"
            f"🏷️ **Categories**:\n{categories_text}\n\n"
            f"📈 **Popularity Ranks**:\n{ranks_text}"
        )
    except Exception as e:
        return f"Error checking VirusTotal domain: {e}"

def find_subdomains_crtsh(domain):
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return "Failed to fetch subdomains."
        results = response.json()
        subdomains = {entry['name_value'] for entry in results}
        formatted = "\n".join(sorted(subdomains))
        return f"🔍 Subdomains for {domain}:\n\n{formatted}"
    except Exception as e:
        return f"Error fetching subdomains: {e}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3841, debug=True)