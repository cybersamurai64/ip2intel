import requests
import os

def get_proxy_details(ip):
    api_key = os.getenv("PROXYCHECK_API_KEY")
    if not api_key:
        return {"error": "Missing PROXYCHECK_API_KEY from .env file!"}

    url = f"https://proxycheck.io/v2/{ip}?key={api_key}&vpn=1&asn=1"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            res = data.get(ip, {})

            operator_info = res.get("operator", {})
            operator = res.get("operator", {})
            policies = operator.get("policies", {})

            extraction = {
                "proxy": res.get("proxy", "no").upper(),
                "type": res.get("type", "N/A"),
                "vpn_operator": operator_info.get("name", "N/A"),
                "protocols": ", ".join(operator_info.get("protocols", [])) if operator_info.get("protocols") else "N/A",
                "hostname": res.get("hostname", "N/A"),
                "provider": res.get("provider", "N/A"),
                "organisation": res.get("organisation", "N/A"),
                "asn": res.get("asn", "N/A"),
                "location": f"{res.get('city', 'N/A')}, {res.get('country', 'N/A')} ({res.get('continent', 'N/A')})",
                "coordinates": f"{res.get('latitude', 0)}, {res.get('longitude', 0)}",
                "timezone": res.get("timezone", "N/A"),
                "anonymity_level": operator_info.get("anonymity", "N/A"),
                "popularity": operator_info.get("popularity", "N/A"),
                "port_forwarding": "ENABLED" if policies.get("port_forwarding") == "yes" else "Disabled",
                "no_logging": "YES" if operator_info.get("policies", {}).get("logging") == "no" else "Unknown",
                "free_access": "YES" if policies.get("free_access") == "yes" else "No",
                "risk_score": res.get("risk", 0)
            }
            return extraction
        else:
            return {"error": f"ProxyCheck error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}