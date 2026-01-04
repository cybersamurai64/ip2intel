import requests
import os

def get_abuse_score(ip):
    """Requests the reputation of the IP address from AbuseIPDB"""

    api_key = os.getenv("ABUSEIPDB_KEY")

    if not api_key:
        return {"error": "API key ABUSEIPDB_KEY is missing from .env)"}

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }

    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90',  # Last 90 days
        'verbose': True
    }

    try:
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json().get('data', {})

            extracted = {
                "score": data.get('abuseConfidenceScore'),  # 0-100%
                "total_reports": data.get('totalReports'),
                "last_reported": data.get('lastReportedAt'),
                "usage_type": data.get('usageType'),
                "isp": data.get('isp'),
                "domain": data.get('domain'),
                "is_whitelisted": data.get('isWhitelisted'),
                "country_name": data.get('countryName'),
                "is_tor_node": data.get('isTor'),
            }

            reports = data.get('reports') or []
            if reports:
                last_report = reports[0]  # Latest report
                extracted["last_report_date"] = last_report.get('reportedAt')

                comment = last_report.get('comment')
                if comment:
                    extracted["last_report_comment"] = comment.strip().replace('\n', ' ')

            return extracted

        elif response.status_code == 401:
            return {"error": "Invalid API key"}
        elif response.status_code == 429:
            return {"error": "Daily query limit reached"}
        else:
            return {"error": f"API error: {response.status_code}"}

    except Exception as e:
        return {"error": f"Connection failed: {str(e)}"}
