from ipwhois import IPWhois

def get_network_details(ip):
    """Requests the IP address's network details (ASN, Owner, Country)"""
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()

        return {
            "asn": results.get('asn'),
            "asn_description": results.get('asn_description'),
            "country": results.get('asn_country_code'),
            "range": results.get('network', {}).get('cidr')
        }
    except Exception as e:
        return {"error": f"Hálózati hiba: {str(e)}"}