import socket
import dns.resolver
import dns.reversename


def get_dns_details(ip):
    """
    Lekérdezi az összes elérhető DNS információt az IP címhez kapcsolódóan.
    """
    extraction = {}
    hostname = None

    # 1. Resolver objektum létrehozása és konfigurálása
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google and Cloudflare
    my_resolver.timeout = 2.0  # Mennyi ideig várjunk egy válaszra
    my_resolver.lifetime = 2.0  # Teljes lekérdezési idő korlát

    # 2. Reverse DNS (PTR)
    try:
        rev_name = dns.reversename.from_address(ip)
        # Itt már a saját resolverünket használjuk!
        ptr_answer = my_resolver.resolve(rev_name, "PTR")
        hostname = str(ptr_answer[0]).rstrip('.')
        extraction["reverse_dns_ptr"] = hostname
    except Exception:
        extraction["reverse_dns_ptr"] = "No PTR record (NXDOMAIN)"
        hostname = None

    # 3. További DNS rekordok lekérdezése, ha van hostname
    if hostname:
        parts = hostname.split('.')
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        record_types = {
            "A": "IPv4 Address (A)",
            "MX": "Mail Exchange (MX)",
            "NS": "Name Servers (NS)",
            "TXT": "TXT records (TXT/SPF)",
            "SOA": "Zone infos (SOA)",
            "AAAA": "IPv6 Address (AAAA)"
        }

        for r_type, label in record_types.items():
            try:
                query_target = domain if r_type in ["MX", "NS", "SOA"] else hostname
                # Ismét a saját resolverünket használjuk
                answers = my_resolver.resolve(query_target, r_type)

                results = []
                for rdata in answers:
                    if r_type == "SOA":
                        results.append(f"Mname: {rdata.mname}, Rname: {rdata.rname}, Serial: {rdata.serial}")
                    else:
                        results.append(str(rdata).strip('"'))

                extraction[label] = " | ".join(results)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except Exception as e:
                extraction[label] = f"Error: {str(e)}"

        # 4. FCrDNS Check (Forward-Confirmed Reverse DNS)
        # Itt is a 8.8.8.8-at használjuk a visszakérdezéshez!
        try:
            # Megnézzük a hostname 'A' rekordját a saját resolverünkkel
            forward_answers = my_resolver.resolve(hostname, 'A')
            forward_ip = str(forward_answers[0])

            if forward_ip == ip:
                extraction["fcrdns_match (Forward-Confirmed Reverse DNS)"] = "[bold green]YES[/bold green]"
            else:
                extraction["fcrdns_match (Forward-Confirmed Reverse DNS)"] = f"[bold red]NO[/bold red] (Points to: {forward_ip})"
        except Exception:
            extraction["fcrdns_match (Forward-Confirmed Reverse DNS)"] = "[bold yellow]Unverifiable (No A record for hostname)[/bold yellow]"

    return extraction