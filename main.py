import argparse
from dotenv import load_dotenv
from rich.console import Console

from modules.network_info import get_network_details
from modules.abusedb_info import get_abuse_score
from modules.dns_info import get_dns_details
from modules.vt_intel import get_vt_score
from modules.proxy_checker import get_proxy_details


load_dotenv()
console = Console()

def print_result(title, data):
    console.print(f"\n[bold yellow]=== {title} ===[/bold yellow]")

    if "error" in data:
        console.print(f"[bold red]HIBA:[/bold red] {data['error']}")
        return

    for key, value in data.items():
        clean_key = key.replace("_", " ").title()

        is_positive = value in [True, "YES", "yes", "True"]

        # 1. Score
        if key == "score":
            color = "red" if value > 50 else "yellow" if value > 0 else "green"
            console.print(f"[cyan]{clean_key}:[/cyan] [{color}]{value}%[/{color}]")

        # 2. Whitelist
        elif key == "is_whitelisted":
            status = "[bold green]YES[/bold green]" if is_positive else "[white]NO[/white]"
            console.print(f"[cyan]{clean_key}:[/cyan] {status}")

        # 3. Etc
        elif key in ["is_tor_node", "proxy", "port_forwarding"]:
            status = "[bold red]YES[/bold red]" if is_positive else "[bold green]NO[/bold green]"
            console.print(f"[cyan]{clean_key}:[/cyan] {status}")

        # 5. Reputation
        elif key == "reputation_points":
            color = "bold red" if int(value) < 0 else "bold green"
            console.print(f"[cyan]{clean_key}:[/cyan] [{color}]{value}[/{color}]")

        # 6. DNS
        elif key == "fcrdns_match":
            status = "[bold green]YES[/bold green]" if is_positive else "[bold red]NO[/bold red]"
            console.print(f"[cyan]{clean_key}:[/cyan] {status}")

        else:
            console.print(f"[cyan]{clean_key}:[/cyan] [white]{value}[/white]")

def main():
    parser = argparse.ArgumentParser(description="IP Enrichment Tool")
    parser.add_argument("ip", help="IP address")
    args = parser.parse_args()
    target_ip = args.ip

    with console.status("[bold green]Requesting data..."):
        net_data = get_network_details(target_ip)
        print_result("Network Information", net_data)
        abuseipdb_data = get_abuse_score(target_ip)
        print_result("AbuseIPDB Information", abuseipdb_data)
        dns_data = get_dns_details(target_ip)
        print_result("DNS Information", dns_data)
        vt_data = get_vt_score(target_ip)
        print_result("VirusTotal Information", vt_data)
        proxy_data = get_proxy_details(target_ip)
        print_result("Proxy Information", proxy_data)


if __name__ == "__main__":
    main()