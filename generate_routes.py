import argparse
import ipaddress
import urllib.request
import urllib.error

def download_list(url, sections=None):
    """Downloads the list from the given URL and cleans comments/empty lines."""
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            lines = response.read().decode('utf-8').splitlines()
            clean_lines = []

            if not sections:
                # No section filter, process all non-comment lines
                for line in lines:
                    clean_line = line.split('#')[0].strip()
                    if clean_line:
                        clean_lines.append(clean_line)
                return clean_lines

            # Section filter is active
            in_target_section = False
            sections_lower = [s.strip().lower() for s in sections]

            for line in lines:
                stripped_line = line.strip()

                if stripped_line.startswith('#'):
                    header_text = stripped_line.lstrip('#').strip().lower()
                    in_target_section = any(s_lower in header_text for s_lower in sections_lower)
                    continue

                if not stripped_line:
                    in_target_section = False
                    continue

                if in_target_section:
                    clean_line = stripped_line.split('#')[0].strip()
                    if clean_line:
                        clean_lines.append(clean_line)

            return clean_lines
    except urllib.error.URLError as e:
        print(f"Error downloading the list: {e}")
        return None

def collapse_ip_list(ip_list):
    """Removes duplicates and collapses overlapping/adjacent subnets."""
    ipv4_nets, ipv6_nets = [], []
    for cidr in ip_list:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.version == 4:
                ipv4_nets.append(network)
            else:
                ipv6_nets.append(network)
        except ValueError as e:
            print(f"Skipping invalid CIDR '{cidr}': {e}")
    
    collapsed = list(ipaddress.collapse_addresses(ipv4_nets)) + list(ipaddress.collapse_addresses(ipv6_nets))
    return [str(net) for net in collapsed]

def generate_wireguard_config(ip_list):
    """Generates a comma-separated string for WireGuard."""
    return ", ".join(ip_list)

def generate_keenetic_config(ip_list):
    """Generates 'route add' commands for Keenetic."""
    routes = []
    for cidr in ip_list:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            route_command = f"route add {network.network_address} mask {network.netmask} 0.0.0.0"
            routes.append(route_command)
        except ValueError as e:
            print(f"Skipping invalid CIDR '{cidr}': {e}")
    return "\n".join(routes)

def main():
    """Main function to parse arguments and generate output."""
    parser = argparse.ArgumentParser(description="Generate network configuration from an IP list.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--wireguard", "--wg", action="store_true", help="Generate WireGuard AllowedIPs string.")
    group.add_argument("--keenetic", "--ke", action="store_true", help="Generate Keenetic 'route add' commands.")
    group.add_argument("-d", "--domains", action="store_true", help="Download and output domains list.")
    parser.add_argument("-o", "--output", type=str, help="Save the output to the specified file.")
    parser.add_argument("-s", "--section", type=str, help="Extract specific section(s), comma-separated (e.g., 'Whatsapp,Telegram').")

    args = parser.parse_args()

    ip_url = "https://raw.githubusercontent.com/ucvu/ip-addresses/refs/heads/main/ip_list.txt"
    domain_url = "https://raw.githubusercontent.com/ucvu/ip-addresses/refs/heads/main/domain_list.txt"
    main_url = "https://raw.githubusercontent.com/ucvu/ip-addresses/refs/heads/main/main_list.txt"

    sections_list = args.section.split(',') if args.section else None
    output_data = ""

    if args.domains:
        domain_list = download_list(domain_url, sections_list)
        if domain_list:
            output_data = "\n".join(domain_list)
    elif args.wireguard:
        ip_list = download_list(main_url, sections_list)
        if ip_list:
            collapsed_ips = collapse_ip_list(ip_list)
            output_data = generate_wireguard_config(collapsed_ips)
    elif args.keenetic:
        ip_list = download_list(ip_url, sections_list)
        domain_list = download_list(domain_url, sections_list)
        
        parts = []
        if ip_list:
            collapsed_ips = collapse_ip_list(ip_list)
            parts.append("\n# IP Routes\n" + generate_keenetic_config(collapsed_ips))
        if domain_list:
            parts.append("\n# Domains\n" + "\n".join(domain_list))
            
        output_data = "\n".join(parts)

    if output_data:
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output_data)
                print(f"Success! Configuration saved to: {args.output}")
            except IOError as e:
                print(f"Error saving to file: {e}")
        else:
            print(output_data)

if __name__ == "__main__":
    main()
