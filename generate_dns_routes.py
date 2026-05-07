import argparse
import ipaddress
import urllib.request
import urllib.error
import os

def read_list(source, sections=None, is_local=False):
    """Reads the list from URL or local file and cleans comments/empty lines."""
    try:
        if is_local:
            with open(source, 'r', encoding='utf-8') as f:
                lines = f.read().splitlines()
        else:
            with urllib.request.urlopen(source, timeout=10) as response:
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
    except (urllib.error.URLError, IOError) as e:
        print(f"Error reading the list from {source}: {e}")
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

def main():
    """Main function to parse arguments and generate Keenetic configuration."""
    parser = argparse.ArgumentParser(description="Generate Keenetic network configuration from IP and domain lists.")
    parser.add_argument("-o", "--output", type=str, help="Save the output to the specified file.")
    parser.add_argument("-s", "--section", type=str, help="Extract specific section(s), comma-separated (e.g., 'Whatsapp,Telegram').")
    parser.add_argument("-l", "--local", action="store_true", help="Use local files instead of downloading from GitHub.")

    args = parser.parse_args()

    if args.local:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        ip_source = os.path.join(script_dir, "ip_list.txt")
        domain_source = os.path.join(script_dir, "domain_list.txt")
    else:
        ip_source = "https://raw.githubusercontent.com/ucvu/ip-addresses/refs/heads/main/ip_list.txt"
        domain_source = "https://raw.githubusercontent.com/ucvu/ip-addresses/refs/heads/main/domain_list.txt"

    sections_list = args.section.split(',') if args.section else None
    
    ip_list = read_list(ip_source, sections_list, args.local)
    domain_list = read_list(domain_source, sections_list, args.local)
    
    parts = []
    if ip_list:
        collapsed_ips = collapse_ip_list(ip_list)
        parts.extend(collapsed_ips)
    if domain_list:
        parts.extend(domain_list)
        
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