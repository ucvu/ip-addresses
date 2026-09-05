from generate_geo_domains import build_custom_domain_blocks, build_custom_ip_blocks


def test_domain_entries_are_split_between_domain_and_ip_files():
    services = [
        "domain:103.224.0.0/16",
        "domain:cdn.discord.app",
        "domain:203.0.113.10",
        "geosite:discord",
    ]

    assert build_custom_domain_blocks(services) == [
        ("# Custom", ["cdn.discord.app"]),
    ]
    assert build_custom_ip_blocks(services) == [
        ("# Custom IP", ["103.224.0.0/16", "203.0.113.10"]),
    ]