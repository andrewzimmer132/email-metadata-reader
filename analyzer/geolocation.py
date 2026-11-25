import geoip2.database

DATABASE_PATH = "geoip/GeoLite2-City/GeoLite2-City.mmdb"

ASN_DATABASE_PATH = (
    "geoip/GeoLite2-ASN/GeoLite2-ASN.mmdb"
)

def lookup_ip(ip):
    with geoip2.database.Reader(DATABASE_PATH) as reader:
        try:
            response = reader.city(ip)

            return {
                "country": response.country.name,
                "region": response.subdivisions.most_specific.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
            }

        except geoip2.errors.AddressNotFoundError:
            return None

def lookup_asn(ip):
    with geoip2.database.Reader(ASN_DATABASE_PATH) as reader:
        try:
            response = reader.asn(ip)

            return {
                "asn": response.autonomous_system_number,
                "organization": (
                    response.autonomous_system_organization
                ),
                "network": str(response.network),
            }

        except geoip2.errors.AddressNotFoundError:
            return None

def add_location_and_network_info(received):
    for hop in received:
        ip = hop.get("ip")
        hop["location"] = None
        hop["network"] = None

        if ip:
            hop["location"] = lookup_ip(ip)
            hop["network"] = lookup_asn(ip)

    return received