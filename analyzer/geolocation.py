import geoip2.database

DATABASE_PATH = "geoip/GeoLite2-City/GeoLite2-City_20260929/GeoLite2-City.mmdb"


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