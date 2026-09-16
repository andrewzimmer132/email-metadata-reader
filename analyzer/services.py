import requests
import json

class IpApiContainer:
    JSON_URL = "http://ip-api.com/json/{query}"
    BATCH_URL = "http://ip-api.com/batch"

    BATCH_MAX_SIZE = 100

    """
    Get information for a single IP address using the JSON API.
        Args:
            ip_address (str): The IP address to query.
        Returns:
            dict: A dictionary of the information for the IP address.
    """
    def get_single_ip_info(self, ip_address: str) -> dict:
        if len(ip_address) == 0:
            raise ValueError("IP address cannot be empty.")
        url = self.JSON_URL.format(query=ip_address)
        response = requests.get(url)
        response.raise_for_status()
        return response.json()

    """
    Get information for multiple IP addresses using the batch API.
        Args:
            ip_addresses (list[str]): A list of IP addresses to query.
        Returns:
            dict: A dictionary of the information for each IP address.
    """
    def get_multiple_ip_info(self, ip_addresses: list[str]) -> dict:
        if len(ip_addresses) == 0:
            raise ValueError("IP addresses list cannot be empty.")
        if len(ip_addresses) > self.BATCH_MAX_SIZE:
            raise ValueError(f"Number of IP addresses exceeds the maximum limit of {self.BATCH_MAX_SIZE}.")
        ip_addr_json = json.dumps(ip_addresses)
        response = requests.post(self.BATCH_URL, data=ip_addr_json)
        response.raise_for_status()
        return response.json()
