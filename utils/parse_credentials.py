import yaml


def parse_user_credentials(credentials_filepath: str) -> tuple[list[dict], list[dict]]:
    """
    Parse user credentials and return as a tuple of exchange and domain credentials
    """
    with open(credentials_filepath, "r") as stream:
        yaml_data = yaml.safe_load(stream)

        exchange_credentials = [
            {
                "username": user.split(":{plain}")[0],
                "password": user.split(":{plain}")[1],
            }
            for user in yaml_data.get("exchange_credentials", [])
        ]

        domain_credentials = [
            {
                "username": user.split(":{plain}")[0],
                "password": user.split(":{plain}")[1],
            }
            for user in yaml_data.get("domain_credentials", [])
        ]

        # Remove duplicate items from domain credentials
        domain_credentials = [
            creds for creds in domain_credentials if creds not in exchange_credentials
        ]

        return exchange_credentials, domain_credentials
