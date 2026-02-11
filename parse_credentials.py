import yaml


def parse_user_credentials(credentials_filepath: str) -> dict:
    """
    Parse user credentials and return as a dict with keys matching the YAML structure.
    """
    with open(credentials_filepath, "r") as stream:
        yaml_data = yaml.safe_load(stream)

        result = {}
        for key, users in yaml_data.items():
            if not users:
                continue
            result[key] = [
                {
                    "username": user.split(":{plain}")[0],
                    "password": user.split(":{plain}")[1],
                }
                for user in users
            ]

        return result
