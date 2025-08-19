import random

from models.client_config import User


class ConfigGenerator:
    def __init__(self, user_credentials: User, generator_config: dict):
        self.user_credentials = user_credentials
        self.generator_config = generator_config

        self.conversation_starter_frequency = (
            self.generator_config.get("conversation_starter_frequency", 2) - 1
        )
        self.user_behaviour = self.generator_config.get("user_behaviour", {})

        self.is_conversation_starter_counter = 0
        self.email_receivers_list = []

    def generate_config(self, email: str) -> dict:
        client_config = {}
        
        # Add general configuration
        general_config = {
            "is_conversation_starter": False,
        }

        # Add idle_cycle configuration
        idle_cycle_config = {
            "procrastination_chance": self.generator_config.get("procrastination_chance", 0.5)
        }

        # Initialize behaviours structure
        behaviours_config = {}
        work_emails_config = {}

        # Email conversation logic
        if self.is_conversation_starter_counter != self.conversation_starter_frequency:
            self.is_conversation_starter_counter += 1
            self.email_receivers_list.append(email)
        else:
            general_config["is_conversation_starter"] = True
            work_emails_config["email_receivers"] = self.email_receivers_list

            self.is_conversation_starter_counter = 0
            self.email_receivers_list = []

        # Add procrastination configuration
        procrastination_config = {}
        procrastination_params = self.user_behaviour.get("procrastination", {})
        
        if procrastination_params:
            param_names = ["procrastination_preference", "procrastination_max_time", "procrastination_min_time"]
            for param_name in param_names:
                if param_name in procrastination_params:
                    procrastination_config[param_name] = self._handle_param_value(
                        procrastination_params[param_name]
                    )

        # Add attack_phishing configuration if needed
        attack_phishing_config = {}
        if "attack_phishing" in self.user_behaviour:
            attack_phishing_params = self.user_behaviour["attack_phishing"]
            if "malicious_email_subject" in attack_phishing_params:
                attack_phishing_config["malicious_email_subject"] = attack_phishing_params["malicious_email_subject"]

        # Build behaviours structure
        if procrastination_config:
            behaviours_config["procrastination"] = procrastination_config
        if work_emails_config:
            behaviours_config["work_emails"] = work_emails_config
        if attack_phishing_config:
            behaviours_config["attack_phishing"] = attack_phishing_config

        # Build the user behaviour structure according to your BaseModel
        user_behaviour = {
            "general": general_config,
            "idle_cycle": idle_cycle_config,
            "behaviours": behaviours_config
        }

        client_config["behaviour"] = user_behaviour

        return client_config

    def _handle_param_value(self, param_value):
        """Handle parameter value that can be either a direct value or a range dict."""
        if isinstance(param_value, dict) and "min" in param_value and "max" in param_value:
            return self._generate_random_value_in_range(param_value["min"], param_value["max"])
        return param_value

    def _generate_random_value_in_range(self, a, b):
        random_value = random.uniform(a, b)
        if random_value > 1:
            random_value = round(random_value)
        return random_value