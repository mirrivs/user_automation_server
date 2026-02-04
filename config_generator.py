import random

from models.client_config import User


class ConfigGenerator:
    def __init__(self, user_credentials: User, generator_config: dict):
        self.user_credentials = user_credentials
        self.generator_config = generator_config

        self.conversation_starter_frequency = (
            self.generator_config.get("conversation_starter_frequency", 2) - 1
        )
        # Updated to use new structure: behaviour.behaviours instead of user_behaviour
        self.automation_config = self.generator_config.get("automation", {})
        self.idle_cycle_template = self.automation_config.get("idle_cycle", {})
        self.behaviours_templates = self.automation_config.get("behaviours", {})

        self.is_conversation_starter_counter = 0
        self.email_receivers_list = []

    def generate_config(self, email: str) -> dict:
        client_config = {}
        
        # Add general configuration
        general_config = {
            "is_conversation_starter": False,
        }

        # Add idle_cycle configuration from template
        idle_cycle_config = {}
        for param_name, param_value in self.idle_cycle_template.items():
            idle_cycle_config[param_name] = self._handle_param_value(param_value)

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

        # Generate configuration for all behaviours defined in the template
        for behaviour_name, behaviour_template in self.behaviours_templates.items():
            behaviour_config = self._generate_behaviour_config(behaviour_template)
            if behaviour_config:
                behaviours_config[behaviour_name] = behaviour_config

        # Add work_emails configuration if it was generated from conversation logic
        if work_emails_config:
            # Merge with any existing work_emails config from template
            if "work_emails" in behaviours_config:
                behaviours_config["work_emails"].update(work_emails_config)
            else:
                behaviours_config["work_emails"] = work_emails_config

        # Build the user behaviour structure according to your BaseModel
        client_config["automation"] = {
            "general": general_config,
            "idle_cycle": idle_cycle_config,
            "behaviours": behaviours_config
        }

        return client_config

    def _generate_behaviour_config(self, behaviour_template: dict) -> dict:
        """Generate configuration for a specific behaviour based on its template."""
        behaviour_config = {}
        
        for param_name, param_value in behaviour_template.items():
            generated_value = self._handle_param_value(param_value)
            behaviour_config[param_name] = generated_value
            
        return behaviour_config

    def _handle_param_value(self, param_value):
        """Handle parameter value that can be either a direct value, a range dict, or nested dict."""
        if isinstance(param_value, dict):
            if set(param_value.keys()) == {"min", "max"}:
                return self._generate_random_value_in_range(param_value["min"], param_value["max"])
            else:
                result = {}
                for key, value in param_value.items():
                    result[key] = self._handle_param_value(value)
                return result
        elif isinstance(param_value, list):
            return [self._handle_param_value(item) for item in param_value]
        else:
            # Direct value, return as-is
            return param_value

    def _generate_random_value_in_range(self, a, b):
        """Generate a random value between a and b."""
        random_value = random.uniform(a, b)
        if random_value > 1:
            random_value = round(random_value)
        return random_value