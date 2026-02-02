from flask import Flask, Response, request
from flask_wtf import CSRFProtect
import re
import os
import logging
import logging.config
import sys
import datetime
import yaml
import json

parent_dir = os.path.dirname(os.path.abspath(__file__))
config_file = os.path.join(parent_dir, "config.yml")

# Read config
with open(config_file, "r") as stream:
    try:
        cfg = yaml.safe_load(stream)
    except yaml.YAMLError as ex:
        print(f"Error reading configuration from '{config_file}': {ex}")
        sys.exit(1)

# Logging config
if "logging" in cfg.keys():
    try:
        # Create the log folder if it does not exist
        log_folder_path = cfg["logging"]["handlers"]["file"]["filename"]
        log_folder = os.path.dirname(log_folder_path)
        try:
            if not os.path.exists(log_folder):
                os.makedirs(log_folder)
        except Exception as ex:
            print(f"Can not create log folder {log_folder}: {ex}")
        logging.config.dictConfig(cfg["logging"])
    except Exception as ex:
        log_folder = None
        print(f"Exception raised while creating logger: {ex}")
        sys.exit(2)

log_file = os.path.join(log_folder, "logs.log") if log_folder else None

logging.basicConfig(
    filename=log_file,
    filemode="a",
    format=cfg["logging"]["formatters"]["simple"]["format"],
    datefmt=cfg["logging"]["formatters"]["simple"]["datefmt"],
    level=logging.DEBUG
)

loggerTmp = logging.getLogger("autoconfig")
stdoutLogger = logging.StreamHandler(stream=sys.stdout)
stdoutLogger.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
loggerTmp.addHandler(stdoutLogger)


def read_yaml_file(file):
    with open(file, "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            return f"Error reading yaml file: {exc}"


app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app)

# Regular expression for validating an Email
email_regex = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


@app.route("/", methods=["GET"])
def get_config():
    config_dir = cfg["app"]["automation_cfg_dir"]
    config_files = os.listdir(config_dir)

    args = request.args
    if "hostname" not in args:
        return "No hostname provided.", 400

    hostname = request.args.get("hostname")
    if not hostname.isalnum():
        return "Invalid hostname.", 400

    pop = int(request.args.get("pop", 0))

    response = {}

    for hostname_int in ["default", hostname]:
        # Config file handling
        client_cfg_file_name = f"{hostname_int}.yml"
        if client_cfg_file_name in config_files:
            client_cfg_file = os.path.join(config_dir, client_cfg_file_name)

            data = read_yaml_file(client_cfg_file)
            if data is not None and "user" in data:
                response["user"] = data["user"]

    # Run_once file handling
    run_once_file_name = f"{hostname}_once.yml"
    if run_once_file_name in config_files:
        run_once_file = os.path.join(config_dir, run_once_file_name)

        data = read_yaml_file(run_once_file)
        if data is not None and "behaviour" in data:
            response["behaviour"] = data["behaviour"]

        if pop == 1:
            timestamp = datetime.datetime.now().strftime("%H%M%S")
            new_run_once_file_name = f"{hostname}_{timestamp}.yml"
            new_run_once_file = os.path.join(config_dir, new_run_once_file_name)
            os.rename(run_once_file, new_run_once_file)

    if response == {}:
        return "No config files found for the provided hostname.", 404

    loggerTmp.info(f"{hostname} {request.remote_addr} Replied {', '.join(response.keys())} configurations")
    return Response(yaml.dump(response), 200, mimetype="text/yaml")


@app.route("/", methods=["POST"])
def post_status():
    data = json.loads(request.json)
    data = request.get_json()
    try:
        tags = ",".join(data["tags"])
        loggerTmp.info(
            f"{data['hostname']} {request.remote_addr} Received status: {'success' if data['status'] else 'failure'} for {data['behaviour']} behaviour. Tags: {tags}")
    except Exception as ex:
        print(f"Error while trying to read post json data. Err: {ex}")
        return "Error while trying to read post json data.", 500
    return "Thanks", 200


if __name__ == "__main__":
    app.run()
