from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from client import broadcast_client_status, client_sockets, clients_info, get_reported_behaviours
from service_auth import require_service_token

router = APIRouter()


class WorkCycleAction(str, Enum):
    START = "start"
    STOP = "stop"


class AvailableBehaviors(str, Enum):
    ATTACK_PHISHING = "attack_phishing"
    ATTACK_PHISHING_ATTACHMENT = "attack_phishing_attachment"
    ATTACK_RANSOMWARE = "attack_ransomware"
    ATTACK_REVERSE_SHELL = "attack_reverse_shell"
    PROCRASTINATION = "procrastination"
    WORK_EMAILS = "work_emails"
    WORK_ORGANIZATION_WEB = "work_organization_web"


# Configuration models for each behavior
class AttackPhishingConfig(BaseModel):
    """Configuration for phishing attack behavior"""

    malicious_email_subject: str = Field(..., description="Malicious email subject")


class AttackPhishingAttachmentConfig(BaseModel):
    """Configuration for phishing attachment attack behavior"""

    malicious_email_subject: str = Field(..., description="Malicious email subject")


class AttackRansomwareConfig(BaseModel):
    """Configuration for ransomware attack behavior"""

    file_extensions: List[str] = Field(default=[".txt", ".doc", ".pdf"], description="File extensions to target")
    encryption_key: str = Field(..., min_length=16, description="Encryption key (minimum 16 characters)")
    ransom_message: str = Field(..., description="Ransom note message")
    delay_seconds: int = Field(default=60, ge=0, le=3600, description="Delay before execution (0-3600 seconds)")


class AttackReverseShellConfig(BaseModel):
    """Configuration for reverse shell attack behavior"""

    target_host: str = Field(..., description="Target host IP or domain")
    target_port: int = Field(..., ge=1, le=65535, description="Target port (1-65535)")
    connection_timeout: int = Field(default=30, ge=5, le=300, description="Connection timeout in seconds")
    retry_attempts: int = Field(default=3, ge=1, le=10, description="Number of retry attempts")


class ProcrastinationConfig(BaseModel):
    """Configuration for procrastination behavior - all fields optional with defaults"""

    websites: List[str] = Field(default=["youtube.com", "reddit.com", "twitter.com"], description="Websites to visit")
    visit_duration_minutes: int = Field(default=15, ge=1, le=120, description="Duration per website visit")
    randomize_order: bool = Field(default=True, description="Randomize website visit order")
    break_frequency_minutes: int = Field(default=60, ge=5, le=480, description="Break frequency in minutes")


class WorkEmailsConfig(BaseModel):
    """Configuration for work emails behavior - requires email accounts"""

    email_accounts: List[str] = Field(..., description="List of email accounts to monitor")
    check_frequency_minutes: int = Field(default=5, ge=1, le=60, description="Email check frequency")
    auto_reply: bool = Field(default=False, description="Enable auto-reply")
    priority_keywords: List[str] = Field(default=["urgent", "asap", "important"], description="Priority keywords")


class WorkOrganizationWebConfig(BaseModel):
    """Configuration for work organization web behavior - all fields optional with defaults"""

    websites: List[str] = Field(default=[], description="Work-related websites to organize")
    bookmark_categories: List[str] = Field(
        default=["productivity", "tools", "documentation"], description="Bookmark categories"
    )
    cleanup_frequency_hours: int = Field(default=24, ge=1, le=168, description="Cleanup frequency in hours")
    backup_enabled: bool = Field(default=True, description="Enable backup of bookmarks")


# Response models
class BehaviorResponse(BaseModel):
    """Standard response for behavior operations"""

    message: str
    status: str
    client_username: str
    behaviour_id: str
    config_keys: List[str] = Field(default_factory=list)
    clients_notified: int
    validated_config: Optional[Dict[str, Any]] = None


class BehaviorRunResponse(BehaviorResponse):
    """Response for behavior run operations"""

    config_updated: bool = False


# Define which behaviors require mandatory configuration
BEHAVIORS_REQUIRING_CONFIG = {
    AvailableBehaviors.ATTACK_PHISHING,
    AvailableBehaviors.ATTACK_RANSOMWARE,
    AvailableBehaviors.ATTACK_REVERSE_SHELL,
}

# Define which behaviors can run without any configuration
BEHAVIORS_WITHOUT_CONFIG = {
    AvailableBehaviors.PROCRASTINATION,
    AvailableBehaviors.WORK_ORGANIZATION_WEB,
    AvailableBehaviors.WORK_EMAILS,
}

# Mapping behaviors to their config models
BEHAVIOR_CONFIG_MAPPING = {
    AvailableBehaviors.ATTACK_PHISHING: AttackPhishingConfig,
    AvailableBehaviors.ATTACK_RANSOMWARE: AttackRansomwareConfig,
    AvailableBehaviors.ATTACK_REVERSE_SHELL: AttackReverseShellConfig,
    AvailableBehaviors.PROCRASTINATION: ProcrastinationConfig,
    AvailableBehaviors.WORK_ORGANIZATION_WEB: WorkOrganizationWebConfig,
}


# Map JSON-schema types (from the Pydantic models) to simple UI field types.
_JSON_TYPE_MAP = {
    "integer": "int",
    "number": "float",
    "string": "string",
    "boolean": "bool",
    "array": "list",
}


def behaviour_config_fields(model) -> List[dict]:
    """Derive a UI-friendly field descriptor list from a behaviour's config model."""
    if model is None:
        return []

    schema = model.schema()
    required = set(schema.get("required", []))
    fields: List[dict] = []

    for name, prop in schema.get("properties", {}).items():
        field = {
            "name": name,
            "type": _JSON_TYPE_MAP.get(prop.get("type"), "string"),
            "required": name in required,
        }
        if prop.get("type") == "array":
            field["item_type"] = _JSON_TYPE_MAP.get(prop.get("items", {}).get("type"), "string")
        for src, dst in (
            ("default", "default"),
            ("description", "description"),
            ("minimum", "min"),
            ("maximum", "max"),
            ("minLength", "min_length"),
            ("maxLength", "max_length"),
        ):
            if src in prop:
                field[dst] = prop[src]
        fields.append(field)

    return fields


@router.get(
    "/behaviours",
    description="List all available behaviours with their configuration field schema, "
    "derived from the behaviour config models. Used by the wizard to render run forms.",
    dependencies=[Depends(require_service_token)],
)
async def list_behaviours() -> List[dict]:
    """Return every behaviour, whether it needs config, and its config field descriptors."""
    return [
        {
            "id": behaviour.value,
            "requires_config": behaviour in BEHAVIORS_REQUIRING_CONFIG,
            "fields": behaviour_config_fields(BEHAVIOR_CONFIG_MAPPING.get(behaviour)),
        }
        for behaviour in AvailableBehaviors
    ]


# Helper function to reject requests targeting a user that has never registered with the server
def ensure_client_known(client_username: str) -> None:
    """Reject the request if no client has ever reported in as this user.

    Distinct from "not currently connected": that means the user exists but
    is offline right now, whereas this means the username itself is unknown
    to the server.
    """
    known_username = any(info.get("username") == client_username for info in clients_info.values())
    if not known_username:
        raise HTTPException(
            status_code=404,
            detail=f"User '{client_username}' does not exist on the server",
        )


# Helper function to enforce client-reported behaviour availability
def ensure_behaviour_available(client_username: str, behaviour_id: AvailableBehaviors) -> None:
    """Reject the request if the target client cannot run the behaviour.

    Availability comes from the workstation's Ansible-rendered toggle map. A
    behaviour outside that set is refused before any command is sent. Clients
    that have not reported capabilities fail closed until they are upgraded.
    """
    ensure_client_known(client_username)

    connected = any(
        info.get("username") == client_username and info.get("connected", True) for info in clients_info.values()
    )
    if not connected:
        # Client exists but is offline right now, so no reported capability set
        # is available to check against. Let the caller's own connectivity
        # check report the accurate "not currently connected" error instead
        # of a misleading "behaviour not available".
        return

    available = get_reported_behaviours(client_username)
    if behaviour_id.value not in available:
        raise HTTPException(
            status_code=403,
            detail=f"Behaviour '{behaviour_id.value}' is not available on client '{client_username}'",
        )


# Helper function to validate config based on behavior
def validate_behavior_config(behaviour_id: AvailableBehaviors, behaviour_config: Optional[dict]) -> Optional[dict]:
    """Validate configuration against the specific behavior model"""

    # If no config provided
    if behaviour_config is None:
        if behaviour_id in BEHAVIORS_WITHOUT_CONFIG:
            # These behaviors run without any configuration
            return None
        elif behaviour_id in BEHAVIORS_REQUIRING_CONFIG:
            raise HTTPException(status_code=422, detail=f"Configuration is required for {behaviour_id.value}")
        return None

    # If config is provided, validate it
    config_model = BEHAVIOR_CONFIG_MAPPING.get(behaviour_id)
    if not config_model:
        return behaviour_config

    try:
        validated_config = config_model(**behaviour_config)
        return validated_config.dict()
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid configuration for {behaviour_id.value}: {str(e)}")


@router.post(
    "/update_config",
    response_model=BehaviorResponse,
    description="""Update configuration parameters
    for a specific behaviour on a connected client. Configuration is validated based on the behavior type.""",
    dependencies=[Depends(require_service_token)],
)
async def update_behaviour_config(
    client_username: str, behaviour_id: AvailableBehaviors, behaviour_config: Optional[dict] = None
) -> BehaviorResponse:
    """
    Update behaviour configuration for a specific client with validation.

    Args:
        client_username: The username/email of the target client
        behaviour_id: The behavior to configure
        behaviour_config: Behavior-specific configuration dictionary

    Returns:
        BehaviorResponse with details about the update operation
    """
    # Refuse behaviours the target client reported it cannot run
    ensure_behaviour_available(client_username, behaviour_id)

    # Validate the configuration
    validated_config = validate_behavior_config(behaviour_id, behaviour_config)

    sockets = [socket for socket, username in client_sockets.connected_sockets.items() if username == client_username]

    if not sockets:
        return BehaviorResponse(
            message=f"Client '{client_username}' is not currently connected",
            status="error",
            client_username=client_username,
            behaviour_id=behaviour_id.value,
            clients_notified=0,
        )

    if validated_config:
        config_summary = f" with {len(validated_config)} parameters"
    else:
        config_summary = " (config cleared)"

    for socket in sockets:
        await socket.send_json(
            {"action": "update_behaviour_config", "behaviour_id": behaviour_id.value, "config": validated_config}
        )

    return BehaviorResponse(
        message=f"""Successfully updated '{behaviour_id.value}'
            behaviour configuration for client '{client_username}'{config_summary}""",
        status="success",
        client_username=client_username,
        behaviour_id=behaviour_id.value,
        config_keys=list(validated_config.keys()) if validated_config else [],
        clients_notified=len(sockets),
        validated_config=validated_config,
    )


@router.post(
    "/run",
    response_model=BehaviorRunResponse,
    description="""Execute a specific behaviour on a connected client.
    Behaviors 'procrastination' and 'work_organization_web' can run without any configuration.
    Attack behaviors and 'work_emails' require configuration.""",
    dependencies=[Depends(require_service_token)],
)
async def run_behaviour(
    client_username: str, behaviour_id: AvailableBehaviors, behaviour_config: Optional[dict] = None
) -> BehaviorRunResponse:
    """
    Execute a behaviour on a specific client with optional validated configuration.

    Args:
        client_username: The username/email of the target client
        behaviour_id: The behavior to execute
        behaviour_config: Optional behavior-specific configuration. Not needed for
                        'procrastination' and 'work_organization_web' behaviors.
                        Required for attack behaviors and 'work_emails'.

    Returns:
        BehaviorRunResponse with details about the execution request
    """
    # Refuse behaviours the target client reported it cannot run
    ensure_behaviour_available(client_username, behaviour_id)

    # Validate the configuration (returns None for behaviors that don't need config)
    validated_config = validate_behavior_config(behaviour_id, behaviour_config)

    sockets = [socket for socket, username in client_sockets.connected_sockets.items() if username == client_username]

    if not sockets:
        return BehaviorRunResponse(
            message=f"Client '{client_username}' is not currently connected",
            status="error",
            client_username=client_username,
            behaviour_id=behaviour_id.value,
            clients_notified=0,
            config_updated=False,
        )

    # Update configuration only if config was provided and the behavior supports configuration
    config_updated = False
    if validated_config is not None and behaviour_config is not None and behaviour_id not in BEHAVIORS_WITHOUT_CONFIG:
        await update_behaviour_config(client_username, behaviour_id, validated_config)
        config_updated = True

    # Send run command to all connected sockets for this client
    for socket in sockets:
        await socket.send_json(
            {
                "action": "run_behaviour",
                "behaviour_id": behaviour_id.value,
                "config": validated_config,  # Will be None for config-less behaviors
            }
        )

    # Reflect the running behaviour on the tracked clients and notify status subscribers.
    for client in clients_info.values():
        if client["username"] == client_username:
            client["current_behaviour"] = behaviour_id.value
    await broadcast_client_status()

    # Determine message based on behavior type
    if behaviour_id in BEHAVIORS_WITHOUT_CONFIG:
        config_note = ""  # No mention of config for config-less behaviors
    elif config_updated:
        config_note = " (with configuration)"
    else:
        config_note = ""

    return BehaviorRunResponse(
        message=f"Successfully initiated '{behaviour_id.value}' behaviour on client '{client_username}'{config_note}",
        status="success",
        client_username=client_username,
        behaviour_id=behaviour_id.value,
        config_updated=config_updated,
        config_keys=list(validated_config.keys()) if validated_config else [],
        clients_notified=len(sockets),
        validated_config=validated_config if validated_config else None,
    )


class WorkCycleResponse(BaseModel):
    """Response for work-cycle start/stop operations."""

    message: str
    status: str
    client_username: str
    action: str
    work_cycle_active: Optional[bool] = None
    clients_notified: int


class StopBehaviourResponse(BaseModel):
    """Response returned after requesting that a client stop its active behaviour."""

    message: str
    status: str
    client_username: str
    clients_notified: int


@router.post(
    "/stop",
    response_model=StopBehaviourResponse,
    description="Stop the behaviour currently running on a connected client.",
    dependencies=[Depends(require_service_token)],
)
async def stop_behaviour(client_username: str) -> StopBehaviourResponse:
    ensure_client_known(client_username)

    sockets = [socket for socket, username in client_sockets.connected_sockets.items() if username == client_username]

    if not sockets:
        return StopBehaviourResponse(
            message=f"Client '{client_username}' is not currently connected",
            status="error",
            client_username=client_username,
            clients_notified=0,
        )

    for socket in sockets:
        await socket.send_json({"action": "stop_behaviour"})

    for client in clients_info.values():
        if client["username"] == client_username:
            client["current_behaviour"] = None
    await broadcast_client_status()

    return StopBehaviourResponse(
        message=f"Successfully stopped the active behaviour on client '{client_username}'",
        status="success",
        client_username=client_username,
        clients_notified=len(sockets),
    )


@router.post(
    "/work_cycle/{action}",
    response_model=WorkCycleResponse,
    description="Start or stop the work cycle (simulated normal user activity) on a connected client.",
    dependencies=[Depends(require_service_token)],
)
async def set_work_cycle(client_username: str, action: WorkCycleAction) -> WorkCycleResponse:
    """
    Remotely start or stop a client's work cycle by pushing a control action over
    its websocket. Reflects the new state on the tracked client and notifies
    status subscribers.
    """
    ensure_client_known(client_username)

    active = action == WorkCycleAction.START

    sockets = [socket for socket, username in client_sockets.connected_sockets.items() if username == client_username]

    if not sockets:
        return WorkCycleResponse(
            message=f"Client '{client_username}' is not currently connected",
            status="error",
            client_username=client_username,
            action=action.value,
            work_cycle_active=None,
            clients_notified=0,
        )

    for socket in sockets:
        await socket.send_json({"action": f"{action.value}_work_cycle"})

    for client in clients_info.values():
        if client["username"] == client_username:
            client["work_cycle_active"] = active

    await broadcast_client_status()

    return WorkCycleResponse(
        message=f"Successfully sent work-cycle '{action.value}' to client '{client_username}'",
        status="success",
        client_username=client_username,
        action=action.value,
        work_cycle_active=active,
        clients_notified=len(sockets),
    )
