from enum import Enum
from typing import Optional, Union, List, Dict, Any
from pydantic import BaseModel, Field

from client import client_sockets
from auth import current_user
from fastapi import (
    Depends,
    APIRouter,
    HTTPException,
)

router = APIRouter()

class AvailableBehaviors(str, Enum):
    ATTACK_PHISHING = "attack_phishing"
    ATTACK_RANSOMWARE = "attack_ransomware"
    ATTACK_REVERSE_SHELL = "attack_reverse_shell"
    PROCRASTINATION = "procrastination"
    WORK_EMAILS = "work_emails"
    WORK_ORGANIZATION_WEB = "work_organization_web"

# Configuration models for each behavior
class AttackPhishingConfig(BaseModel):
    """Configuration for phishing attack behavior"""
    target_domains: List[str] = Field(..., description="List of domains to target")
    email_template: str = Field(..., description="Email template to use")
    frequency_minutes: int = Field(default=30, ge=1, le=1440, description="Frequency in minutes (1-1440)")
    max_attempts: int = Field(default=10, ge=1, le=100, description="Maximum attempts per target")

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
    bookmark_categories: List[str] = Field(default=["productivity", "tools", "documentation"], description="Bookmark categories")
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
    AvailableBehaviors.WORK_EMAILS,  # Work emails requires email accounts
}

# Define which behaviors can run without any configuration
BEHAVIORS_WITHOUT_CONFIG = {
    AvailableBehaviors.PROCRASTINATION,
    AvailableBehaviors.WORK_ORGANIZATION_WEB,
}

# Mapping behaviors to their config models
BEHAVIOR_CONFIG_MAPPING = {
    AvailableBehaviors.ATTACK_PHISHING: AttackPhishingConfig,
    AvailableBehaviors.ATTACK_RANSOMWARE: AttackRansomwareConfig,
    AvailableBehaviors.ATTACK_REVERSE_SHELL: AttackReverseShellConfig,
    AvailableBehaviors.PROCRASTINATION: ProcrastinationConfig,
    AvailableBehaviors.WORK_EMAILS: WorkEmailsConfig,
    AvailableBehaviors.WORK_ORGANIZATION_WEB: WorkOrganizationWebConfig,
}

# Helper function to validate config based on behavior
def validate_behavior_config(behaviour_id: AvailableBehaviors, behaviour_config: Optional[dict]) -> Optional[dict]:
    """Validate configuration against the specific behavior model"""
    
    # If no config provided
    if behaviour_config is None:
        if behaviour_id in BEHAVIORS_WITHOUT_CONFIG:
            # These behaviors run without any configuration
            return None
        elif behaviour_id in BEHAVIORS_REQUIRING_CONFIG:
            raise HTTPException(
                status_code=422,
                detail=f"Configuration is required for {behaviour_id.value}"
            )
        return None
    
    # If config is provided, validate it
    config_model = BEHAVIOR_CONFIG_MAPPING.get(behaviour_id)
    if not config_model:
        return behaviour_config
        
    try:
        validated_config = config_model(**behaviour_config)
        return validated_config.dict()
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid configuration for {behaviour_id.value}: {str(e)}"
        )

@router.post(
    "/update_config",
    response_model=BehaviorResponse,
    description="Update configuration parameters for a specific behaviour on a connected client. Configuration is validated based on the behavior type.",
    dependencies=[Depends(current_user)],
)
async def update_behaviour_config(
    client_username: str,
    behaviour_id: AvailableBehaviors,
    behaviour_config: Optional[dict] = None
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
    # Validate the configuration
    validated_config = validate_behavior_config(behaviour_id, behaviour_config)
    
    sockets = [
        socket
        for socket, username in client_sockets.connected_sockets.items()
        if username == client_username
    ]

    if not sockets:
        return BehaviorResponse(
            message=f"Client '{client_username}' is not currently connected",
            status="error",
            client_username=client_username,
            behaviour_id=behaviour_id.value,
            clients_notified=0
        )

    if validated_config:
        config_summary = f" with {len(validated_config)} parameters"
    else:
        config_summary = " (config cleared)"
    
    for socket in sockets:
        await socket.send_json({
            "action": "behaviour_config_update", 
            "behaviour_id": behaviour_id.value,
            "config": validated_config
        })

    return BehaviorResponse(
        message=f"Successfully updated '{behaviour_id.value}' behaviour configuration for client '{client_username}'{config_summary}",
        status="success",
        client_username=client_username,
        behaviour_id=behaviour_id.value,
        config_keys=list(validated_config.keys()) if validated_config else [],
        clients_notified=len(sockets),
        validated_config=validated_config
    )

@router.post(
    "/run",
    response_model=BehaviorRunResponse,
    description="Execute a specific behaviour on a connected client. Behaviors 'procrastination' and 'work_organization_web' can run without any configuration. Attack behaviors and 'work_emails' require configuration.",
    dependencies=[Depends(current_user)],
)
async def run_behaviour(
    client_username: str,
    behaviour_id: AvailableBehaviors,
    behaviour_config: Optional[dict] = None
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
    # Validate the configuration (returns None for behaviors that don't need config)
    validated_config = validate_behavior_config(behaviour_id, behaviour_config)
    
    sockets = [
        socket
        for socket, username in client_sockets.connected_sockets.items()
        if username == client_username
    ]

    if not sockets:
        return BehaviorRunResponse(
            message=f"Client '{client_username}' is not currently connected",
            status="error",
            client_username=client_username,
            behaviour_id=behaviour_id.value,
            clients_notified=0,
            config_updated=False
        )

    # Update configuration only if config was provided and the behavior supports configuration
    config_updated = False
    if validated_config is not None and behaviour_config is not None and behaviour_id not in BEHAVIORS_WITHOUT_CONFIG:
        await update_behaviour_config(client_username, behaviour_id, validated_config)
        config_updated = True

    # Send run command to all connected sockets for this client
    for socket in sockets:
        await socket.send_json({
            "action": "run_behaviour", 
            "behaviour_id": behaviour_id.value,
            "config": validated_config  # Will be None for config-less behaviors
        })

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
        validated_config=validated_config if validated_config else None
    )