
from pydantic import BaseModel
from typing import Optional


class User(BaseModel):
    email: str
    password: str

class IdleCycle(BaseModel):
    procrastination_chance: Optional[float]

class General(BaseModel):
    user: Optional[User]
    is_conversation_starter: Optional[bool]
    organization_mail_server_url: Optional[str]
    organization_web_url: Optional[str]
    archive_path: Optional[str]

class AttackRansomware(BaseModel):
    malicious_email_subject: Optional[str]

class AttackPhishing(BaseModel):
    malicious_email_subject: Optional[str]

class Procrastination(BaseModel):
    procrastination_preference: Optional[float]
    procrastination_max_time: Optional[float]
    procrastination_min_time: Optional[float]

class WorkEmails(BaseModel):
    email_receivers: Optional[list[str]]

class Behaviours(BaseModel):
    procrastination: Optional[Procrastination]
    work_emails: Optional[WorkEmails]
    attack_phishing: Optional[AttackPhishing]

class UserBehaviour(BaseModel):
    general: Optional[General]
    idle_cycle: Optional[IdleCycle]
    behaviours: Optional[Behaviours]

class ClientConfig(BaseModel):
    behaviour: Optional[UserBehaviour] = None