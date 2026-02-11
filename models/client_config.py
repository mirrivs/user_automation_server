from typing import List, Optional

from pydantic import BaseModel, Field


class User(BaseModel):
    email: str
    password: str


class IdleCycle(BaseModel):
    procrastination_chance: Optional[float] = Field(default=None)


class General(BaseModel):
    is_conversation_starter: Optional[bool] = Field(default=None)


class AttackRansomware(BaseModel):
    malicious_email_subject: Optional[str] = Field(default=None)


class AttackPhishing(BaseModel):
    malicious_email_subject: Optional[str] = Field(default=None)


class ProcrastinationPreference(BaseModel):
    youtube: Optional[float] = Field(default=1)
    kittens: Optional[float] = Field(default=1)


class Procrastination(BaseModel):
    preference: Optional[ProcrastinationPreference] = Field(default=None)
    duration_min: Optional[float] = Field(default=None)
    duration_max: Optional[float] = Field(default=None)


class WorkEmails(BaseModel):
    email_receivers: Optional[List[str]] = Field(default=None)


class Behaviours(BaseModel):
    procrastination: Optional[Procrastination] = Field(default=None)
    work_emails: Optional[WorkEmails] = Field(default=None)
    attack_phishing: Optional[AttackPhishing] = Field(default=None)


class Automation(BaseModel):
    general: Optional[General] = Field(default=None)
    idle_cycle: Optional[IdleCycle] = Field(default=None)
    behaviours: Optional[Behaviours] = Field(default=None)


class ClientConfig(BaseModel):
    automation: Optional[Automation] = Field(default=None)
    automation: Optional[Automation] = Field(default=None)
