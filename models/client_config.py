from typing import List, Optional

from pydantic import BaseModel, Field


class User(BaseModel):
    email: str
    password: str


class WorkCycle(BaseModel):
    procrastination_chance: Optional[float] = Field(default=None)


# class General(BaseModel)


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
    is_conversation_starter: Optional[bool] = Field(default=None)


class Behaviours(BaseModel):
    procrastination: Optional[Procrastination] = Field(default=None)
    work_emails: Optional[WorkEmails] = Field(default=None)
    attack_phishing: Optional[AttackPhishing] = Field(default=None)


class Automation(BaseModel):
    # general: Optional[General] = Field(default=None)
    work_cycle: Optional[WorkCycle] = Field(default=None)
    behaviours: Optional[Behaviours] = Field(default=None)


class Screenshot(BaseModel):
    interval_seconds: Optional[float] = Field(default=None, gt=0, description="Seconds between periodic screenshots")


class ClientConfig(BaseModel):
    automation: Optional[Automation] = Field(default=None)
    screenshot: Optional[Screenshot] = Field(default=None)
