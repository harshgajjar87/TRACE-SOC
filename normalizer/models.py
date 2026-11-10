
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from datetime import datetime, timezone
import ipaddress


class NormalizedEvent(BaseModel):

    model_config = ConfigDict(extra="forbid")

    # Event identification
    event_id: str
    record_id: Optional[str] = None
    provider: Optional[str] = None
    channel: Optional[str] = None

    # Time and machine
    timestamp_utc: Optional[str] = None
    hostname: Optional[str] = None

    # User information
    username: Optional[str] = None

    # Process information
    process_id: Optional[int] = None
    parent_process_id: Optional[int] = None

    process_guid: Optional[str] = None
    parent_process_guid: Optional[str] = None

    image: Optional[str] = None
    command_line: Optional[str] = None

    # Network information
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None

    # Event classification
    event_type: str = "unknown"

    # Original provider-specific fields
    extra_data: dict = Field(default_factory=dict)

    @field_validator("timestamp_utc")
    @classmethod
    def normalize_timestamp(cls, value):

        if value is None or not value.strip():
            return None

        try:

            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed.astimezone(
                timezone.utc
            ).isoformat().replace("+00:00", "Z")

        except ValueError:

            raise ValueError(
                "Invalid timestamp format"
            )

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, value):

        if value is None or value in ("", "-"):
            return None

        try:

            return str(ipaddress.ip_address(value))

        except ValueError:

            raise ValueError(
                f"Invalid IP address: {value}"
            )

    @field_validator("hostname", "username", "provider", "channel")
    @classmethod
    def clean_optional_text(cls, value):

        if value is None:
            return None

        value = value.strip()

        if value in ("", "-"):
            return None

        return value

