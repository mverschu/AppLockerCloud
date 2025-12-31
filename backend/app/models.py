"""
Data models for AppLocker rules and policies.
"""
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class RuleCollection(str, Enum):
    """AppLocker rule collection types."""
    EXECUTABLE = "Exe"
    SCRIPT = "Script"
    DLL = "Dll"
    MSI = "Msi"
    PACKAGED_APP = "Appx"


class Action(str, Enum):
    """Rule action types."""
    ALLOW = "Allow"
    DENY = "Deny"


class ConditionType(str, Enum):
    """Condition types for rules."""
    PATH = "FilePathCondition"
    PUBLISHER = "FilePublisherCondition"
    HASH = "FileHashCondition"


class PathCondition(BaseModel):
    """Path-based condition."""
    path: str = Field(..., description="File or directory path pattern")
    type: str = Field(default="Path", description="Condition type identifier")


class PublisherCondition(BaseModel):
    """Publisher-based condition (for signed files)."""
    publisher_name: str = Field(..., description="Publisher name from certificate")
    product_name: Optional[str] = Field(None, description="Product name")
    binary_name: Optional[str] = Field(None, description="Binary name pattern")
    version: Optional[str] = Field(None, description="Version number or range")


class HashCondition(BaseModel):
    """Hash-based condition."""
    file_hash: str = Field(..., description="SHA256 hash of the file")
    source_file_name: str = Field(..., description="Source file name")
    source_file_length: Optional[int] = Field(None, description="File length in bytes")
    type: str = Field(default="SHA256", description="Hash algorithm type")


class Rule(BaseModel):
    """AppLocker rule model."""
    id: Optional[str] = Field(None, description="Unique rule identifier")
    name: str = Field(..., description="Rule name")
    description: Optional[str] = Field(None, description="Rule description")
    collection: RuleCollection = Field(..., description="Rule collection type")
    action: Action = Field(..., description="Allow or Deny")
    user_or_group_sid: Optional[str] = Field(
        None, 
        description="User or group SID (defaults to Everyone if not specified)"
    )
    conditions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of conditions (path, publisher, or hash)"
    )
    exceptions: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="List of exception conditions (for FilePathRule)"
    )
    created_at: Optional[datetime] = Field(default_factory=datetime.now)
    updated_at: Optional[datetime] = Field(default_factory=datetime.now)


class Policy(BaseModel):
    """AppLocker policy model."""
    version: str = Field(default="1", description="Policy version")
    rules: List[Rule] = Field(default_factory=list, description="List of rules")
    enforcement_mode: str = Field(
        default="AuditOnly",
        description="Enforcement mode: AuditOnly or Enforced"
    )


class RuleCreate(BaseModel):
    """Model for creating a new rule."""
    name: str
    description: Optional[str] = None
    collection: RuleCollection
    action: Action
    user_or_group_sid: Optional[str] = None
    conditions: List[Dict[str, Any]]
    exceptions: Optional[List[Dict[str, Any]]] = None


class RuleUpdate(BaseModel):
    """Model for updating an existing rule."""
    name: Optional[str] = None
    description: Optional[str] = None
    collection: Optional[RuleCollection] = None
    action: Optional[Action] = None
    user_or_group_sid: Optional[str] = None
    conditions: Optional[List[Dict[str, Any]]] = None
    exceptions: Optional[List[Dict[str, Any]]] = None


class ExportRequest(BaseModel):
    """Request model for exporting policy."""
    rules: List[Rule]
    enforcement_mode: Optional[str] = "AuditOnly"
    version: Optional[str] = "1"

