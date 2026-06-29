from pydantic import BaseModel, Field
from typing import Optional
from models.enums import AssetType
from models.evidence import Evidence

class Asset(BaseModel):
    type: AssetType
    value: str
    evidence: list[Evidence] = Field(default_factory=list)
    parent: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
