from pydantic import BaseModel, Field
from models.enums import RiskLevel
from models.evidence import Evidence

class Finding(BaseModel):
    title: str
    description: str
    risk: RiskLevel
    asset: str
    confidence: int = 90
    impact: list[str] = Field(default_factory=list)
    recommendation: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
