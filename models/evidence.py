from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict
from typing import Any, Optional

class Evidence(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    source: str
    confidence: int = Field(ge=0, le=100)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: Optional[dict[str, Any]] = None
    metadata: Optional[dict[str, Any]] = None
