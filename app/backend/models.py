from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class IOC(BaseModel):
    """Indicator of Compromise model"""
    type: str
    value: str
    description: Optional[str] = None
    tags: List[str] = []


class MitreTechnique(BaseModel):
    """MITRE ATT&CK Technique"""
    technique_id: str
    technique_name: str
    tactic: Optional[str] = None
    description: Optional[str] = None


class ThreatAnalysis(BaseModel):
    """Threat Analysis Document"""
    id: Optional[str] = None
    title: str
    apt_group: str
    country: Optional[str] = None
    date: datetime
    content: str
    file_path: str
    iocs: List[IOC] = []
    mitre_techniques: List[MitreTechnique] = []
    tags: List[str] = []
    threat_type: str = "APT"  # APT, Cybercriminal, Unknown


class APTGroup(BaseModel):
    """APT Group Information"""
    name: str
    country: Optional[str] = None
    aliases: List[str] = []
    total_analyses: int = 0
    latest_activity: Optional[datetime] = None
    threat_level: str = "medium"  # low, medium, high, critical


class SearchQuery(BaseModel):
    """Search query model"""
    query: str
    filters: Optional[Dict[str, Any]] = {}
    limit: int = 50
    offset: int = 0


class HealthCheck(BaseModel):
    """Health check response"""
    status: str
    version: str
    database_connected: bool
    total_analyses: int
    total_iocs: int
