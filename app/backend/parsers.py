import json
import os
import re
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatIntelParser:
    """Parser for threat intelligence data from the repository"""

    def __init__(self, base_path: str = "/home/user/CyberThreatIntel"):
        self.base_path = Path(base_path)

    def parse_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Parse all threat intelligence data"""
        analyses = []
        iocs = []

        # Parse markdown analysis files
        for md_file in self.base_path.rglob("*.md"):
            if md_file.name.lower() not in ['readme.md']:
                try:
                    analysis = self.parse_analysis_file(md_file)
                    if analysis:
                        analyses.append(analysis)
                except Exception as e:
                    logger.error(f"Error parsing {md_file}: {e}")

        # Parse JSON IOC files
        for json_file in self.base_path.rglob("*.json"):
            try:
                ioc_data = self.parse_ioc_file(json_file)
                if ioc_data:
                    iocs.extend(ioc_data)
            except Exception as e:
                logger.error(f"Error parsing {json_file}: {e}")

        return {
            "analyses": analyses,
            "iocs": iocs
        }

    def parse_analysis_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Parse a markdown analysis file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Extract metadata from path
            parts = file_path.parts
            base_idx = parts.index('CyberThreatIntel')

            country = None
            apt_group = None
            threat_type = "Unknown"

            if len(parts) > base_idx + 1:
                country = parts[base_idx + 1]

            if len(parts) > base_idx + 3:
                apt_group = parts[base_idx + 3]

            # Determine threat type
            if 'cybercriminal' in str(file_path).lower():
                threat_type = "Cybercriminal"
            elif 'APT' in str(file_path) or 'apt' in str(file_path).lower():
                threat_type = "APT"

            # Extract date from path or filename
            date_str = self.extract_date(str(file_path))
            date = datetime.fromisoformat(date_str) if date_str else datetime.now()

            # Extract title from content
            title = self.extract_title(content, apt_group)

            return {
                "title": title,
                "apt_group": apt_group or "Unknown",
                "country": country,
                "date": date.isoformat(),
                "content": content[:5000],  # Limit content size
                "file_path": str(file_path.relative_to(self.base_path)),
                "threat_type": threat_type,
                "tags": self.extract_tags(content)
            }
        except Exception as e:
            logger.error(f"Error parsing analysis file {file_path}: {e}")
            return None

    def parse_ioc_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse a JSON IOC file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)

            # Extract metadata from path
            parts = file_path.parts
            base_idx = parts.index('CyberThreatIntel')

            apt_group = None
            if len(parts) > base_idx + 3:
                apt_group = parts[base_idx + 3]

            iocs = []

            # Handle different JSON structures
            if isinstance(data, list):
                for item in data:
                    ioc = self.extract_ioc_from_item(item, apt_group, file_path)
                    if ioc:
                        iocs.append(ioc)
            elif isinstance(data, dict):
                # Handle nested structures
                for key, value in data.items():
                    if isinstance(value, list):
                        for item in value:
                            ioc = self.extract_ioc_from_item(item, apt_group, file_path)
                            if ioc:
                                iocs.append(ioc)
                    else:
                        ioc = self.extract_ioc_from_item(data, apt_group, file_path)
                        if ioc:
                            iocs.append(ioc)
                            break

            return iocs
        except Exception as e:
            logger.error(f"Error parsing IOC file {file_path}: {e}")
            return []

    def extract_ioc_from_item(self, item: Any, apt_group: Optional[str], file_path: Path) -> Optional[Dict[str, Any]]:
        """Extract IOC from a JSON item"""
        if not isinstance(item, dict):
            return None

        # Try to identify IOC type and value
        ioc_type = None
        ioc_value = None

        # Common IOC fields
        if 'hash' in item or 'md5' in item or 'sha256' in item or 'sha1' in item:
            ioc_type = 'hash'
            ioc_value = item.get('hash') or item.get('md5') or item.get('sha256') or item.get('sha1')
        elif 'ip' in item or 'ip_address' in item:
            ioc_type = 'ip'
            ioc_value = item.get('ip') or item.get('ip_address')
        elif 'domain' in item or 'hostname' in item:
            ioc_type = 'domain'
            ioc_value = item.get('domain') or item.get('hostname')
        elif 'url' in item:
            ioc_type = 'url'
            ioc_value = item.get('url')
        elif 'email' in item:
            ioc_type = 'email'
            ioc_value = item.get('email')
        elif 'filename' in item or 'file' in item:
            ioc_type = 'filename'
            ioc_value = item.get('filename') or item.get('file')

        if ioc_type and ioc_value:
            return {
                "type": ioc_type,
                "value": str(ioc_value),
                "apt_group": apt_group or "Unknown",
                "source_file": str(file_path.relative_to(self.base_path)),
                "description": item.get('description', ''),
                "tags": item.get('tags', [])
            }

        return None

    def extract_date(self, text: str) -> Optional[str]:
        """Extract date from text"""
        # Try YYYY-MM-DD format
        match = re.search(r'(\d{4})-(\d{2})-(\d{2})', text)
        if match:
            return f"{match.group(1)}-{match.group(2)}-{match.group(3)}"

        # Try DD-MM-YY format
        match = re.search(r'(\d{2})-(\d{2})-(\d{2})', text)
        if match:
            day, month, year = match.groups()
            year = f"20{year}"
            return f"{year}-{month}-{day}"

        return None

    def extract_title(self, content: str, apt_group: Optional[str]) -> str:
        """Extract title from content"""
        lines = content.split('\n')
        for line in lines[:10]:
            line = line.strip()
            if line.startswith('#'):
                title = line.lstrip('#').strip()
                if title:
                    return title

        return f"{apt_group or 'Unknown'} Analysis"

    def extract_tags(self, content: str) -> List[str]:
        """Extract tags from content"""
        tags = []
        content_lower = content.lower()

        # Common malware families
        malware_families = ['emotet', 'trickbot', 'dridex', 'qakbot', 'cobalt strike',
                           'metasploit', 'mimikatz', 'powershell', 'phishing', 'ransomware']

        for family in malware_families:
            if family in content_lower:
                tags.append(family)

        return tags
