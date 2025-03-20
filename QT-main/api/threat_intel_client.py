"""
Threat Intelligence API Client
Handles interactions with various threat intelligence APIs
"""

import os
import socket
import ipaddress
import requests
import json
import logging
from datetime import datetime
from typing import Dict, Optional, Any, Union
from cachetools import TTLCache, cached
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class APIError(Exception):
    """Custom exception for API-related errors"""
    pass

class ThreatIntelClient:
    """Client for querying various Threat Intelligence APIs"""

    def __init__(self):
        """Initialize client with API keys and cache"""
        # Load environment variables
        load_dotenv()
        
        # Initialize API keys
        self.vt_api_key = os.getenv("VT_API_KEY")
        self.ipstack_key = os.getenv("IPSTACK_KEY")
        
        # Initialize cache
        self.cache = TTLCache(maxsize=100, ttl=3600)  # 1 hour TTL
        
        # Validate API keys
        self._validate_api_keys()

    def _validate_api_keys(self):
        """Validate that required API keys are present"""
        if not self.vt_api_key:
            logger.warning("VirusTotal API key not found")
        if not self.ipstack_key:
            logger.warning("IPStack API key not found")

    @cached(TTLCache(maxsize=100, ttl=3600))
    def query_virustotal(self, ioc: str, ioc_type: str) -> Optional[Dict]:
        """
        Query VirusTotal API for given IOC
        
        Args:
            ioc: Indicator of Compromise (IP, hash, or domain)
            ioc_type: Type of IOC ('ip', 'hash', or 'domain')
            
        Returns:
            Dictionary containing analysis results or None if error
        """
        if not self.vt_api_key:
            raise APIError("VirusTotal API key not configured")

        url_map = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
            "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}"
        }

        if ioc_type not in url_map:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")

        headers = {"x-apikey": self.vt_api_key}

        try:
            logger.info(f"Querying VirusTotal for {ioc_type}: {ioc}")
            response = requests.get(url_map[ioc_type], headers=headers)
            response.raise_for_status()
            
            data = response.json()
            logger.debug(f"VirusTotal response: {data}")
            return data

        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API error: {str(e)}")
            return None

    @cached(TTLCache(maxsize=100, ttl=3600))
    def query_abusech_malwarebazaar(self, file_hash: str) -> Optional[Dict]:
        """
        Query MalwareBazaar (Abuse.ch) for file hash
        
        Args:
            file_hash: File hash to query
            
        Returns:
            Dictionary containing analysis results or None if error
        """
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {
            "query": "get_info",
            "hash": file_hash
        }

        try:
            logger.info(f"Querying Abuse.ch for hash: {file_hash}")
            response = requests.post(url, data=data)
            response.raise_for_status()
            
            data = response.json()
            logger.debug(f"Abuse.ch response: {data}")
            return data

        except requests.exceptions.RequestException as e:
            logger.error(f"Abuse.ch API error: {str(e)}")
            return None

    @cached(TTLCache(maxsize=100, ttl=3600))
    def query_ipstack(self, ip_address: str) -> Optional[Dict]:
        """
        Query ipstack API for IP geolocation
        
        Args:
            ip_address: IP address to query
            
        Returns:
            Dictionary containing geolocation data or None if error
        """
        if not self.ipstack_key:
            raise APIError("IPStack API key not configured")

        try:
            logger.info(f"Querying ipstack for IP: {ip_address}")
            url = f"http://api.ipstack.com/{ip_address}?access_key={self.ipstack_key}"
            response = requests.get(url)
            response.raise_for_status()
            
            data = response.json()
            
            if "error" in data:
                logger.error(f"IPStack API error: {data['error']}")
                return None
                
            logger.debug(f"IPStack response: {data}")
            return data

        except requests.exceptions.RequestException as e:
            logger.error(f"IPStack API error: {str(e)}")
            return None

    def extract_virustotal_info(self, vt_json: Optional[Dict]) -> Optional[Dict]:
        """
        Extract useful information from VirusTotal response
        
        Args:
            vt_json: Raw VirusTotal API response
            
        Returns:
            Dictionary containing extracted information or None if invalid
        """
        if not vt_json or "data" not in vt_json:
            return None

        try:
            data = vt_json["data"]
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            total_scans = sum(stats.values())
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            return {
                "detection_ratio": f"{malicious}/{total_scans}",
                "total_scans": total_scans,
                "malicious": malicious,
                "suspicious": suspicious,
                "last_analysis_date": datetime.fromtimestamp(
                    attributes.get("last_analysis_date", 0)
                ).strftime("%Y-%m-%d %H:%M:%S")
            }

        except Exception as e:
            logger.error(f"Error extracting VirusTotal info: {str(e)}")
            return None

    def extract_abusech_info(self, abuse_json: Optional[Dict]) -> Optional[Dict]:
        """
        Extract useful information from Abuse.ch response
        
        Args:
            abuse_json: Raw Abuse.ch API response
            
        Returns:
            Dictionary containing extracted information or None if invalid
        """
        if not abuse_json or abuse_json.get("query_status") != "ok":
            return None

        try:
            data = abuse_json.get("data", [])
            if not data:
                return None

            sample = data[0]
            return {
                "file_type": sample.get("file_type", "N/A"),
                "signature": sample.get("signature", "N/A"),
                "reporter": sample.get("reporter", "N/A"),
                "tags": ", ".join(sample.get("tags", [])),
                "first_seen": sample.get("first_seen", "N/A"),
                "last_seen": sample.get("last_seen", "N/A")
            }

        except Exception as e:
            logger.error(f"Error extracting Abuse.ch info: {str(e)}")
            return None

    def extract_ipstack_info(self, ipstack_json: Optional[Dict]) -> Optional[Dict]:
        """
        Extract useful information from ipstack response
        
        Args:
            ipstack_json: Raw IPStack API response
            
        Returns:
            Dictionary containing extracted information or None if invalid
        """
        if not ipstack_json or "error" in ipstack_json:
            return None

        try:
            return {
                "ip": ipstack_json.get("ip", "N/A"),
                "type": ipstack_json.get("type", "N/A"),
                "continent": ipstack_json.get("continent_name", "N/A"),
                "country": ipstack_json.get("country_name", "N/A"),
                "region": ipstack_json.get("region_name", "N/A"),
                "city": ipstack_json.get("city", "N/A"),
                "latitude": ipstack_json.get("latitude", "N/A"),
                "longitude": ipstack_json.get("longitude", "N/A"),
                "zip": ipstack_json.get("zip", "N/A")
            }

        except Exception as e:
            logger.error(f"Error extracting IPStack info: {str(e)}")
            return None

    def detect_ioc_type(self, ioc: str) -> str:
        """
        Detect the type of IOC (Indicator of Compromise)
        
        Args:
            ioc: String to analyze
            
        Returns:
            String indicating IOC type ('ip', 'hash', 'domain', or 'unknown')
        """
        try:
            ipaddress.ip_address(ioc)
            return "ip"
        except ValueError:
            if len(ioc) in (32, 40, 64):  # MD5, SHA1, or SHA256
                return "hash"
            elif "." in ioc:  # Simple domain check
                return "domain"
            return "unknown"

    def analyze_ioc(self, ioc: str) -> Dict[str, Any]:
        """
        Analyze an IOC using all available services
        
        Args:
            ioc: Indicator of Compromise to analyze
            
        Returns:
            Dictionary containing all analysis results
        """
        results = {"ioc": ioc}
        ioc_type = self.detect_ioc_type(ioc)
        results["ioc_type"] = ioc_type

        if ioc_type == "ip":
            vt_data = self.query_virustotal(ioc, ioc_type)
            ipstack_data = self.query_ipstack(ioc)
            
            results["virustotal"] = self.extract_virustotal_info(vt_data)
            results["ipstack"] = self.extract_ipstack_info(ipstack_data)

        elif ioc_type == "hash":
            vt_data = self.query_virustotal(ioc, ioc_type)
            abuse_data = self.query_abusech_malwarebazaar(ioc)
            
            results["virustotal"] = self.extract_virustotal_info(vt_data)
            results["abusech"] = self.extract_abusech_info(abuse_data)

        elif ioc_type == "domain":
            vt_data = self.query_virustotal(ioc, ioc_type)
            results["virustotal"] = self.extract_virustotal_info(vt_data)
            
            try:
                ip_address = socket.gethostbyname(ioc)
                ipstack_data = self.query_ipstack(ip_address)
                results["ipstack"] = self.extract_ipstack_info(ipstack_data)
            except socket.gaierror:
                logger.warning(f"Could not resolve domain: {ioc}")

        return results

if __name__ == "__main__":
    # Example usage
    client = ThreatIntelClient()
    
    # Test with an IP
    results = client.analyze_ioc("8.8.8.8")
    print(json.dumps(results, indent=2))
    
    # Test with a domain
    results = client.analyze_ioc("google.com")
    print(json.dumps(results, indent=2))
