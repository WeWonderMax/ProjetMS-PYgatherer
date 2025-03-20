"""
API package initialization
"""
from .virustotal import VirusTotalAPI
from .abuse import AbuseAPI

__all__ = ['VirusTotalAPI', 'AbuseAPI']
