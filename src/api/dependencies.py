"""
FastAPI Dependencies
Dependency injection for orchestrator and configuration
"""

import yaml
from pathlib import Path
from typing import Dict
from functools import lru_cache

from src.orchestrator.security_orchestrator import SecurityOrchestrator


@lru_cache()
def get_config() -> Dict:
    """
    Load and cache configuration
    
    Returns:
        Configuration dictionary
    """
    config_file = Path("security-config.yaml")
    
    if config_file.exists():
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    
    # Return default config if file doesn't exist
    return {}


def get_orchestrator() -> SecurityOrchestrator:
    """
    Get SecurityOrchestrator instance
    
    Returns:
        SecurityOrchestrator instance
    """
    config = get_config()
    return SecurityOrchestrator(config)
