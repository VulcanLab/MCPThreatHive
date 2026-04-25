"""
LLM Configuration for MCP Threat Platform

Supports LiteLLM multi-endpoint configuration for:
- AI threat analysis
- Report generation
- Intelligence summarization
- Attack result judgment
"""

from __future__ import annotations

import os
import json
import requests
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from dotenv import load_dotenv

try:
    from .gemini_config import get_gemini_config, GeminiConfig
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    GeminiConfig = None

load_dotenv()


@dataclass
class LiteLLMEndpoint:
    """LiteLLM endpoint configuration"""
    name: str
    api_base: str
    api_key: str
    description: str = ""
    is_default: bool = False


@dataclass
class ModelRole:
    """Model role configuration"""
    role: str
    model_id: str
    description: str
    required: bool = False


class LLMConfigManager:
    """
    LLM Configuration Manager
    
    Manages LiteLLM endpoints and model selection, supporting:
    - Multi-endpoint switching (base / latest)
    - Model role assignment
    - Model validation
    """
    
    # AI roles in this platform
    PLATFORM_ROLES = {
        "THREAT_ANALYZER": {
            "description": "Analyze threats and assess risk levels",
            "required": True
        },
        "REPORT_GENERATOR": {
            "description": "Generate threat reports and summaries",
            "required": True
        },
        "INTEL_SUMMARIZER": {
            "description": "Summarize intelligence content",
            "required": True
        },
        "ATTACK_JUDGE": {
            "description": "Judge whether attack tests are successful",
            "required": False
        },
        "CONTROL_ADVISOR": {
            "description": "Recommend security control measures",
            "required": False
        },
        "SCHEMA_CONVERTER": {
            "description": "Convert intelligence to unified Schema",
            "required": True
        }
    }
    
    def __init__(self, env_file: Optional[Path] = None):
        """Initialize configuration manager"""
        self.env_file = env_file or Path(__file__).parent.parent / ".env"
        self.endpoints: Dict[str, LiteLLMEndpoint] = {}
        self.active_endpoint: Optional[str] = None
        self.model_assignments: Dict[str, str] = {}
        
        self._load_endpoints()
    
    def _load_endpoints(self):
        """Load endpoint configuration from environment variables"""
        # Base endpoint
        base_url = os.getenv("LITELLM_API_BASE", "")
        base_key = os.getenv("LITELLM_API_KEY", "")
        if base_url and base_key:
            self.endpoints["base"] = LiteLLMEndpoint(
                name="base",
                api_base=base_url,
                api_key=base_key,
                description="Base LiteLLM Endpoint"
            )
        
        # Latest endpoint
        latest_url = os.getenv("LITELLM_API_Latest", "")
        latest_key = os.getenv("LITELLM_API_KEY_Latest", "")
        if latest_url and latest_key:
            self.endpoints["latest"] = LiteLLMEndpoint(
                name="latest",
                api_base=latest_url,
                api_key=latest_key,
                description="Latest LiteLLM Endpoint"
            )
        
        # Load model assignments
        for role in self.PLATFORM_ROLES:
            env_key = f"LITELLM_{role}_MODEL"
            model = os.getenv(env_key, "")
            if model:
                self.model_assignments[role] = model
    
    def get_endpoints(self) -> Dict[str, LiteLLMEndpoint]:
        """Get all available endpoints"""
        return self.endpoints
    
    def select_endpoint(self, endpoint_name: str) -> bool:
        """Select endpoint to use"""
        if endpoint_name in self.endpoints:
            self.active_endpoint = endpoint_name
            return True
        return False
    
    def get_active_endpoint(self) -> Optional[LiteLLMEndpoint]:
        """Get currently active endpoint"""
        if self.active_endpoint:
            return self.endpoints.get(self.active_endpoint)
        # Default to latest, fallback to base if not available
        if "latest" in self.endpoints:
            return self.endpoints["latest"]
        if "base" in self.endpoints:
            return self.endpoints["base"]
        return None
    
    def fetch_available_models(self, endpoint_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch available models from endpoint
        
        Args:
            endpoint_name: Endpoint name, None to use current endpoint
            
        Returns:
            List of models
        """
        endpoint = None
        if endpoint_name:
            endpoint = self.endpoints.get(endpoint_name)
        else:
            endpoint = self.get_active_endpoint()
        
        if not endpoint:
            return []
        
        try:
            url = f"{endpoint.api_base.rstrip('/')}/models"
            headers = {
                "x-litellm-api-key": endpoint.api_key,
                "Authorization": f"Bearer {endpoint.api_key}"
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and "data" in data:
                    return data["data"]
                return data if isinstance(data, list) else []
            else:
                print(f"[LLMConfig] Failed to fetch model list: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"[LLMConfig] Error fetching model list: {e}")
            return []
    
    def get_model_ids(self, models: List[Dict[str, Any]]) -> List[str]:
        """Extract model IDs from model list"""
        model_ids = []
        for model in models:
            if isinstance(model, dict):
                model_id = model.get("id", "")
                if model_id:
                    model_ids.append(model_id)
            elif isinstance(model, str):
                model_ids.append(model)
        return model_ids
    
    def validate_model(
        self, 
        model_id: str, 
        endpoint_name: Optional[str] = None,
        verbose: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate if model is available
        
        Args:
            model_id: Model ID
            endpoint_name: Endpoint name
            verbose: Whether to output detailed information
            
        Returns:
            (is_valid, error_message)
        """
        endpoint = None
        if endpoint_name:
            endpoint = self.endpoints.get(endpoint_name)
        else:
            endpoint = self.get_active_endpoint()
        
        if not endpoint:
            return False, "No endpoint configured"
        
        try:
            url = f"{endpoint.api_base.rstrip('/')}/v1/chat/completions"
            headers = {
                "x-litellm-api-key": endpoint.api_key,
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": model_id,
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 5
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=15)
            
            if response.status_code == 200:
                return True, None
            else:
                error_msg = f"{response.status_code}"
                try:
                    error_data = response.json()
                    if "error" in error_data:
                        error_msg = f"{response.status_code} - {error_data['error'].get('message', 'Unknown error')}"
                except:
                    pass
                
                if verbose:
                    print(f"[LLMConfig] Model validation failed: {error_msg}")
                
                return False, error_msg
                
        except Exception as e:
            if verbose:
                print(f"[LLMConfig] Validation exception: {e}")
            return False, str(e)
    
    def assign_model_to_role(self, role: str, model_id: str):
        """Assign model to role"""
        if role in self.PLATFORM_ROLES:
            self.model_assignments[role] = model_id
    
    def get_model_for_role(self, role: str) -> Optional[str]:
        """Get model for role"""
        return self.model_assignments.get(role)
    
    def get_all_assignments(self) -> Dict[str, str]:
        """Get all model assignments"""
        return self.model_assignments.copy()
    
    def save_config(self):
        """Save configuration to .env file"""
        from dotenv import set_key
        
        if not self.env_file.exists():
            self.env_file.touch()
        
        # Save model assignments
        for role, model in self.model_assignments.items():
            env_key = f"LITELLM_{role}_MODEL"
            set_key(self.env_file, env_key, model)
    
    def completion(
        self,
        messages: List[Dict[str, str]],
        role: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute LLM completion
        
        Args:
            messages: Message list
            role: Which role's model to use
            model: Directly specify model (overrides role)
            temperature: Temperature
            max_tokens: Maximum token count
            
        Returns:
            Response content
        """
        endpoint = self.get_active_endpoint()
        if not endpoint:
            return {"error": "No endpoint configured", "content": ""}
        
        # Determine which model to use
        model_id = model
        if not model_id and role:
            model_id = self.model_assignments.get(role)
        if not model_id:
            # Use first available model
            models = self.fetch_available_models()
            if models:
                model_id = self.get_model_ids(models)[0]
        
        if not model_id:
            return {"error": "No model available", "content": ""}
        
        try:
            url = f"{endpoint.api_base.rstrip('/')}/v1/chat/completions"
            headers = {
                "x-litellm-api-key": endpoint.api_key,
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": model_id,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                **kwargs
            }
            
            if GEMINI_AVAILABLE:
                gemini_config = get_gemini_config()
                if gemini_config.is_gemini_model(model_id):
                    safety_kwargs = gemini_config.get_safety_kwargs(model_id)
                    if safety_kwargs:
                        if "extra_body" in safety_kwargs:
                            if "extra_body" not in payload:
                                payload["extra_body"] = {}
                            payload["extra_body"].update(safety_kwargs["extra_body"])
                        if "safety_settings" in safety_kwargs:
                            payload["safety_settings"] = safety_kwargs["safety_settings"]
            
            response = requests.post(url, headers=headers, json=payload, timeout=120)
            
            if response.status_code == 200:
                data = response.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return {
                    "content": content,
                    "model": model_id,
                    "usage": data.get("usage", {}),
                    "raw_response": data
                }
            else:
                return {"error": f"API error: {response.status_code}", "content": ""}
                
        except Exception as e:
            return {"error": str(e), "content": ""}


# Global instance
_config_manager: Optional[LLMConfigManager] = None


def get_llm_config() -> LLMConfigManager:
    """Get LLM configuration manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = LLMConfigManager()
    return _config_manager


