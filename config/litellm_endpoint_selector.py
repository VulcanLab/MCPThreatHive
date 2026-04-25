"""
LLM Provider Selector

Allows users to select which LLM provider to use:
- LiteLLM (with endpoint selection: base or latest)
"""

import os
import json
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from dotenv import load_dotenv, set_key
from enum import Enum


class LLMProvider(Enum):
    """Available LLM providers"""
    LITELLM = "litellm"


@dataclass
class LLMProviderConfig:
    """Configuration for an LLM provider"""
    provider: LLMProvider
    endpoint_type: Optional[str] = None  
    api_base: Optional[str] = None
    api_key: Optional[str] = None
    model_name: Optional[str] = None
    config: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.config is None:
            self.config = {
                "temperature": 0.1,
                "max_tokens": 4000
            }


# Backward compatibility alias
LiteLLMEndpointConfig = LLMProviderConfig


class LLMProviderSelector:
    """
    Interactive selector for LLM providers.
    
    Allows users to choose between:
    - LiteLLM (with endpoint selection: base or latest)
    Allows users to choose:
    - LiteLLM (with endpoint selection: base or latest)
    """
    
    def __init__(self, env_file: Optional[Path] = None):
        """Initialize provider selector"""
        if env_file is None:
            env_file = Path(__file__).parent.parent / ".env"
        self.env_file = env_file
        load_dotenv(self.env_file)
        self.config: Optional[LLMProviderConfig] = None
        # Config file path for persistence
        self.config_file = Path(__file__).parent.parent / ".llm_provider_config.json"
    
    def select_provider_interactive(self) -> LLMProviderConfig:
        """
        Interactive provider selection.
        
        Returns:
            LLMProviderConfig with selected provider
        """
        print("\n" + "="*60)
        print("🔧 LLM Provider Selection")
        print("="*60)
        print("\nSelect which LLM provider to use for threat generation:")
        print("  [1] LiteLLM (with endpoint selection)")
        print()
        
        while True:
            try:
                # Default to LiteLLM directly or ask to confirm if needed, 
                # but since it's the only option now, we might just proceed or keep it as specific choice for future extensibility.
                # For now, let's keep the menu logic simple or auto-select.
                
                return self._select_litellm_endpoint()
            except (KeyboardInterrupt, EOFError):
                print("\n⚠️  Using default: LiteLLM")
                return self._select_litellm_endpoint(use_default=True)
    
    def _select_litellm_endpoint(self, use_default: bool = False) -> LLMProviderConfig:
        """Select LiteLLM endpoint (base or latest)"""
        if not use_default:
            print("\n" + "-"*60)
            print("LiteLLM Endpoint Selection")
            print("-"*60)
        
        # Check which endpoints are configured
        base_url = os.getenv("LITELLM_API_BASE", "")
        base_key = os.getenv("LITELLM_API_KEY", "")
        latest_url = os.getenv("LITELLM_API_Latest", "")
        latest_key = os.getenv("LITELLM_API_KEY_Latest", "")
        
        has_base = bool(base_url and base_key)
        has_latest = bool(latest_url and latest_key)
        
        if not has_base and not has_latest:
            print("\n❌ No LiteLLM endpoints configured in .env file!")
            print("Please configure at least one of:")
            print("  - LITELLM_API_BASE and LITELLM_API_KEY")
            print("  - LITELLM_API_Latest and LITELLM_API_KEY_Latest")
            raise ValueError("No LiteLLM endpoints configured")
        
        # Build options
        options = []
        if has_base:
            print(f"\n[1] Base Endpoint")
            print(f"    URL: {base_url}")
            print(f"    Key: {base_key[:10]}...")
            options.append(("1", "base", base_url, base_key))
        
        if has_latest:
            print(f"\n[2] Latest Endpoint")
            print(f"    URL: {latest_url}")
            print(f"    Key: {latest_key[:10]}...")
            options.append(("2", "latest", latest_url, latest_key))
        
        # If only one option, use it automatically
        if len(options) == 1 or use_default:
            opt_num, endpoint_type, url, key = options[0] if len(options) == 1 else (options[1] if has_latest else options[0])
            if not use_default:
                print(f"\n✅ Auto-selected {endpoint_type} endpoint: {url}")
            # Still fetch and select model even if endpoint is auto-selected
            selected_model = self._select_litellm_model(url, key, endpoint_type)
            config = LLMProviderConfig(
                provider=LLMProvider.LITELLM,
                endpoint_type=endpoint_type,
                api_base=url,
                api_key=key,
                model_name=selected_model
            )
            self.config = config
            # Save config to file
            self._save_config_to_file(url, key, selected_model, endpoint_type)
            return config
        
        # Let user choose
        print()
        while True:
            try:
                choice = input(f"Select endpoint (1-{len(options)}): ").strip()
                
                for opt_num, endpoint_type, url, key in options:
                    if opt_num == choice:
                        print(f"\n✅ Selected {endpoint_type} endpoint: {url}")
                        # Fetch and select model
                        selected_model = self._select_litellm_model(url, key, endpoint_type)
                        config = LLMProviderConfig(
                            provider=LLMProvider.LITELLM,
                            endpoint_type=endpoint_type,
                            api_base=url,
                            api_key=key,
                            model_name=selected_model
                        )
                        self.config = config
                        # Save config to file
                        self._save_config_to_file(url, key, selected_model, endpoint_type)
                        return config
                
                print(f"❌ Invalid choice. Please enter 1-{len(options)}")
            except (KeyboardInterrupt, EOFError):
                print("\n⚠️  Using default: Latest endpoint")
                # Use latest if available, otherwise base
                if has_latest:
                    selected_model = self._select_litellm_model(latest_url, latest_key, "latest")
                    config = LLMProviderConfig(
                        provider=LLMProvider.LITELLM,
                        endpoint_type="latest",
                        api_base=latest_url,
                        api_key=latest_key,
                        model_name=selected_model
                    )
                else:
                    selected_model = self._select_litellm_model(base_url, base_key, "base")
                    config = LLMProviderConfig(
                        provider=LLMProvider.LITELLM,
                        endpoint_type="base",
                        api_base=base_url,
                        api_key=base_key,
                        model_name=selected_model
                    )
                self.config = config
                # Save config to file
                self._save_config_to_file(config.api_base, config.api_key, selected_model, config.endpoint_type)
                return config
    
    def _select_litellm_model(self, api_base: str, api_key: str, endpoint_type: str = "base") -> str:
        """Fetch and select LiteLLM model"""
        print("\n" + "-"*60)
        print("Fetching available models...")
        print("-"*60)
        
        try:
            import requests
            
            # Ensure API base ends with /
            if not api_base.endswith('/'):
                api_base += '/'
            
            # Fetch models from /models endpoint
            models_url = f"{api_base}models"
            headers = {
                "x-litellm-api-key": api_key,
                "accept": "application/json"
            }
            params = {
                "return_wildcard_routes": "false",
                "include_model_access_groups": "false",
                "only_model_access_groups": "false"
            }
            
            print(f"🔍 Fetching models from {models_url}...")
            response = requests.get(models_url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                # Handle different response formats
                if "data" in data:
                    models = data["data"]
                elif isinstance(data, list):
                    models = data
                else:
                    models = [data] if data else []
                
                if models:
                    # Extract model IDs
                    model_ids = []
                    for model in models:
                        if isinstance(model, dict):
                            model_id = model.get("id", model.get("model_id", ""))
                            if model_id:
                                model_ids.append(model_id)
                        elif isinstance(model, str):
                            model_ids.append(model)
                    
                    if model_ids:
                        print(f"\n✅ Found {len(model_ids)} available models\n")
                        
                        # Display models (limit to first 50 for readability)
                        # Display all models
                        for i, model_id in enumerate(model_ids, 1):
                            print(f"  [{i}] {model_id}")
                        
                        # Get default model from env
                        default_model = os.getenv("LITELLM_MODEL")
                        default_index = None
                        if default_model in model_ids:
                            default_index = model_ids.index(default_model) + 1
                        
                        print()
                        while True:
                            try:
                                prompt = f"Select model (1-{len(model_ids)}"
                                if default_index:
                                    prompt += f", default: {default_index}"
                                prompt += "): "
                                
                                choice = input(prompt).strip()
                                
                                # Use default if empty
                                if not choice and default_index:
                                    choice = str(default_index)
                                
                                if choice:
                                    idx = int(choice) - 1
                                    if 0 <= idx < len(model_ids):
                                        selected_model = model_ids[idx]
                                        print(f"\n✅ Selected model: {selected_model}")
                                        
                                        # Test if the model is accessible
                                        print(f"🔍 Testing model access...")
                                        if self._test_model_access(api_base, api_key, selected_model):
                                            print(f"✅ Model access test passed!")
                                            return selected_model
                                        else:
                                            print(f"❌ Model access test failed. Please select a different model.")
                                            continue
                                    else:
                                        print(f"❌ Invalid choice. Please enter 1-{len(model_ids)}")
                                else:
                                    # Use default
                                    if default_model in model_ids:
                                        print(f"\n✅ Using default model: {default_model}")
                                        print(f"🔍 Testing model access...")
                                        if self._test_model_access(api_base, api_key, default_model):
                                            print(f"✅ Model access test passed!")
                                            return default_model
                                        else:
                                            print(f"❌ Default model access test failed. Please select a different model.")
                                            continue
                                    else:
                                        print(f"❌ Default model '{default_model}' not found. Please select a model.")
                            except ValueError:
                                print("❌ Invalid input. Please enter a number.")
                            except (KeyboardInterrupt, EOFError):
                                # Use default or first model
                                if default_model in model_ids:
                                    print(f"\n⚠️  Using default model: {default_model}")
                                    if self._test_model_access(api_base, api_key, default_model):
                                        return default_model
                                elif model_ids:
                                    print(f"\n⚠️  Using first model: {model_ids[0]}")
                                    if self._test_model_access(api_base, api_key, model_ids[0]):
                                        return model_ids[0]
                                break
                        
                        # Fallback to default or first model (with test)
                        if default_model in model_ids:
                            if self._test_model_access(api_base, api_key, default_model):
                                return default_model
                        elif model_ids:
                            if self._test_model_access(api_base, api_key, model_ids[0]):
                                return model_ids[0]
                    else:
                        print("⚠️  No model IDs found in response")
                else:
                    print("⚠️  No models found in response")
            else:
                error_text = response.text[:500] if response.text else "Unknown error"
                print(f"⚠️  Failed to fetch models: HTTP {response.status_code}")
                print(f"   Error: {error_text}")
        except requests.exceptions.Timeout:
            print("⚠️  Request timeout while fetching models")
        except requests.exceptions.RequestException as e:
            print(f"⚠️  Request error: {e}")
        except Exception as e:
            print(f"⚠️  Error fetching models: {e}")
        
        # Fallback to environment variable or default
        default_model = os.getenv("LITELLM_MODEL")
        print(f"\n⚠️  Using default model from environment: {default_model}")
        # Test access even for fallback
        if self._test_model_access(api_base, api_key, default_model):
            return default_model
        else:
            print(f"⚠️  Default model access test failed, but continuing anyway...")
            return default_model
    
    def _test_model_access(self, api_base: str, api_key: str, model_name: str) -> bool:
        """Test if a model is accessible by making a simple test request"""
        try:
            import requests
            
            base_url = api_base.rstrip('/')
            endpoint_url = f"{base_url}/v1/chat/completions"
            
            headers = {
                "x-litellm-api-key": api_key,
                "Content-Type": "application/json"
            }
            
            # Simple test payload with minimal tokens
            payload = {
                "model": model_name,
                "messages": [
                    {"role": "user", "content": "test"}
                ],
                "max_tokens": 5,
                "temperature": 0.1
            }
            
            response = requests.post(
                endpoint_url,
                headers=headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                return True
            else:
                error_data = response.json() if response.text else {}
                error_msg = error_data.get("error", {}).get("message", response.text[:200] if response.text else "Unknown error")
                print(f"   ❌ Access test failed: HTTP {response.status_code}")
                print(f"   Error: {error_msg}")
                
                # If error mentions allowed models, show them
                if "allowed to access model" in error_msg or "can only access" in error_msg:
                    # Try to extract model list from error message
                    if "models=" in error_msg:
                        print(f"   💡 Check the error message above for allowed models")
                
                return False
                
        except requests.exceptions.Timeout:
            print(f"   ❌ Access test timeout")
            return False
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Access test request error: {e}")
            return False
        except Exception as e:
            print(f"   ❌ Access test error: {e}")
            return False
    
    # _select_ollama removed
    
    def select_endpoint_interactive(self) -> LLMProviderConfig:
        """Backward compatibility: alias for select_provider_interactive"""
        return self.select_provider_interactive()
    
    def get_config(self) -> Optional[LLMProviderConfig]:
        """Get current configuration"""
        return self.config
    
    def _save_config_to_file(self, api_base: str, api_key: str, model_name: str, endpoint_type: str):
        """Save selected configuration to JSON file"""
        try:
            config_data = {
                "provider": "litellm",
                "endpoint_type": endpoint_type,
                "api_base": api_base,
                "api_key": api_key,  # Note: In production, consider encrypting this
                "model_name": model_name
            }
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
        except Exception as e:
            print(f"⚠️  Failed to save config to file: {e}")
    
    def load_from_file(self) -> Optional[LLMProviderConfig]:
        """Load configuration from saved JSON file"""
        if not self.config_file.exists():
            return None
        
        try:
            with open(self.config_file, 'r') as f:
                config_data = json.load(f)
            
            if config_data.get("provider") == "litellm":
                return LLMProviderConfig(
                    provider=LLMProvider.LITELLM,
                    endpoint_type=config_data.get("endpoint_type", "base"),
                    api_base=config_data.get("api_base"),
                    api_key=config_data.get("api_key"),
                    model_name=config_data.get("model_name")
                )
        except Exception as e:
            print(f"⚠️  Failed to load config from file: {e}")
            return None
        
        return None
    
    def load_from_env(self) -> Optional[LLMProviderConfig]:
        """Load configuration from environment variables (non-interactive)"""
        latest_url = os.getenv("LITELLM_API_Latest", "")
        latest_key = os.getenv("LITELLM_API_KEY_Latest", "")
        base_url = os.getenv("LITELLM_API_BASE", "")
        base_key = os.getenv("LITELLM_API_KEY", "")
        
        if latest_url and latest_key:
            config = LLMProviderConfig(
                provider=LLMProvider.LITELLM,
                endpoint_type="latest",
                api_base=latest_url,
                api_key=latest_key,
                model_name=os.getenv("LITELLM_MODEL")
            )
            self.config = config
            return config
        elif base_url and base_key:
            config = LLMProviderConfig(
                provider=LLMProvider.LITELLM,
                endpoint_type="base",
                api_base=base_url,
                api_key=base_key,
                model_name=os.getenv("LITELLM_MODEL")
            )
            self.config = config
            return config
        
        return None


# Global selector instance
_provider_selector: Optional[LLMProviderSelector] = None


def get_litellm_selector() -> LLMProviderSelector:
    """Get global provider selector instance (backward compatibility)"""
    global _provider_selector
    if _provider_selector is None:
        _provider_selector = LLMProviderSelector()
    return _provider_selector


def get_provider_selector() -> LLMProviderSelector:
    """Get global provider selector instance"""
    return get_litellm_selector()


# Backward compatibility alias
LiteLLMEndpointSelector = LLMProviderSelector


def initialize_litellm_endpoint(interactive: bool = True) -> LLMProviderConfig:
    """
    Initialize LLM provider selection at startup.
    
    Args:
        interactive: Whether to show interactive prompt
    
    Returns:
        LLMProviderConfig
    """
    selector = get_provider_selector()
    
    # Try to load from env first (non-interactive)
    config = selector.load_from_env()
    if config and not interactive:
        return config
    
    # Interactive selection
    if interactive:
        try:
            return selector.select_provider_interactive()
        except Exception as e:
            print(f"⚠️  Provider selection failed: {e}")
            # Fallback to env
            config = selector.load_from_env()
            if config:
                return config
            raise
    
    # Non-interactive: use env
    config = selector.load_from_env()
    if config:
        return config
    
    raise ValueError("No LLM provider configured and interactive mode is disabled")


def initialize_llm_provider(interactive: bool = True) -> LLMProviderConfig:
    """
    Initialize LLM provider selection at startup.
    
    Priority:
    1. Load from environment variables (Deployment/Docker)
    2. Load from saved config file (Local development persistence)
    3. Interactive selection (if interactive=True)
    
    Args:
        interactive: Whether to show interactive prompt if no saved config exists
    
    Returns:
        LLMProviderConfig
    """
    selector = get_provider_selector()

    # 1. First, try to load from env (highest priority for Docker/Deployment)
    env_config = selector.load_from_env()
    if env_config:
        print(f"✅ Loaded LLM provider config from environment variables")
        provider_name = env_config.provider.value if isinstance(env_config.provider, LLMProvider) else str(env_config.provider)
        if provider_name == "litellm":
            print(f"   Provider: {provider_name} ({env_config.endpoint_type}) - {env_config.api_base}")
            print(f"   Model: {env_config.model_name}")
        return env_config
    
    # 2. Second, try to load from saved config file
    saved_config = selector.load_from_file()
    if saved_config:
        print(f"✅ Loaded LLM provider config from saved file")
        provider_name = saved_config.provider.value if isinstance(saved_config.provider, LLMProvider) else str(saved_config.provider)
        if provider_name == "litellm":
            print(f"   Provider: {provider_name} ({saved_config.endpoint_type}) - {saved_config.api_base}")
            print(f"   Model: {saved_config.model_name}")
        return saved_config
    
    # 3. Interactive selection or error
    return initialize_litellm_endpoint(interactive=interactive)
