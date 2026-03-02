"""
Model Selector Configuration

Allows users to select which LLM provider to use at startup:
- LiteLLM (models from litellm endpoints)
- None (simple extraction only)

This configuration is set at startup and used throughout the platform.
"""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from dotenv import load_dotenv


class ModelProvider(Enum):
    """Available model providers"""
    LITELLM = "litellm"


@dataclass
class ModelConfig:
    """Configuration for a model provider"""
    provider: ModelProvider
    enabled: bool = False
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model_name: Optional[str] = None
    config: Dict = field(default_factory=dict)


@dataclass
class ModelSelection:
    """User's model selection configuration"""
    providers: List[ModelProvider] = field(default_factory=list)
    primary_provider: Optional[ModelProvider] = None
    fallback_providers: List[ModelProvider] = field(default_factory=list)
    configs: Dict[str, ModelConfig] = field(default_factory=dict)
    
    def has_provider(self, provider: ModelProvider) -> bool:
        """Check if provider is enabled"""
        return provider in self.providers
    
    # can_use_ollama removed
    
    def can_use_litellm(self) -> bool:
        """Check if LiteLLM can be used"""
        return self.has_provider(ModelProvider.LITELLM)


class ModelSelector:
    """
    Interactive model selector for startup configuration.
    
    Allows users to select which LLM providers to use:
    - Single selection: litellm
    """
    
    CONFIG_FILE = Path(__file__).parent.parent / ".model_config.json"
    
    def __init__(self):
        """Initialize model selector"""
        self.selection: Optional[ModelSelection] = None
    
    def select_models_interactive(self) -> ModelSelection:
        """
        Interactive model selection at startup.
        
        Returns:
            ModelSelection with user's choices
        """
        print("\n" + "="*60)
        print("🤖 LLM Model Provider Selection")
        print("="*60)
        print("\nSelect which LLM providers to use for this session:")
        print("  [1] LiteLLM (models from litellm endpoints)")
        print("  [0] None (use simple extraction only)")
        print()
        
        while True:
            try:
                choice = input("Enter your choice (0 or 1): ").strip()
                
                if choice == "0":
                    return self._create_selection([])
                
                # Parse multiple selections (e.g., "1,2")
                selected_providers = []
                choices = [c.strip() for c in choice.split(',')]
                
                for c in choices:
                    if c == "1":
                        selected_providers.append(ModelProvider.LITELLM)
                    else:
                        print(f"❌ Invalid choice: {c}. Please enter 0 or 1.")
                        selected_providers = None
                        break
                
                if selected_providers is not None and selected_providers:
                    # Remove duplicates while preserving order
                    unique_providers = []
                    seen = set()
                    for p in selected_providers:
                        if p not in seen:
                            unique_providers.append(p)
                            seen.add(p)
                    return self._create_selection(unique_providers)
                elif selected_providers is None:
                    continue
                else:
                    print("❌ No valid provider selected. Please enter 0 or 1.")
                    continue
            except (KeyboardInterrupt, EOFError):
                print("\n⚠️  Using default: Simple extraction only")
                return self._create_selection([])
    
    def _create_selection(self, providers: List[ModelProvider]) -> ModelSelection:
        """Create ModelSelection from provider list"""
        selection = ModelSelection(providers=providers)
        
        # Set primary provider (prefer LiteLLM > Ollama)
        if ModelProvider.LITELLM in providers:
            selection.primary_provider = ModelProvider.LITELLM
        
        # Set fallback providers
        selection.fallback_providers = [p for p in providers if p != selection.primary_provider]
        
        # Configure each provider
        for provider in providers:
            config = self._configure_provider(provider)
            selection.configs[provider.value] = config
        
        self.selection = selection
        self._save_config()
        
        return selection
    
    def _configure_provider(self, provider: ModelProvider) -> ModelConfig:
        """Configure a specific provider"""
        config = ModelConfig(provider=provider, enabled=True)
        
        if provider == ModelProvider.LITELLM:
            # Get API credentials from env
            api_base = os.getenv("LITELLM_API_BASE")
            api_key = os.getenv("LITELLM_API_KEY")
            
            # If not configured, ask to run setup
            if not api_base or not api_key:
                print("\n⚠️  LiteLLM is not configured (missing API_BASE or API_KEY).")
                print("   Starting setup wizard to configure endpoints...")
                if self._run_interactive_setup():
                    # Reload vars
                    api_base = os.getenv("LITELLM_API_BASE")
                    api_key = os.getenv("LITELLM_API_KEY")
            
            # List available LiteLLM models
            available_models = self._list_litellm_models(api_base, api_key)
            if available_models:
                print(f"\n📋 Available LiteLLM models:")
                # Limit to 50 models to avoid flooding the console
                # Display all models
                for i, model in enumerate(available_models, 1):
                    print(f"  [{i}] {model}")
                print()
                
                # Skip interactive prompt if LITELLM_MODEL is set in environment (auto-config)
                default_model = os.getenv("LITELLM_MODEL")
                if default_model and default_model in available_models:
                     print(f"✅ Using configured model from environment: {default_model}")
                     config.model_name = default_model
                elif default_model:
                     print(f"✅ Using configured model from environment: {default_model} (not in list)")
                     config.model_name = default_model
                else:
                    user_input = input(f"Enter LiteLLM model name or number (default: {default_model}): ").strip()
                    
                    # Check if user entered a number
                    if user_input.isdigit():
                        idx = int(user_input) - 1
                        if 0 <= idx < len(available_models):
                            config.model_name = available_models[idx]
                        else:
                            print(f"⚠️  Invalid number, using default: {default_model}")
                            config.model_name = default_model
                    elif user_input:
                        config.model_name = user_input
                    else:
                        config.model_name = default_model
            else:
                config.model_name = os.getenv("LITELLM_MODEL")
            
            config.config = {
                "temperature": float(os.getenv("LITELLM_TEMPERATURE", "0.1")),
                "max_tokens": int(os.getenv("LITELLM_MAX_TOKENS", "2000"))
            }
        
        return config

    def _run_interactive_setup(self) -> bool:
        """Run interactive setup wizard"""
        try:
            from scripts.interactive_setup import InteractiveSetup
            setup = InteractiveSetup()
            setup.run()
            # Reload env after setup
            load_dotenv(override=True)
            return True
        except Exception as e:
            print(f"❌ Setup wizard failed: {e}")
            return False

    
    # _list_ollama_models removed
    
    def _list_litellm_models(self, api_base: Optional[str] = None, api_key: Optional[str] = None) -> List[str]:
        """List available LiteLLM models from endpoint or configuration"""
        # Predefined common models as fallback
        common_models = [
            "gpt-4o-mini",
            "gpt-4o",
            "gpt-4-turbo",
            "gpt-4",
            "gpt-3.5-turbo",
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
            "gemini-2.0-flash",
            "gemini-1.5-pro",
            "gemini-1.5-flash"
        ]

        if not api_base:
            # If no API base is configured, just return common models + env model
            env_model = os.getenv("LITELLM_MODEL")
            if env_model and env_model not in common_models:
                common_models.insert(0, env_model)
            return common_models

        try:
            import requests
            
            # Ensure API base ends with /
            if not api_base.endswith('/'):
                api_base += '/'
            
            # Fetch models from /models endpoint
            models_url = f"{api_base}models"
            headers = {}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            
            # Add litellm specific header just in case
            if api_key:
                headers["x-litellm-api-key"] = api_key
            
            print(f"🔍 Fetching models from {models_url}...")
            response = requests.get(models_url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                models = []
                
                # Parse standard OpenAI-compatible response format: {"data": [{"id": "model-id", ...}, ...]}
                if "data" in data and isinstance(data["data"], list):
                    for item in data["data"]:
                        if isinstance(item, dict) and "id" in item:
                            models.append(item["id"])
                        elif isinstance(item, str):
                            models.append(item)
                # Handle simple list format
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "id" in item:
                            models.append(item["id"])
                        elif isinstance(item, str):
                            models.append(item)
                
                if models:
                    return models
                
            print(f"⚠️  Could not fetch models from {models_url} (HTTP {response.status_code}), using default list.")
            
        except Exception as e:
            print(f"⚠️  Error fetching LiteLLM models: {e}")
            pass
            
        # Fallback to common models
        env_model = os.getenv("LITELLM_MODEL")
        if env_model and env_model not in common_models:
            common_models.insert(0, env_model)
        
        return common_models
    
    def load_config(self) -> Optional[ModelSelection]:
        """Load saved configuration"""
        if self.CONFIG_FILE.exists():
            try:
                with open(self.CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                
                providers = [ModelProvider(p) for p in data.get('providers', [])]
                selection = ModelSelection(providers=providers)
                
                if data.get('primary_provider'):
                    selection.primary_provider = ModelProvider(data['primary_provider'])
                
                if data.get('fallback_providers'):
                    selection.fallback_providers = [ModelProvider(p) for p in data['fallback_providers']]
                
                # Load configs
                for key, config_data in data.get('configs', {}).items():
                    config = ModelConfig(
                        provider=ModelProvider(key),
                        enabled=config_data.get('enabled', False),
                        api_key=config_data.get('api_key'),
                        base_url=config_data.get('base_url'),
                        model_name=config_data.get('model_name'),
                        config=config_data.get('config', {})
                    )
                    selection.configs[key] = config
                
                self.selection = selection
                return selection
            except Exception as e:
                print(f"⚠️  Failed to load model config: {e}")
        
        return None
    
    def _save_config(self):
        """Save configuration to file"""
        if not self.selection:
            return
        
        try:
            data = {
                'providers': [p.value for p in self.selection.providers],
                'primary_provider': self.selection.primary_provider.value if self.selection.primary_provider else None,
                'fallback_providers': [p.value for p in self.selection.fallback_providers],
                'configs': {}
            }
            
            for key, config in self.selection.configs.items():
                config_dict = {
                    'provider': config.provider.value,  # Convert enum to string
                    'enabled': config.enabled,
                    'api_key': '***' if config.api_key else None,  # Mask API key
                    'base_url': config.base_url,
                    'model_name': config.model_name,
                    'config': config.config
                }
                data['configs'][key] = config_dict
            
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"⚠️  Failed to save model config: {e}")
            import traceback
            print(traceback.format_exc())
    
    def get_selection(self) -> Optional[ModelSelection]:
        """Get current model selection"""
        return self.selection


# Global model selector instance
_model_selector: Optional[ModelSelector] = None


def get_model_selector() -> ModelSelector:
    """Get global model selector instance"""
    global _model_selector
    if _model_selector is None:
        _model_selector = ModelSelector()
    return _model_selector


def initialize_model_selection(interactive: bool = True) -> ModelSelection:
    """
    Initialize model selection at startup.
    
    If no config exists and interactive=True, automatically runs interactive_setup.
    
    Args:
        interactive: Whether to show interactive prompt (or run interactive_setup if no config)
    
    Returns:
        ModelSelection
    """
    from pathlib import Path
    
    selector = get_model_selector()
    config_file = Path(".model_config.json")
    
    # If no config exists and interactive mode, run interactive setup

    
    # Try to load saved config
    saved_config = selector.load_config()
    if saved_config:
        return saved_config
    
    # Auto-detection from environment variables (smart default)
    # If LITELLM_API_KEY is present, assume we want to use LiteLLM
    import os
    if os.getenv("LITELLM_API_KEY"):
        print("✅ Detected LITELLM_API_KEY in environment, auto-configuring LiteLLM provider")
        from config.model_selector import ModelProvider
        return selector._create_selection([ModelProvider.LITELLM])

    # Interactive selection (if config still doesn't exist and interactive=True)
    if interactive:
        selection = selector.select_models_interactive()
        print(f"\n✅ Selected providers: {', '.join([p.value for p in selection.providers]) if selection.providers else 'None (simple extraction only)'}")
        return selection
    
    # Non-interactive: use defaults
    return ModelSelection(providers=[])
