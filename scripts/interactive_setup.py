#!/usr/bin/env python3
"""
MCP Threat Platform - Interactive Setup

Interactive setup wizard for configuring LiteLLM endpoints and model assignments.
AI roles in this platform: analysis, summarization, report generation, attack result judgment.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Dict, Optional

# Rich for beautiful CLI
try:
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from dotenv import load_dotenv, set_key

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.llm_config import LLMConfigManager, LiteLLMEndpoint


if RICH_AVAILABLE:
    console = Console()
else:
    class FakeConsole:
        def print(self, *args, **kwargs):
            # Strip rich markup for plain output
            text = str(args[0]) if args else ""
            import re
            text = re.sub(r'\[.*?\]', '', text)
            print(text)
    console = FakeConsole()


class InteractiveSetup:
    """
    MCP Threat Platform Interactive Setup Wizard
    
    Setup process:
    1. Select LiteLLM endpoint (base / latest)
    2. Fetch available model list
    3. Assign models to each role
    4. Validate models
    5. Save configuration
    """
    
    def __init__(self):
        self.env_file = Path(__file__).parent.parent / ".env"
        load_dotenv(self.env_file)
        self.config_manager = LLMConfigManager(self.env_file)
        self.selected_endpoint: Optional[str] = None
        self.model_assignments: Dict[str, str] = {}
    
    def run(self):
        """Execute interactive setup with main menu"""
        self._print_header()
        
        while True:
            console.print("\n[bold cyan]Main Menu[/bold cyan]")
            console.print("1. [bold]Run Full Setup Wizard[/bold] (Recommended for first run)")
            console.print("2. [bold]Update Model Assignments[/bold] (Switch models for roles)")
            console.print("3. [bold]Manage Endpoints[/bold] (Edit API Keys/URLs)")
            console.print("4. Exit")
            
            choice = Prompt.ask("\nSelect option", choices=["1", "2", "3", "4"], default="1")
            
            if choice == "1":
                self._run_wizard()
                if not Confirm.ask("\nReturn to main menu?", default=False):
                    break
            elif choice == "2":
                self._update_models_only()
                if not Confirm.ask("\nReturn to main menu?", default=False):
                    break
            elif choice == "3":
                self._manage_endpoints_menu()
            elif choice == "4":
                sys.exit(0)

    def _run_wizard(self):
        """Execute complete setup wizard"""
        console.print("\n[bold]Starting Setup Wizard...[/bold]")
        
        # Step 1: Select endpoint
        self._select_endpoint()
        
        # Step 2: Fetch model list
        models = self._fetch_models()
        if not models:
            console.print("\n[red]✗ Failed to fetch model list, please check endpoint configuration[/red]")
            return
        
        model_ids = self.config_manager.get_model_ids(models)
        
        # Step 3: Select model assignment method
        self._select_models(model_ids)
        
        # Step 4: Validate models
        self._validate_models()
        
        # Step 5: Save configuration
        self._save_config()
        
        self._print_summary()

    def _update_models_only(self):
        """Update model assignments only"""
        console.print("\n[bold]Updating Model Assignments[/bold]")
        
        # Step 1: Select endpoint (reuse _select_endpoint)
        self._select_endpoint()
        
        # Step 2: Fetch model list
        models = self._fetch_models()
        if not models:
            console.print("\n[red]✗ Failed to fetch model list[/red]")
            return
        
        model_ids = self.config_manager.get_model_ids(models)
        
        # Step 3: Select models
        self._select_models(model_ids)
        
        # Step 4: Validate
        self._validate_models()
        
        # Step 5: Save
        self._save_config()
        
        console.print("\n[green]✓ Model assignments updated successfully![/green]")

    def _manage_endpoints_menu(self):
        """Menu for managing endpoints"""
        while True:
            console.print("\n[bold]Manage LiteLLM Endpoints[/bold]")
            
            # Refresh config
            load_dotenv(self.env_file, override=True)
            self.config_manager = LLMConfigManager(self.env_file)
            endpoints = self.config_manager.get_endpoints()
            
            # List current
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Name", style="green", width=10)
            table.add_column("URL", style="yellow")
            
            for name, endpoint in endpoints.items():
                table.add_row(name, endpoint.api_base)
            
            console.print(table)
            
            console.print("\n1. Edit/Add Endpoint")
            console.print("2. Back to Main Menu")
            
            choice = Prompt.ask("Select", choices=["1", "2"], default="1")
            
            if choice == "1":
                self._manual_endpoint_setup()
            else:
                break
    
    def _print_header(self):
        """Print header"""
        header = """
╔══════════════════════════════════════════════════════════════════╗
║         🛡️  MCP Threat Platform - Setup Wizard  🛡️              ║
║                                                                  ║
║  Configure LiteLLM endpoints and model assignments for:         ║
║  • Threat Analysis     • Report Generation                      ║
║  • Intel Summarization • Attack Result Judgment                 ║
╚══════════════════════════════════════════════════════════════════╝
"""
        console.print(f"[bold cyan]{header}[/bold cyan]")
    
    def _select_endpoint(self):
        """Select LiteLLM endpoint"""
        console.print("\n[bold]Step 1: Select LiteLLM Endpoint[/bold]\n")
        
        endpoints = self.config_manager.get_endpoints()
        
        if not endpoints:
            console.print("[yellow]⚠ No endpoints found in .env file[/yellow]")
            console.print("\nPlease configure endpoints in .env:")
            console.print("  LITELLM_API_BASE=https://...")
            console.print("  LITELLM_API_KEY=sk-...")
            console.print("  LITELLM_API_Latest=https://...")
            console.print("  LITELLM_API_KEY_Latest=sk-...")
            
            # Manual input
            if Confirm.ask("\nManually enter endpoint?", default=True):
                self._manual_endpoint_setup()
                return
            else:
                # Ask to retry or exit
                return
        
        # Display available endpoints
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Name", style="green", width=10)
        table.add_column("URL", style="yellow")
        
        endpoint_list = list(endpoints.items())
        for i, (name, endpoint) in enumerate(endpoint_list, 1):
            table.add_row(str(i), name, endpoint.api_base)
        
        console.print(table)
        
        if len(endpoint_list) == 1:
            # Only one endpoint, auto-select
            self.selected_endpoint = endpoint_list[0][0]
            self.config_manager.select_endpoint(self.selected_endpoint)
            console.print(f"\n[green]✓ Auto-selected: {self.selected_endpoint}[/green]")
        else:
            # Let user choose
            choice = Prompt.ask(
                "\nSelect endpoint",
                choices=[str(i) for i in range(1, len(endpoint_list) + 1)],
                default="2" if len(endpoint_list) >= 2 else "1"  # Default to latest
            )
            idx = int(choice) - 1
            self.selected_endpoint = endpoint_list[idx][0]
            self.config_manager.select_endpoint(self.selected_endpoint)
            console.print(f"\n[green]✓ Selected: {self.selected_endpoint}[/green]")
    
    def _manual_endpoint_setup(self):
        """Manually configure endpoint"""
        console.print("\n[bold]Manual Endpoint Configuration[/bold]\n")
        
        console.print("Existing endpoints:")
        endpoints = self.config_manager.get_endpoints()
        for name, ep in endpoints.items():
            console.print(f" - {name}: {ep.api_base}")
        
        print("")
        name = Prompt.ask("Endpoint name (use 'base' or 'latest')", default="base")
        api_base = Prompt.ask("API Base URL")
        api_key = Prompt.ask("API Key")
        
        # Save to .env
        if not self.env_file.exists():
            self.env_file.touch()
        
        if name == "base":
            set_key(self.env_file, "LITELLM_API_BASE", api_base)
            set_key(self.env_file, "LITELLM_API_KEY", api_key)
        else:
            # For any other name, we currently only support 'latest' as the secondary in LLMConfigManager
            # But we can store it. However, LLMConfigManager only reads base and latest.
            # So we should probably restriction to base/latest or update LLMConfigManager.
            # For now, sticking to what LLMConfigManager supports.
            if name != "latest":
                 console.print("[yellow]Note: currently only 'base' and 'latest' are fully supported by the config manager.[/yellow]")
            
            set_key(self.env_file, "LITELLM_API_Latest", api_base)
            set_key(self.env_file, "LITELLM_API_KEY_Latest", api_key)
        
        # Reload
        load_dotenv(self.env_file, override=True)
        self.config_manager = LLMConfigManager(self.env_file)
        self.selected_endpoint = name
        self.config_manager.select_endpoint(name)
        
        console.print(f"\n[green]✓ Endpoint configured: {name}[/green]")
    
    def _fetch_models(self) -> List[Dict]:
        """Fetch available model list"""
        console.print("\n[bold]Step 2: Fetching Available Models[/bold]\n")
        
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Fetching models...", total=None)
                models = self.config_manager.fetch_available_models()
                progress.update(task, completed=True)
        else:
            console.print("Fetching models...")
            models = self.config_manager.fetch_available_models()
        
        if models:
            model_ids = self.config_manager.get_model_ids(models)
            console.print(f"[green]✓ Found {len(model_ids)} available models[/green]")
            return models
        else:
            console.print("[red]✗ No models found[/red]")
            return []
    
    def _select_models(self, model_ids: List[str]):
        """Select model assignment"""
        console.print("\n[bold]Step 3: Model Assignment for Platform Roles[/bold]\n")
        
        # Display role descriptions
        console.print("[bold cyan]Platform AI Roles:[/bold cyan]")
        
        role_table = Table(show_header=True, header_style="bold magenta")
        role_table.add_column("Role", style="cyan", width=20)
        role_table.add_column("Description", style="green")
        role_table.add_column("Required", style="yellow", width=10)
        
        for role, info in self.config_manager.PLATFORM_ROLES.items():
            required = "✅" if info["required"] else "Optional"
            role_table.add_row(role, info["description"], required)
        
        console.print(role_table)
        
        # Display all models (no truncation)
        console.print("\n[bold]Available Models:[/bold]")
        for i, model_id in enumerate(model_ids, 1):
            console.print(f"  {i}. {model_id}")
        
        # Use single model for all roles (simplified)
        self._select_single_model(model_ids)
    
    def _select_single_model(self, model_ids: List[str]):
        """Select single model"""
        console.print("\n[bold]Select model for all roles:[/bold]")
        
        choice = Prompt.ask(
            f"Enter model number (1-{len(model_ids)})",
            default="1"
        )
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(model_ids):
                selected_model = model_ids[idx]
            else:
                selected_model = model_ids[0]
        except ValueError:
            selected_model = model_ids[0]
        
        # Assign to all roles
        for role in self.config_manager.PLATFORM_ROLES:
            self.model_assignments[role] = selected_model
            self.config_manager.assign_model_to_role(role, selected_model)
        
        console.print(f"\n[green]✓ All roles assigned to: {selected_model}[/green]")
    
    def _validate_models(self):
        """Validate all assigned models"""
        console.print("\n[bold]Step 4: Validating Models[/bold]\n")
        
        unique_models = set(self.model_assignments.values())
        
        for model in unique_models:
            console.print(f"Testing: {model}... ", end="")
            
            is_valid, error = self.config_manager.validate_model(model)
            
            if is_valid:
                console.print("[green]✓[/green]")
            else:
                console.print(f"[red]✗ {error}[/red]")
                
                # Ask if user wants to replace
                if Confirm.ask(f"Replace {model}?", default=True):
                    # Re-select
                    models = self.config_manager.fetch_available_models()
                    model_ids = self.config_manager.get_model_ids(models)
                    
                    console.print("\nAvailable models:")
                    for i, mid in enumerate(model_ids[:20], 1):
                        console.print(f"  {i}. {mid}")
                    
                    choice = Prompt.ask("Select replacement", default="1")
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(model_ids):
                            new_model = model_ids[idx]
                            
                            # Update all roles using this model
                            for role, assigned in self.model_assignments.items():
                                if assigned == model:
                                    self.model_assignments[role] = new_model
                                    self.config_manager.assign_model_to_role(role, new_model)
                            
                            console.print(f"[green]✓ Replaced with: {new_model}[/green]")
                    except ValueError:
                        pass
    
    def _save_config(self):
        """Save configuration to .env AND .llm_provider_config.json"""
        console.print("\n[bold]Step 5: Saving Configuration[/bold]\n")
        
        if not self.env_file.exists():
            self.env_file.touch()
        
        # Get the single model (all roles use the same)
        single_model = list(self.model_assignments.values())[0] if self.model_assignments else None
        
        if single_model:
            # Check if it's a Gemini model
            is_gemini = "gemini" in single_model.lower()
            
            if is_gemini:
                console.print(f"[yellow]⚠ Gemini model detected: {single_model}[/yellow]")
                console.print("[yellow]  Disabling all Gemini safety filters...[/yellow]")
                
                # Set flag to disable safety settings
                set_key(self.env_file, "GEMINI_DISABLE_SAFETY", "true")
                console.print("[green]✓[/green] GEMINI_DISABLE_SAFETY = true")
            
            # Save LITELLM_MODEL (used by api/server.py as fallback)
            set_key(self.env_file, "LITELLM_MODEL", single_model)
            console.print(f"[green]✓[/green] LITELLM_MODEL = {single_model}")
            
            # Assign same model to all roles
            for role in self.config_manager.PLATFORM_ROLES:
                env_key = f"LITELLM_{role}_MODEL"
                set_key(self.env_file, env_key, single_model)
                console.print(f"[green]✓[/green] {env_key} = {single_model}")
        
        # Also update .llm_provider_config.json (read by api/server.py on startup)
        self._save_provider_config_json(single_model)
        
        console.print(f"\n[green]✓ Configuration saved to {self.env_file}[/green]")
    
    def _save_provider_config_json(self, model_name: Optional[str]):
        """Update .llm_provider_config.json so api/server.py picks up the new config"""
        import json
        
        config_file = Path(__file__).parent.parent / ".llm_provider_config.json"
        
        # Get the active endpoint info
        endpoint = self.config_manager.get_active_endpoint()
        if not endpoint:
            # Try to get from selected endpoint
            endpoints = self.config_manager.get_endpoints()
            if self.selected_endpoint and self.selected_endpoint in endpoints:
                endpoint = endpoints[self.selected_endpoint]
            elif endpoints:
                endpoint = list(endpoints.values())[0]
        
        if endpoint and model_name:
            config_data = {
                "provider": "litellm",
                "endpoint_type": self.selected_endpoint or endpoint.name,
                "api_base": endpoint.api_base,
                "api_key": endpoint.api_key,
                "model_name": model_name
            }
            
            try:
                with open(config_file, 'w') as f:
                    json.dump(config_data, f, indent=2)
                console.print(f"[green]✓[/green] Updated .llm_provider_config.json (model: {model_name})")
            except Exception as e:
                console.print(f"[red]✗ Failed to update .llm_provider_config.json: {e}[/red]")
    
    def _print_summary(self):
        """Print setup summary"""
        summary = """
╔══════════════════════════════════════════════════════════════════╗
║                    ✅ Setup Complete!                            ║
╚══════════════════════════════════════════════════════════════════╝

Available Commands:

  [cyan]python scripts/run_threat_platform.py[/cyan]
    Start the MCP Threat Platform server

  [cyan]python scripts/gather_intel.py[/cyan]
    Run MCP security intelligence gathering

  [cyan]python -m api.server[/cyan]
    Start the API server for the UI

Configuration Files:
  • .env - LiteLLM endpoint and model settings
  • config/platform_config.yaml - Platform settings (optional)

"""
        console.print(summary)
        
        # Display current assignments
        console.print("[bold]Current Model Assignments:[/bold]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Role", style="cyan")
        table.add_column("Model", style="green")
        
        for role, model in self.model_assignments.items():
            table.add_row(role, model)
        
        console.print(table)


def main():
    """Main entry point"""
    try:
        setup = InteractiveSetup()
        setup.run()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Setup cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]✗ Setup failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
