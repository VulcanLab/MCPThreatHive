"""
Utility functions for MCP Security Scanner
"""

import asyncio
import tempfile
import shutil
from pathlib import Path
from typing import Optional
import subprocess
import logging

logger = logging.getLogger(__name__)


async def clone_repository(github_url: str) -> Path:
    """
    Clone GitHub repository to temporary directory
    
    Args:
        github_url: GitHub repository URL
        
    Returns:
        Path to cloned repository
    """
    temp_dir = Path(tempfile.mkdtemp(prefix="mcp_scan_"))
    
    # [SECURITY] Validate URL
    from core.security_utils import validate_git_url
    if not validate_git_url(github_url):
        raise ValueError(f"Invalid or unsafe GitHub URL: {github_url}")

    try:
        # Use shallow clone for faster download
        # [SECURITY] Use '--' to separate options from positional arguments
        result = await asyncio.create_subprocess_exec(
            'git', 'clone', '--depth', '1', '--', github_url, str(temp_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await result.communicate()
        
        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise RuntimeError(f"Failed to clone repository: {stderr.decode()}")
        
        logger.info(f"Cloned repository to {temp_dir}")
        return temp_dir
        
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise RuntimeError(f"Error cloning repository: {e}") from e


def discover_files(
    root_path: Path,
    include_patterns: list,
    exclude_patterns: list
) -> list[Path]:
    """
    Discover files matching patterns
    
    Args:
        root_path: Root directory to search
        include_patterns: List of glob patterns to include
        exclude_patterns: List of glob patterns to exclude
        
    Returns:
        List of matching file paths
    """
    files = []
    
    # Simple pattern matching (can be enhanced with fnmatch)
    for pattern in include_patterns:
        # Convert glob pattern to path matching
        if pattern.startswith('**/'):
            # Recursive pattern
            for file_path in root_path.rglob(pattern[3:]):
                if file_path.is_file():
                    files.append(file_path)
        elif pattern.startswith('*/'):
            # Single level pattern
            for file_path in root_path.glob(pattern[2:]):
                if file_path.is_file():
                    files.append(file_path)
        else:
            # Direct pattern
            for file_path in root_path.glob(pattern):
                if file_path.is_file():
                    files.append(file_path)
    
    # Filter out excluded patterns
    filtered_files = []
    for file_path in files:
        relative_path = file_path.relative_to(root_path)
        excluded = False
        for exclude_pattern in exclude_patterns:
            if exclude_pattern in str(relative_path):
                excluded = True
                break
        if not excluded:
            filtered_files.append(file_path)
    
    return list(set(filtered_files))  # Remove duplicates

