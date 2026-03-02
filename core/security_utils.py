"""
Security Utilities for MCP Threat Platform

Provides centralized validation for paths, URLs, and other sensitive inputs
to prevent common vulnerabilities like Path Traversal and Command Injection.
"""

import os
import re
from pathlib import Path
from typing import Union, List, Optional
import logging

logger = logging.getLogger(__name__)

# Allowed schemes for Git URLs
ALLOWED_GIT_SCHEMES = ['https://', 'git@', 'ssh://']

def validate_safe_path(path: Union[str, Path], allow_dirs: Optional[List[Path]] = None) -> Path:
    """
    Validate that a path is safe to access (no traversal, within allowed directories).
    
    Args:
        path: Path string or object to validate
        allow_dirs: Optional list of allowed root directories. 
                   If None, defaults to [User Home, Current Working Directory].
                   
    Returns:
        Resolved absolute Path object if valid.
        
    Raises:
        ValueError: If path is unsafe or outside allowed directories.
    """
    try:
        # Convert to absolute path and resolve symlinks
        # [SECURITY] strict=True ensures the file/path actually exists
        safe_path = Path(path).resolve(strict=True)
    except FileNotFoundError:
        # If file doesn't exist, we can't verify it properly or scan it
        raise ValueError(f"Path not found: {path}")
    except Exception as e:
        raise ValueError(f"Invalid path format: {str(e)}")
    
    # Determine allowed roots
    if allow_dirs is None:
        # [SECURITY] Only allow current project directory by default.
        # Allowing Path.home() is too broad (exposes ~/.ssh, other projects).
        allow_dirs = [
            Path.cwd().resolve()
        ]
    else:
        allow_dirs = [Path(p).resolve() for p in allow_dirs]
        
    # Check if path is within any allowed directory
    is_allowed = False
    for root in allow_dirs:
        try:
            # Check if safe_path is relative to root (i.e., inside it)
            safe_path.relative_to(root)
            is_allowed = True
            break
        except ValueError:
            continue
            
    if not is_allowed:
        # Log the attempt for security auditing
        logger.warning(f"Security Alert: Blocked access to unsafe path '{path}' (resolved: '{safe_path}')")
        raise ValueError(f"Access denied: Path '{path}' is outside allowed directories.")
        
    return safe_path

def validate_git_url(url: str) -> bool:
    """
    Validate a Git URL to prevent argument injection and ensure protocol safety.
    
    Args:
        url: Git URL string
        
    Returns:
        True if valid, False otherwise
    """
    if not url:
        return False
        
    # Prevent argument injection (starting with -)
    if url.startswith('-'):
        logger.warning(f"Security Alert: Blocked potentially malicious Git URL '{url}'")
        return False
        
    # Validate scheme
    valid_scheme = False
    for scheme in ALLOWED_GIT_SCHEMES:
        if url.startswith(scheme):
            valid_scheme = True
            break
            
    if not valid_scheme:
        # Allow simple GitHub short format "user/repo" if meant for expansion, 
        # but strict clone usually requires full URL. 
        # For security, we require strict schemes.
        return False
        
    # Basic character check (alphanumeric, -, _, ., /, :, @)
    # This regex allows standard git URLs but blocks shell complexity
    # e.g. https://github.com/user/repo.git
    # e.g. git@github.com:user/repo.git
    if not re.match(r'^[a-zA-Z0-9_\-\.\/\:\@]+$', url):
        return False
        
    return True
