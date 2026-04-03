# -*- coding: utf-8 -*-
"""
Platform Skill Discovery - Mode A Batch Scanning

Supports multiple agent platforms:
- OpenClaw
- CodeBuddy
- Cursor
- Windsurf
- Claude Code
- qclaw
- WorkBuddy
"""

import os
from pathlib import Path
from typing import List, Dict, Tuple


class PlatformDiscoverer:
    """Discover skills from various agent platforms"""
    
    # Platform skill directories (common defaults)
    PLATFORM_PATHS = {
        'openclaw': [
            Path.home() / '.openclaw' / 'skills',
            Path.home() / '.openclaw' / 'workspace' / 'skills',
        ],
        'codebuddy': [
            Path.home() / '.codebuddy' / 'plugins',
            Path.home() / '.codebuddy' / 'plugins' / 'marketplaces',
        ],
        'cursor': [
            Path.home() / '.cursor' / 'extensions',
            Path.current / '.cursor' / 'skills' if hasattr(Path, 'current') else Path.cwd() / '.cursor' / 'skills',
        ],
        'windsurf': [
            Path.home() / '.windsurf' / 'skills',
            Path.cwd() / '.windsurf' / 'skills',
        ],
        'claude': [
            Path.home() / '.claude' / 'skills',
            Path.cwd() / '.claude' / 'skills',
        ],
        'qclaw': [
            Path.home() / '.qclaw' / 'skills',
        ],
        'workbuddy': [
            Path.home() / '.workbuddy' / 'skills',
        ],
    }
    
    def __init__(self, platform: str = None):
        """
        Initialize discoverer
        
        Args:
            platform: Specific platform to scan, or None for auto-detect
        """
        self.platform = platform
        self.supported_platforms = list(self.PLATFORM_PATHS.keys())
    
    def detect_platform(self) -> str:
        """
        Auto-detect current platform from environment
        
        Returns:
            Platform name or 'unknown'
        """
        # Check environment variables
        env_platforms = {
            'OPENCLAW': 'openclaw',
            'CODEBUDDY': 'codebuddy',
            'CURSOR': 'cursor',
            'WINDSURF': 'windsurf',
            'CLAUDE': 'claude',
            'QCLAW': 'qclaw',
            'WORKBUDDY': 'workbuddy',
        }
        
        for env_var, platform in env_platforms.items():
            if os.environ.get(env_var):
                return platform
        
        # Check running environment (OpenClaw specific)
        try:
            # If running in OpenClaw context
            import sys
            if 'openclaw' in str(sys.modules):
                return 'openclaw'
        except:
            pass
        
        # Default to openclaw
        return 'openclaw'
    
    def get_skill_paths(self, platform: str = None) -> List[Tuple[Path, str]]:
        """
        Get all skill paths for a platform
        
        Args:
            platform: Platform name or None for auto-detect
            
        Returns:
            List of (skill_path, source) tuples
        """
        if platform is None:
            platform = self.platform or self.detect_platform()
        
        if platform not in self.PLATFORM_PATHS:
            return []
        
        skills = []
        for base_path in self.PLATFORM_PATHS[platform]:
            if not base_path.exists():
                continue
            
            # Find all SKILL.md files
            for skill_md in base_path.rglob('SKILL.md'):
                skill_dir = skill_md.parent
                # Determine source
                if 'marketplaces' in str(skill_md) or 'marketplace' in str(skill_md):
                    source = 'marketplace'
                elif 'system' in str(skill_md):
                    source = 'system'
                else:
                    source = 'local'
                
                skills.append((skill_dir, source))
            
            # Also check for Skill.md (case variations)
            for skill_md in base_path.rglob('Skill.md'):
                skill_dir = skill_md.parent
                # Avoid duplicates
                if not any(s[0] == skill_dir for s in skills):
                    if 'marketplaces' in str(skill_md):
                        source = 'marketplace'
                    else:
                        source = 'local'
                    skills.append((skill_dir, source))
        
        return skills
    
    def discover_all(self) -> Dict[str, List[Tuple[Path, str]]]:
        """
        Discover skills from all platforms
        
        Returns:
            Dict of platform -> [(skill_path, source), ...]
        """
        result = {}
        for platform in self.supported_platforms:
            skills = self.get_skill_paths(platform)
            if skills:
                result[platform] = skills
        return result
    
    def format_summary(self, skills: List[Tuple[Path, str]]) -> str:
        """
        Format skill discovery summary
        
        Args:
            skills: List of (skill_path, source) tuples
            
        Returns:
            Formatted summary string
        """
        if not skills:
            return "未发现任何技能"
        
        lines = [f"发现 {len(skills)} 个技能："]
        for skill_path, source in skills:
            skill_name = skill_path.name
            lines.append(f"  - {skill_name} ({source})")
        
        return '\n'.join(lines)


def discover_skills(platform: str = None) -> List[Dict]:
    """
    Convenience function to discover skills
    
    Args:
        platform: Platform name or None for auto-detect
        
    Returns:
        List of skill info dicts
    """
    discoverer = PlatformDiscoverer(platform)
    skills = discoverer.get_skill_paths()
    
    result = []
    for skill_path, source in skills:
        # Try to read basic info from SKILL.md
        skill_info = {
            'path': str(skill_path),
            'name': skill_path.name,
            'source': source,
            'platform': platform or discoverer.detect_platform(),
        }
        
        # Parse SKILL.md for name/version if possible
        skill_md = skill_path / 'SKILL.md'
        if skill_md.exists():
            try:
                content = skill_md.read_text(encoding='utf-8')
                for line in content.split('\n')[:20]:
                    if line.startswith('name:'):
                        skill_info['name'] = line.split(':', 1)[1].strip()
                    elif line.startswith('version:'):
                        skill_info['version'] = line.split(':', 1)[1].strip()
                    elif line.startswith('author:'):
                        skill_info['author'] = line.split(':', 1)[1].strip()
            except:
                pass
        
        result.append(skill_info)
    
    return result


# CLI interface
if __name__ == '__main__':
    import sys
    
    platform = sys.argv[1] if len(sys.argv) > 1 else None
    skills = discover_skills(platform)
    
    print(f"\n🔍 发现 {len(skills)} 个技能\n")
    for skill in skills:
        print(f"  - {skill['name']} ({skill['source']})")
        if 'version' in skill:
            print(f"    版本：{skill['version']}")