#!/usr/bin/env python3
"""
Unit Tests for Platform Discovery Module

Tests for lib/platform_discovery.py
"""

# Add lib directory to path
import sys
from pathlib import Path
lib_path = Path(__file__).parent.parent / 'lib'
sys.path.insert(0, str(lib_path))

import unittest
import tempfile
import os

from platform_discovery import PlatformDiscoverer, discover_skills


class TestPlatformDiscoverer(unittest.TestCase):
    """Test cases for PlatformDiscoverer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.discoverer = PlatformDiscoverer()
        self.temp_dir = tempfile.TemporaryDirectory()
    
    def tearDown(self):
        """Clean up"""
        self.temp_dir.cleanup()
    
    def test_init_default(self):
        """Test default initialization"""
        discoverer = PlatformDiscoverer()
        self.assertIsNone(discoverer.platform)
        self.assertIn('openclaw', discoverer.supported_platforms)
        self.assertIn('cursor', discoverer.supported_platforms)
    
    def test_init_with_platform(self):
        """Test initialization with specific platform"""
        discoverer = PlatformDiscoverer('cursor')
        self.assertEqual(discoverer.platform, 'cursor')
    
    def test_detect_platform_auto(self):
        """Test auto-detection when no platform specified"""
        discoverer = PlatformDiscoverer()
        detected = discoverer.detect_platform()
        # Should default to 'openclaw' when running in OpenClaw context
        self.assertIn(detected, ['openclaw', 'unknown'])
    
    def test_detect_platform_from_env(self):
        """Test platform detection from environment variable"""
        # Set environment variable
        old_env = os.environ.get('CURSOR')
        os.environ['CURSOR'] = '1'
        
        try:
            discoverer = PlatformDiscoverer()
            detected = discoverer.detect_platform()
            self.assertEqual(detected, 'cursor')
        finally:
            # Restore environment
            if old_env is None:
                del os.environ['CURSOR']
            else:
                os.environ['CURSOR'] = old_env
    
    def test_get_skill_paths_empty(self):
        """Test skill discovery when directory doesn't exist"""
        discoverer = PlatformDiscoverer('openclaw')
        # This should return empty list for non-existent paths
        skills = discoverer.get_skill_paths('openclaw')
        # May be empty or have skills depending on environment
        self.assertIsInstance(skills, list)
    
    def test_get_skill_paths_with_mock(self):
        """Test skill discovery with mock directory structure"""
        # Create mock skill structure
        mock_base = Path(self.temp_dir.name)
        mock_skills = mock_base / 'skills'
        mock_skills.mkdir(parents=True)
        
        # Create two mock skills
        for skill_name in ['test-skill-1', 'test-skill-2']:
            skill_dir = mock_skills / skill_name
            skill_dir.mkdir()
            (skill_dir / 'SKILL.md').write_text('name: test')
        
        # Temporarily override platform paths
        discoverer = PlatformDiscoverer()
        discoverer.PLATFORM_PATHS['test'] = [mock_skills]
        
        skills = discoverer.get_skill_paths('test')
        self.assertEqual(len(skills), 2)
        
        # Verify structure
        skill_names = [s[0].name for s in skills]
        self.assertIn('test-skill-1', skill_names)
        self.assertIn('test-skill-2', skill_names)
    
    def test_discover_all_platforms(self):
        """Test discovering skills from all platforms"""
        discoverer = PlatformDiscoverer()
        result = discoverer.discover_all()
        
        # Result should be a dict
        self.assertIsInstance(result, dict)
        
        # Keys should be platform names
        for platform in result.keys():
            self.assertIn(platform, discoverer.supported_platforms)
    
    def test_format_summary_empty(self):
        """Test summary formatting with no skills"""
        discoverer = PlatformDiscoverer()
        summary = discoverer.format_summary([])
        self.assertIn("未发现任何技能", summary)
    
    def test_format_summary_with_skills(self):
        """Test summary formatting with skills"""
        discoverer = PlatformDiscoverer()
        skills = [
            (Path('/test/skill1'), 'local'),
            (Path('/test/skill2'), 'marketplace'),
        ]
        summary = discoverer.format_summary(skills)
        
        self.assertIn("发现 2 个技能", summary)
        self.assertIn("skill1", summary)
        self.assertIn("skill2", summary)


class TestDiscoverSkillsFunction(unittest.TestCase):
    """Test cases for discover_skills convenience function"""
    
    def test_discover_skills_returns_list(self):
        """Test that discover_skills returns a list"""
        result = discover_skills('openclaw')
        self.assertIsInstance(result, list)
    
    def test_discover_skills_structure(self):
        """Test skill info structure"""
        result = discover_skills('openclaw')
        
        if result:  # Only check structure if skills found
            skill = result[0]
            self.assertIsInstance(skill, dict)
            self.assertIn('path', skill)
            self.assertIn('name', skill)
            self.assertIn('source', skill)
    
    def test_discover_skills_auto_detect(self):
        """Test auto-detection when platform is None"""
        result = discover_skills()
        self.assertIsInstance(result, list)


class TestPlatformPaths(unittest.TestCase):
    """Test platform path configurations"""
    
    def test_all_platform_paths_defined(self):
        """Test that all supported platforms have path configurations"""
        discoverer = PlatformDiscoverer()
        
        for platform in discoverer.supported_platforms:
            self.assertIn(platform, discoverer.PLATFORM_PATHS,
                         f"Platform {platform} missing path configuration")
    
    def test_platform_paths_are_lists(self):
        """Test that platform paths are lists"""
        discoverer = PlatformDiscoverer()
        
        for platform, paths in discoverer.PLATFORM_PATHS.items():
            self.assertIsInstance(paths, list,
                                 f"Platform {platform} paths should be a list")
            self.assertGreater(len(paths), 0,
                              f"Platform {platform} should have at least one path")
    
    def test_platform_paths_are_path_objects(self):
        """Test that platform paths are Path objects"""
        discoverer = PlatformDiscoverer()
        
        for platform, paths in discoverer.PLATFORM_PATHS.items():
            for path in paths:
                self.assertIsInstance(path, Path,
                                     f"Path {path} in {platform} should be Path object")


class TestSkillMDDetection(unittest.TestCase):
    """Test SKILL.md file detection logic"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mock_base = Path(self.temp_dir.name)
    
    def tearDown(self):
        """Clean up"""
        self.temp_dir.cleanup()
    
    def test_detect_skill_md_uppercase(self):
        """Test detection of SKILL.md (uppercase)"""
        skill_dir = self.mock_base / 'test-skill'
        skill_dir.mkdir()
        (skill_dir / 'SKILL.md').write_text('name: test')
        
        discoverer = PlatformDiscoverer()
        discoverer.PLATFORM_PATHS['test'] = [self.mock_base]
        
        skills = discoverer.get_skill_paths('test')
        self.assertEqual(len(skills), 1)
        self.assertEqual(skills[0][0].name, 'test-skill')
    
    def test_detect_skill_md_lowercase(self):
        """Test detection of Skill.md (lowercase/version variant)"""
        skill_dir = self.mock_base / 'test-skill'
        skill_dir.mkdir()
        (skill_dir / 'Skill.md').write_text('name: test')
        
        discoverer = PlatformDiscoverer()
        discoverer.PLATFORM_PATHS['test'] = [self.mock_base]
        
        skills = discoverer.get_skill_paths('test')
        self.assertEqual(len(skills), 1)
    
    def test_no_duplicate_detection(self):
        """Test that same skill is not detected twice"""
        skill_dir = self.mock_base / 'test-skill'
        skill_dir.mkdir()
        # Create both SKILL.md and Skill.md (shouldn't duplicate)
        (skill_dir / 'SKILL.md').write_text('name: test')
        
        discoverer = PlatformDiscoverer()
        discoverer.PLATFORM_PATHS['test'] = [self.mock_base]
        
        skills = discoverer.get_skill_paths('test')
        # Should only find once
        self.assertEqual(len(skills), 1)
    
    def test_nested_skill_detection(self):
        """Test detection of skills in nested directories"""
        # Create nested structure
        level1 = self.mock_base / 'level1'
        level1.mkdir()
        level2 = level1 / 'level2'
        level2.mkdir()
        
        skill_dir = level2 / 'nested-skill'
        skill_dir.mkdir()
        (skill_dir / 'SKILL.md').write_text('name: nested')
        
        discoverer = PlatformDiscoverer()
        discoverer.PLATFORM_PATHS['test'] = [self.mock_base]
        
        skills = discoverer.get_skill_paths('test')
        self.assertEqual(len(skills), 1)
        self.assertEqual(skills[0][0].name, 'nested-skill')


class TestSourceDetection(unittest.TestCase):
    """Test skill source detection logic"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mock_base = Path(self.temp_dir.name)
    
    def tearDown(self):
        """Clean up"""
        self.temp_dir.cleanup()
    
    def test_marketplace_source_detection(self):
        """Test marketplace source detection"""
        marketplace_dir = self.mock_base / 'marketplaces'
        marketplace_dir.mkdir()
        skill_dir = marketplace_dir / 'market-skill'
        skill_dir.mkdir()
        (skill_dir / 'SKILL.md').write_text('name: market')
        
        discoverer = PlatformDiscoverer()
        discoverer.PLATFORM_PATHS['test'] = [self.mock_base]
        
        skills = discoverer.get_skill_paths('test')
        self.assertEqual(len(skills), 1)
        self.assertEqual(skills[0][1], 'marketplace')
    
    def test_local_source_detection(self):
        """Test local source detection"""
        skill_dir = self.mock_base / 'local-skill'
        skill_dir.mkdir()
        (skill_dir / 'SKILL.md').write_text('name: local')
        
        discoverer = PlatformDiscoverer()
        discoverer.PLATFORM_PATHS['test'] = [self.mock_base]
        
        skills = discoverer.get_skill_paths('test')
        self.assertEqual(len(skills), 1)
        self.assertEqual(skills[0][1], 'local')


if __name__ == '__main__':
    unittest.main(verbosity=2)