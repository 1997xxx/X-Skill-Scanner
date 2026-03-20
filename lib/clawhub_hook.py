#!/usr/bin/env python3
"""
ClawHub 安装拦截 Hook
在技能安装前自动执行安全扫描
"""

import os
import sys
import json
import tempfile
import subprocess
from pathlib import Path
from typing import Optional, Tuple


# 扫描器路径
SCANNER_PATH = Path(__file__).parent.parent / 'scanner.py'


def pre_install_scan(skill_name: str, temp_dir: Optional[str] = None) -> Tuple[bool, dict]:
    """
    安装前扫描
    
    Args:
        skill_name: 技能名称
        temp_dir: 临时目录（用于下载技能）
    
    Returns:
        (allowed, scan_result)
    """
    print(f"🔍 [PRE-INSTALL SCAN] {skill_name}")
    
    # 创建临时目录
    if temp_dir is None:
        temp_dir = tempfile.mkdtemp(prefix='skill-scan-')
    
    temp_path = Path(temp_dir)
    
    try:
        # 1. 下载技能到临时目录（不安装）
        print(f"📥 Downloading to temp directory: {temp_dir}")
        download_result = subprocess.run(
            ['clawhub', 'install', skill_name, '--dir', str(temp_path), '--no-input'],
            capture_output=True,
            text=True
        )
        
        if download_result.returncode != 0:
            print(f"❌ Download failed: {download_result.stderr}")
            return False, {'error': 'Download failed'}
        
        # 2. 运行安全扫描
        skill_path = temp_path / skill_name
        if not skill_path.exists():
            # 尝试查找技能目录
            skill_dirs = list(temp_path.glob('*/'))
            if skill_dirs:
                skill_path = skill_dirs[0]
            else:
                print("❌ Cannot find skill directory")
                return False, {'error': 'Skill directory not found'}
        
        print(f"🔍 Scanning: {skill_path}")
        scan_result = subprocess.run(
            [sys.executable, str(SCANNER_PATH), '-t', str(skill_path), '--semantic', '--json'],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if scan_result.returncode != 0:
            print(f"❌ Scan failed: {scan_result.stderr}")
            return False, {'error': 'Scan failed', 'stderr': scan_result.stderr}
        
        # 3. 解析扫描结果
        try:
            result = json.loads(scan_result.stdout)
        except json.JSONDecodeError:
            print(f"❌ Failed to parse scan result")
            return False, {'error': 'Failed to parse scan result'}
        
        risk_level = result.get('risk_level', 'UNKNOWN')
        verdict = result.get('verdict', 'UNKNOWN')
        
        # 4. 根据风险等级决定是否允许安装
        if risk_level in ['EXTREME', 'HIGH']:
            print(f"❌ [BLOCKED] Risk Level: {risk_level} | Verdict: {verdict}")
            print("\n📋 Scan Summary:")
            print(f"   - Total Findings: {result.get('total_findings', 0)}")
            for severity, count in result.get('findings_by_severity', {}).items():
                if count > 0:
                    print(f"   - {severity}: {count}")
            return False, result
        
        elif risk_level == 'MEDIUM':
            print(f"⚠️  [CAUTION] Risk Level: {risk_level} | Verdict: {verdict}")
            print("\n⚠️  This skill requires manual review before installation.")
            print("    Run the following command to see detailed findings:")
            print(f"    python3 {SCANNER_PATH} -t {skill_path} --semantic")
            # 中等风险需要用户确认
            response = input("\nProceed with installation? (y/N): ")
            if response.lower() != 'y':
                print("❌ Installation cancelled by user")
                return False, result
        
        # 5. 低风险，允许安装
        print(f"✅ [PASSED] Risk Level: {risk_level} | Verdict: {verdict}")
        return True, result
    
    except subprocess.TimeoutExpired:
        print("❌ Scan timeout (120s)")
        return False, {'error': 'Scan timeout'}
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False, {'error': str(e)}
    finally:
        # 清理临时目录
        import shutil
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    """命令行入口"""
    if len(sys.argv) < 2:
        print("Usage: python3 clawhub_hook.py <skill-name>")
        sys.exit(1)
    
    skill_name = sys.argv[1]
    allowed, result = pre_install_scan(skill_name)
    
    if allowed:
        # 执行实际安装
        print("\n📦 Installing skill...")
        install_result = subprocess.run(
            ['clawhub', 'install', skill_name],
            capture_output=True,
            text=True
        )
        if install_result.returncode == 0:
            print("✅ Installation complete")
            sys.exit(0)
        else:
            print(f"❌ Installation failed: {install_result.stderr}")
            sys.exit(1)
    else:
        print("\n❌ Installation blocked due to security concerns")
        sys.exit(1)


if __name__ == '__main__':
    main()
