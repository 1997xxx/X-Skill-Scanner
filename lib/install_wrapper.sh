#!/bin/bash
#
# Ant International Skill Scanner - 安全安装包装脚本
# 用法：./install_wrapper.sh clawhub install <skill-name>
#

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_DIR="$(dirname "$SCRIPT_DIR")"
SCANNER="$SCANNER_DIR/scanner.py"
PYTHON_HOOK="$SCRIPT_DIR/clawhub_hook.py"

# 打印横幅
print_banner() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}     Ant International Skill Scanner - Safe Install${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo
}

# 打印错误
print_error() {
    echo -e "${RED}❌ ERROR: $1${NC}" >&2
}

# 打印成功
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# 打印警告
print_warning() {
    echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
}

# 打印信息
print_info() {
    echo -e "${BLUE}ℹ️  INFO: $1${NC}"
}

# 主函数
main() {
    print_banner
    
    # 检查参数
    if [ $# -lt 3 ]; then
        print_error "Usage: $0 clawhub install <skill-name>"
        echo
        echo "Examples:"
        echo "  $0 clawhub install weather"
        echo "  $0 clawhub install github"
        exit 1
    fi
    
    # 验证命令
    if [ "$1" != "clawhub" ] || [ "$2" != "install" ]; then
        print_error "Only 'clawhub install' is supported"
        exit 1
    fi
    
    SKILL_NAME="$3"
    
    # 检查 Python Hook 是否存在
    if [ ! -f "$PYTHON_HOOK" ]; then
        print_error "Python hook not found: $PYTHON_HOOK"
        exit 1
    fi
    
    # 检查扫描器是否存在
    if [ ! -f "$SCANNER" ]; then
        print_error "Scanner not found: $SCANNER"
        exit 1
    fi
    
    # 执行安装前扫描
    echo
    print_info "Starting pre-install security scan for: $SKILL_NAME"
    echo
    
    # 运行 Python Hook
    if python3 "$PYTHON_HOOK" "$SKILL_NAME"; then
        echo
        print_success "Security scan passed. Skill installed successfully."
        echo
        print_banner
        echo -e "${GREEN}Installation complete!${NC}"
        exit 0
    else
        echo
        print_error "Security scan failed. Installation blocked."
        echo
        print_warning "If you believe this is a false positive, you can:"
        echo "  1. Review the scan report above"
        echo "  2. Run manual scan: python3 $SCANNER -t /tmp/<skill-path>"
        echo "  3. Report false positive: contact security team"
        echo
        print_info "To bypass security check (NOT RECOMMENDED):"
        echo "  clawhub install $SKILL_NAME --no-verify"
        echo
        exit 1
    fi
}

# 执行主函数
main "$@"
