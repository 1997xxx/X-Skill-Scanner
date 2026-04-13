#!/usr/bin/env bash
#
# X Skill Scanner v7.1 - 扫描入口脚本
# 纯 Skill 实现的标准化扫描流程 + 平台检测
#
# 用法:
#   ./scan_skill.sh <skill-path> [options]
#   ./scan_skill.sh --url <github-url> [options]
#   ./scan_skill.sh --mode batch --platform openclaw
#

set -e

# 脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_DIR="$(dirname "$SCRIPT_DIR")"
LIB_DIR="$SCANNER_DIR/lib"

# 默认参数
TARGET_PATH=""
OUTPUT_FORMAT="text"
QUICK_MODE=false
JSON_OUTPUT=false
BATCH_MODE=false
PLATFORM="auto"
VERBOSE=false

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印函数
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检测当前 AI Agent 平台
detect_platform() {
    print_info "检测 AI Agent 平台..."

    # 1. 检查 OpenClaw 目录
    if [[ -d "$HOME/.openclaw" ]]; then
        echo "openclaw"
        return
    fi

    # 2. 检查环境变量
    if [[ -n "$CLAUDE_CODE" ]] || [[ -n "$CLAUDE_SESSION_ID" ]]; then
        echo "claude_code"
        return
    fi

    if [[ -n "$CURSOR" ]]; then
        echo "cursor"
        return
    fi

    if [[ -n "$WINDSURF" ]]; then
        echo "windsurf"
        return
    fi

    if [[ -n "$QCLAW" ]]; then
        echo "qclaw"
        return
    fi

    # 3. 检查配置文件
    if [[ -f "$HOME/.cursor/settings.json" ]]; then
        echo "cursor"
        return
    fi

    if [[ -f "$HOME/.windsurf/config.json" ]]; then
        echo "windsurf"
        return
    fi

    if [[ -f "$HOME/.qclaw/config.json" ]]; then
        echo "qclaw"
        return
    fi

    # 4. 默认返回 unknown
    echo "unknown"
}

# 显示帮助
show_help() {
    cat << EOF
X Skill Scanner v7.1 - 技能安全扫描器

用法:
    $0 <skill-path> [options]
    $0 --url <github-url> [options]
    $0 --mode batch [options]

选项:
    -t, --target <path>          扫描目标路径
    -u, --url <url>              扫描远程技能 URL
    -q, --quick                  快速模式（跳过深度扫描）
    -j, --json                   JSON 格式输出
    -f, --format <format>        输出格式: text|json|html|markdown
    -o, --output <file>         输出文件路径
    -m, --mode <mode>           扫描模式: single|batch
    -p, --platform <platform>    目标平台: openclaw|claude_code|cursor|windsurf|qclaw|auto
    -v, --verbose               详细输出
    -h, --help                  显示帮助

示例:
    $0 ./my-skill/
    $0 --url https://github.com/user/skill
    $0 ./my-skill/ --quick --json
    $0 --mode batch --platform openclaw

EOF
}

# 解析参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET_PATH="$2"
                shift 2
                ;;
            -u|--url)
                TARGET_PATH="--url $2"
                shift 2
                ;;
            -q|--quick)
                QUICK_MODE=true
                shift
                ;;
            -j|--json)
                JSON_OUTPUT=true
                OUTPUT_FORMAT="json"
                shift
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -m|--mode)
                BATCH_MODE=true
                BATCH_TYPE="$2"
                shift 2
                ;;
            -p|--platform)
                PLATFORM="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                if [[ -z "$TARGET_PATH" ]]; then
                    TARGET_PATH="$1"
                fi
                shift
                ;;
        esac
    done
}

# 检测环境
detect_env() {
    # 检测平台
    DETECTED_PLATFORM=$(detect_platform)
    print_info "检测到平台: $DETECTED_PLATFORM"

    # 如果用户未指定平台，使用检测结果
    if [[ "$PLATFORM" == "auto" ]]; then
        PLATFORM="$DETECTED_PLATFORM"
    fi

    print_info "使用平台: $PLATFORM"

    # 检测 Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python3 未安装"
        exit 1
    fi

    # 检测扫描器模块
    if [[ ! -d "$LIB_DIR" ]]; then
        print_error "扫描器模块未找到: $LIB_DIR"
        exit 1
    fi

    print_success "环境检测通过"
}

# 执行扫描
run_scan() {
    local target="$1"
    local extra_args=""

    # 添加参数
    [[ "$QUICK_MODE" == "true" ]] && extra_args="$extra_args --no-semantic"
    [[ "$JSON_OUTPUT" == "true" ]] && extra_args="$extra_args --json"
    [[ "$VERBOSE" == "true" ]] && extra_args="$extra_args --verbose"
    [[ -n "$OUTPUT_FORMAT" ]] && extra_args="$extra_args --format $OUTPUT_FORMAT"
    [[ -n "$OUTPUT_FILE" ]] && extra_args="$extra_args -o $OUTPUT_FILE"

    echo ""
    print_info "开始扫描: $target"
    echo "========================================"

    # 执行 Python 扫描器
    cd "$SCANNER_DIR"
    python3 "$SCANNER_DIR/lib/scanner.py" -t "$target" $extra_args
    local result=$?

    echo "========================================"

    return $result
}

# 批量扫描
run_batch_scan() {
    local platform="$1"

    print_info "批量扫描模式"
    print_info "目标平台: $platform"

    cd "$SCANNER_DIR"
    python3 "$SCANNER_DIR/lib/scanner.py" --mode batch --platform "$platform" $extra_args
}

# 主函数
main() {
    parse_args "$@"

    # 检测环境
    detect_env

    # 批量模式
    if [[ "$BATCH_MODE" == "true" ]]; then
        run_batch_scan "$PLATFORM"
        exit $?
    fi

    # 检查目标
    if [[ -z "$TARGET_PATH" ]]; then
        print_error "请指定扫描目标路径或 URL"
        show_help
        exit 1
    fi

    # 处理 URL
    if [[ "$TARGET_PATH" == --url\ * ]]; then
        local url="${TARGET_PATH#--url }"
        run_scan "--url $url"
    else
        run_scan "$TARGET_PATH"
    fi
}

main "$@"