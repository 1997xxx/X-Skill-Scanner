#!/bin/bash
#
# sanitize_skill.sh - 脱敏技能文件，准备开源
#
# 替换所有公司内部信息为通用名称
#

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo "  Skill Sanitization for Open Source"
echo "========================================"
echo ""
echo "Target directory: ${SKILL_DIR}"
echo ""

# 定义替换规则
declare -A REPLACEMENTS=(
    ["Ant International Skill Scanner"]="AI Skill Scanner"
    ["Ant International"]="AI Security"
    ["Ant International Security Team"]="Open Source Security Team"
    ["蚂蚁国际"]="开源社区"
    ["蚂蚁"]="开源"
)

# 统计
MODIFIED_COUNT=0
FILES_CHECKED=0

# 处理文件
sanitize_file() {
    local file="$1"
    local modified=false
    
    for pattern in "${!REPLACEMENTS[@]}"; do
        replacement="${REPLACEMENTS[$pattern]}"
        if grep -q "$pattern" "$file" 2>/dev/null; then
            sed -i.bak "s|$pattern|$replacement|g" "$file"
            modified=true
        fi
    done
    
    if [ "$modified" = true ]; then
        rm -f "${file}.bak"
        echo "  ✓ Modified: $(basename "$file")"
        ((MODIFIED_COUNT++))
    fi
}

# 遍历所有文件
echo "Scanning files..."
echo ""

while IFS= read -r -d '' file; do
    ((FILES_CHECKED++))
    sanitize_file "$file"
done < <(find "$SKILL_DIR" -type f \( -name "*.md" -o -name "*.py" -o -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.sh" \) -print0 2>/dev/null)

echo ""
echo "========================================"
echo "  Summary"
echo "========================================"
echo "Files checked: ${FILES_CHECKED}"
echo "Files modified: ${MODIFIED_COUNT}"
echo ""
