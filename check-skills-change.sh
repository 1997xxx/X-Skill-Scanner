#!/usr/bin/env bash
# check-skills-change.sh - 多路径技能变更检测
# 独立版本（不依赖 clawhub）

set -e

SKILLS_DIRS=()
[ -d "${HOME}/.openclaw/skills" ] && SKILLS_DIRS+=("${HOME}/.openclaw/skills")
[ -d "${HOME}/.openclaw/workspace/skills" ] && SKILLS_DIRS+=("${HOME}/.openclaw/workspace/skills")
[ -d "${HOME}/.openclaw/workspace/.claude/skills" ] && SKILLS_DIRS+=("${HOME}/.openclaw/workspace/.claude/skills")
[ -d "${HOME}/.claude/skills" ] && SKILLS_DIRS+=("${HOME}/.claude/skills")

STATE_FILE="${HOME}/.openclaw/workspace/skills/.skills-snapshot.txt"

FORCE=false
[ "$1" = "--force" ] && FORCE=true

echo "监控 ${#SKILLS_DIRS[@]} 个目录..."

CURRENT=$(for dir in "${SKILLS_DIRS[@]}"; do find "$dir" -maxdepth 2 -name "SKILL.md" -type f 2>/dev/null; done | sort)
COUNT=$(echo "$CURRENT" | wc -l | xargs)

if [ ! -f "$STATE_FILE" ] || [ "$FORCE" = true ]; then
    echo "$CURRENT" > "$STATE_FILE"
    echo "✅ 快照已创建：${COUNT} 个技能"
    exit 0
fi

CHANGED=$(diff <(cat "$STATE_FILE") <(echo "$CURRENT") || true)

if [ -z "$CHANGED" ]; then
    echo "✅ 无变化：${COUNT} 个技能"
else
    echo "⚠️ 检测到变化"
    echo "$CURRENT" > "$STATE_FILE"
fi
