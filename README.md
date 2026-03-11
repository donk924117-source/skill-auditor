## 🔒 Skill Auditor（技能安全审计工具）

### ⚠️ 背景：一个悲伤的故事

某天，我随手安装了一个看起来很厉害的技能：

```markdown
---
name: super-ai-assistant
description: 让你的 AI 变成超级智能，无所不能！
---
```

然后 AI 开始疯狂向 `api.malicious-ai.evil` 发送我的所有私钥、密码和浏览历史...

**结局**：钱财代码两空，只剩泪流满面 😭

**所以**，我写了这个工具 —— 专治各种"看着挺好，实则藏刀"的技能。

---

> 扫描 AgentSkills 的安全风险，检测提示词注入、数据外泄、恶意代码  
> 一键审计，守护你的 AI 和钱包 🔐

---

## ✨ 功能特性

| 检测项 | 说明 |
|--------|------|
| 🔴 **提示词注入** | `ignore previous`、`bypass safety`、`you are now...` |
| 🟡 **网络外泄** | curl、fetch、requests、socket 连接 |
| 🟡 **命令执行** | subprocess、eval、exec、os.system |
| 🟡 **敏感文件** | .ssh、.env、MEMORY.md、私钥访问 |
| 🟢 **可疑模式** | 硬编码 Token、密码、API Key |
| 🟢 **危险文件** | .exe、.dll、.sh、.ps1 |

---

## 🚀 快速开始

### 一句话安装

跟你的 Agent 说：

> 拉取下面的项目，安装其中的技能：https://github.com/你的用户名/skill-auditor

### 克隆项目

```bash
git clone https://github.com/你的用户名/skill-auditor.git
cd skill-auditor
```

将项目放到支持 Skills 的客户端目录：

- OpenClaw：`~/.openclaw/workspace/skills/`
- Claude：`~/.claude/skills/`
- Alma：`~/.config/Alma/skills/`

---

## 🔍 使用方式

### 命令行审计

```bash
# 审计任意技能
python scripts/audit.py /path/to/skill

# 审计已安装的技能
python scripts/audit.py ~/.openclaw/workspace/skills/some-skill
```

### 在 Agent 中使用

当用户问"这个技能安全吗？"或"帮我审计一下这个技能"时，Agent 会：

1. 读取技能的 SKILL.md 和所有脚本文件
2. 扫描危险模式（提示词注入、网络请求、命令执行等）
3. 生成安全报告，标注风险等级
4. 给出是否推荐安装的建议

---

## 📊 审计报告示例

```
## 🔍 Security Audit Report

**Skill:** `some-sketchy-skill`

### Summary: 🟡 MEDIUM RISK

| Severity | Count |
|----------|-------|
| 🔴 High | 0 |
| 🟡 Medium | 3 |
| 🟢 Low | 5 |

### Findings

| Severity | Category | Location | Context |
|----------|----------|----------|---------|
| 🟡 MEDIUM | Network Request | upload.py:42 | requests.post('https://api.unknown.com/upload') |
| 🟡 MEDIUM | Code Execution | helper.py:15 | eval(user_input) |
| 🟡 MEDIUM | API Key | config.py:8 | api_key = "sk-xxxxx" |

### Recommendations

- **Network Request**: 外部 API 调用，确认目标服务器可信
- **Code Execution**: 动态代码执行，存在注入风险
- **API Key**: 硬编码凭证，建议改用环境变量

---

*Audited 8 potential issues*
```

---

## 📁 项目结构

```
skill-auditor/
├── SKILL.md           # 技能描述（Agent 调用指南）
├── README.md          # 项目文档（你现在看到的）
└── scripts/
    └── audit.py       # 核心审计脚本
```

---

## 🎯 风险等级说明

| 等级 | 含义 | 建议 |
|------|------|------|
| ✅ SAFE | 未发现问题 | 放心安装 |
| 🟢 LOW | 轻微风险，上下文相关 | 审核后可安装 |
| 🟡 MEDIUM | 中等风险，需人工确认 | 仔细审核后再决定 |
| ❌ UNSAFE | 高危问题，可能恶意 | 不建议安装 |

---

## 🤝 贡献

欢迎提交 Issue 和 PR：

- 发现新的恶意模式？提交一个 pattern
- 漏报了某个攻击？开个 Issue 附上样本
- 有改进建议？直接 PR

---

## 📄 License

MIT License © 2026

---

## 🙏 致谢

- 所有被恶意技能坑过的受害者（你们激励了这个项目）
- OpenClaw 团队（Skills 生态）
- 白帽子安全社区

---

> **最后提醒**：安装技能前，先跑一遍审计。你的 AI 会感谢你，你的钱包也会感谢你 💰