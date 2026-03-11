#!/usr/bin/env python3
"""
Skill Security Auditor
Scans AgentSkills for potential security risks.
"""

import os
import re
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Finding:
    severity: str  # HIGH, MEDIUM, LOW
    category: str
    pattern: str
    location: str
    line_number: Optional[int]
    context: str
    recommendation: str

# High risk patterns - prompt injection & malicious instructions
HIGH_RISK_PATTERNS = [
    (r'ignore\s+(all\s+)?previous', 'Prompt Injection', 'Attempt to bypass previous instructions'),
    (r'ignore\s+(all\s+)?instructions', 'Prompt Injection', 'Attempt to bypass instructions'),
    (r'disregard\s+(all\s+)?(previous|instructions)', 'Prompt Injection', 'Attempt to bypass instructions'),
    (r'you\s+are\s+now\s+\w+', 'Identity Override', 'Attempt to change AI identity'),
    (r'new\s+identity[:\s]', 'Identity Override', 'Attempt to assign new identity'),
    (r'forget\s+(your\s+)?instructions', 'Prompt Injection', 'Attempt to erase instructions'),
    (r'forget\s+everything', 'Prompt Injection', 'Attempt to erase context'),
    (r'system\s+prompt[:\s]*["\']', 'System Prompt Manipulation', 'Attempt to manipulate system prompt'),
    (r'override\s+(system|default|safety)', 'Safety Override', 'Attempt to override safety measures'),
    (r'bypass\s+(restrictions?|filters?|safety)', 'Safety Bypass', 'Attempt to bypass security'),
    (r'---\s*system\s*---', 'Fake System Block', 'Attempt to inject fake system message'),
    (r'<\s*system\s*>', 'Fake System Block', 'Attempt to inject fake system message'),
]

# Medium risk patterns - network & execution
MEDIUM_RISK_PATTERNS = [
    (r'curl\s+.*(-d|--data|-X\s*POST)', 'Network Request', 'Potential data exfiltration via curl'),
    (r'wget\s+.*(-O|--output)', 'Network Request', 'Potential download/upload via wget'),
    (r'fetch\s*\(\s*["\']https?://', 'Network Request', 'JavaScript fetch to external URL'),
    (r'requests\.(get|post|put|delete)\s*\(', 'Network Request', 'Python requests library call'),
    (r'urllib\.request\.(urlopen|Request)', 'Network Request', 'Python urllib call'),
    (r'http\.client\.', 'Network Request', 'Python HTTP client'),
    (r'socket\.connect\s*\(', 'Network Request', 'Direct socket connection'),
    (r'upload\s*[:=]', 'Data Upload', 'Potential data upload operation'),
    (r'download\s*[:=]', 'Data Download', 'Potential data download operation'),
    (r'api\.key\s*[:=]', 'API Key', 'Hardcoded API key pattern'),
    (r'token\s*[:=]\s*["\'][a-zA-Z0-9]{10,}', 'Token', 'Hardcoded token'),
    (r'password\s*[:=]', 'Password', 'Hardcoded password pattern'),
    (r'secret\s*[:=]\s*["\'][a-zA-Z0-9]{8,}', 'Secret', 'Hardcoded secret'),
    (r'eval\s*\(', 'Code Execution', 'Dynamic code execution'),
    (r'exec\s*\(', 'Code Execution', 'Dynamic code execution'),
    (r'Function\s*\(', 'Code Execution', 'Dynamic function creation'),
    (r'compile\s*\(', 'Code Execution', 'Dynamic code compilation'),
    (r'__import__\s*\(', 'Code Execution', 'Dynamic module import'),
    (r'subprocess\.(run|call|Popen)', 'Process Execution', 'Subprocess call - check command'),
    (r'os\.system\s*\(', 'Process Execution', 'Direct shell command execution'),
    (r'os\.popen\s*\(', 'Process Execution', 'Shell command via popen'),
]

# Low risk patterns - contextual concerns
LOW_RISK_PATTERNS = [
    (r'\.env', 'Config File', 'Environment file reference - check for sensitive data'),
    (r'open\s*\([^)]*["\']w["\']', 'File Write', 'File write operation - check target'),
    (r'shutil\.rmtree', 'File Deletion', 'Directory deletion - check target'),
    (r'os\.remove', 'File Deletion', 'File deletion - check target'),
    (r'\.ssh', 'Sensitive Path', 'SSH directory reference'),
    (r'id_rsa', 'Sensitive Path', 'SSH private key reference'),
    (r'\.gitconfig', 'Sensitive Path', 'Git config reference'),
    (r'\.npmrc', 'Sensitive Path', 'NPM config (may contain tokens)'),
    (r'MEMORY\.md', 'Memory Access', 'Access to AI memory file'),
    (r'USER\.md', 'User Data', 'Access to user profile'),
]

def scan_file(file_path: Path) -> List[Finding]:
    """Scan a single file for security risks."""
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception as e:
        return [Finding('LOW', 'Read Error', str(e), str(file_path), None, '', 'Unable to read file')]
    
    # Check high risk patterns
    for pattern, category, description in HIGH_RISK_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            line_content = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
            findings.append(Finding(
                severity='HIGH',
                category=category,
                pattern=pattern,
                location=str(file_path),
                line_number=line_num,
                context=line_content,
                recommendation=f'{description}. Review carefully or reject skill.'
            ))
    
    # Check medium risk patterns
    for pattern, category, description in MEDIUM_RISK_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            line_content = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
            findings.append(Finding(
                severity='MEDIUM',
                category=category,
                pattern=pattern,
                location=str(file_path),
                line_number=line_num,
                context=line_content,
                recommendation=f'{description}. Verify destination is safe.'
            ))
    
    # Check low risk patterns
    for pattern, category, description in LOW_RISK_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            line_num = content[:match.start()].count('\n') + 1
            line_content = lines[line_num - 1].strip()[:100] if line_num <= len(lines) else ''
            findings.append(Finding(
                severity='LOW',
                category=category,
                pattern=pattern,
                location=str(file_path),
                line_number=line_num,
                context=line_content,
                recommendation=description
            ))
    
    return findings

def check_file_types(skill_path: Path) -> List[Finding]:
    """Check for dangerous file types."""
    findings = []
    
    dangerous_extensions = {'.exe', '.dll', '.so', '.dylib', '.bat', '.cmd', '.ps1', '.sh'}
    
    for file_path in skill_path.rglob('*'):
        if file_path.is_file():
            ext = file_path.suffix.lower()
            if ext in dangerous_extensions:
                findings.append(Finding(
                    severity='MEDIUM',
                    category='Executable File',
                    pattern=ext,
                    location=str(file_path),
                    line_number=None,
                    context='',
                    recommendation=f'Executable file ({ext}) found. Verify source is trusted.'
                ))
    
    return findings

def audit_skill(skill_path: str) -> dict:
    """Main audit function."""
    skill_path = Path(skill_path)
    
    if not skill_path.exists():
        return {'error': f'Skill path not found: {skill_path}'}
    
    all_findings = []
    
    # Scan text files
    text_extensions = {'.md', '.py', '.js', '.ts', '.json', '.yaml', '.yml', '.txt', '.sh', '.ps1'}
    
    for ext in text_extensions:
        for file_path in skill_path.rglob(f'*{ext}'):
            all_findings.extend(scan_file(file_path))
    
    # Check file types
    all_findings.extend(check_file_types(skill_path))
    
    # Calculate summary
    high_count = sum(1 for f in all_findings if f.severity == 'HIGH')
    medium_count = sum(1 for f in all_findings if f.severity == 'MEDIUM')
    low_count = sum(1 for f in all_findings if f.severity == 'LOW')
    
    # Determine verdict
    if high_count > 0:
        verdict = 'UNSAFE'
        emoji = '❌'
    elif medium_count > 0:
        verdict = 'MEDIUM RISK'
        emoji = '🟡'
    elif low_count > 0:
        verdict = 'LOW RISK'
        emoji = '🟢'
    else:
        verdict = 'SAFE'
        emoji = '✅'
    
    return {
        'skill_path': str(skill_path),
        'verdict': verdict,
        'emoji': emoji,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'findings': all_findings,
        'summary': f'{emoji} {verdict} - {high_count} high, {medium_count} medium, {low_count} low risk findings'
    }

def format_report(result: dict) -> str:
    """Format audit result as readable report."""
    if 'error' in result:
        return f"## ❌ Audit Failed\n\n{result['error']}"
    
    lines = [
        f"## 🔍 Security Audit Report",
        f"",
        f"**Skill:** `{Path(result['skill_path']).name}`",
        f"",
        f"### Summary: {result['emoji']} {result['verdict']}",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 High | {result['high_count']} |",
        f"| 🟡 Medium | {result['medium_count']} |",
        f"| 🟢 Low | {result['low_count']} |",
        f"",
    ]
    
    if result['findings']:
        lines.append("### Findings")
        lines.append("")
        lines.append("| Severity | Category | Location | Context |")
        lines.append("|----------|----------|----------|---------|")
        
        for f in result['findings']:
            severity_emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(f.severity, '⚪')
            loc = Path(f.location).name
            ctx = f.context[:50] + '...' if len(f.context) > 50 else f.context
            lines.append(f"| {severity_emoji} {f.severity} | {f.category} | {loc}:{f.line_number or '-'} | {ctx} |")
        
        lines.append("")
        lines.append("### Recommendations")
        lines.append("")
        
        for f in result['findings']:
            if f.severity in ('HIGH', 'MEDIUM'):
                lines.append(f"- **{f.category}**: {f.recommendation}")
    else:
        lines.append("### ✅ No Issues Found")
        lines.append("")
        lines.append("This skill appears safe to use.")
    
    lines.append("")
    lines.append(f"---")
    lines.append(f"*Audited {len(result['findings'])} potential issues*")
    
    return '\n'.join(lines)

if __name__ == '__main__':
    import io
    # Force UTF-8 output for Windows compatibility
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    
    if len(sys.argv) < 2:
        print("Usage: python audit.py <skill_path>")
        sys.exit(1)
    
    result = audit_skill(sys.argv[1])
    print(format_report(result))