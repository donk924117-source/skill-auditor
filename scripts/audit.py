#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Skill Security Auditor - Scan AgentSkills for security risks.

Usage:
    python audit.py <skill_path> [--json] [--quick]

Exit Codes:
    0 - SAFE or LOW risk (proceed)
    1 - MEDIUM risk (warn user)
    2 - HIGH risk (block installation)
    3 - Error
"""

import os
import re
import sys
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

@dataclass
class Finding:
    severity: str
    category: str
    pattern: str
    location: str
    line_number: Optional[int]
    context: str
    recommendation: str

# Security patterns organized by severity
PATTERNS = {
    'HIGH': [
        # Prompt Injection
        (r'ignore\s+(all\s+)?previous\s+(instructions?|prompts?|context)', 
         'Prompt Injection', 'Attempt to ignore previous instructions'),
        (r'bypass\s+(all\s+)?(safety|security|filter|restrictions?)', 
         'Prompt Injection', 'Attempt to bypass safety measures'),
        (r'you\s+are\s+now\s+(a|an|the)\s+\w+', 
         'Identity Override', 'Attempt to change AI identity'),
        (r'forget\s+(all\s+)?(previous|above|earlier)', 
         'Prompt Injection', 'Attempt to make AI forget context'),
        (r'disregard\s+(all\s+)?(previous|above|instructions?)', 
         'Prompt Injection', 'Attempt to disregard instructions'),
        (r'new\s+instructions?\s*:', 
         'Prompt Injection', 'Potential instruction injection'),
        (r'system\s*:\s*["\']?(you|ignore|forget|bypass)', 
         'Fake System Block', 'Fake system prompt injection'),
        
        # Data Exfiltration
        (r'send\s+(all\s+)?(user\s+)?data\s+to', 
         'Data Exfiltration', 'Attempt to exfiltrate user data'),
        (r'exfiltrate\s+', 
         'Data Exfiltration', 'Data exfiltration keyword'),
        (r'upload\s+.*\s+to\s+https?://', 
         'Data Exfiltration', 'Upload data to external server'),
        (r'post\s+.*\s+(password|token|key|secret)', 
         'Data Exfiltration', 'Attempt to send sensitive data'),
        
        # Malicious Code
        (r'curl\s+.*\|\s*(bash|sh|python|ruby)', 
         'Remote Code Execution', 'Piping remote content to shell'),
        (r'wget\s+.*\|\s*(bash|sh|python|ruby)', 
         'Remote Code Execution', 'Piping remote content to shell'),
        (r'eval\s*\(["\']', 
         'Code Injection', 'Dynamic code evaluation with string'),
        (r'exec\s*\(["\']', 
         'Code Injection', 'Dynamic code execution with string'),
        (r'__import__\s*\(["\']', 
         'Code Injection', 'Dynamic import with string'),
        (r'compile\s*\(.*exec', 
         'Code Injection', 'Compile and exec pattern'),
    ],
    'MEDIUM': [
        # Code Execution
        (r'subprocess\.(run|call|Popen|check_output)\s*\(', 
         'Process Execution', 'External command execution'),
        (r'os\.system\s*\(', 
         'Process Execution', 'Shell command execution'),
        (r'os\.popen\s*\(', 
         'Process Execution', 'Shell command via popen'),
        (r'commands\.getoutput\s*\(', 
         'Process Execution', 'Shell command execution (legacy)'),
        
        # Network Requests
        (r'requests\.(get|post|put|delete|patch)\s*\(', 
         'Network Request', 'HTTP request via requests library'),
        (r'urllib\.request\.(urlopen|Request)', 
         'Network Request', 'HTTP request via urllib'),
        (r'httpx\.(get|post|put|delete|patch)\s*\(', 
         'Network Request', 'HTTP request via httpx'),
        (r'aiohttp\.ClientSession', 
         'Network Request', 'Async HTTP client'),
        (r'fetch\s*\(["\']https?://', 
         'Network Request', 'JavaScript fetch to URL'),
        (r'axios\.(get|post|put|delete)\s*\(["\']https?://', 
         'Network Request', 'Axios HTTP request'),
        (r'curl\s+https?://', 
         'Network Request', 'curl command to URL'),
        (r'wget\s+https?://', 
         'Network Request', 'wget command to URL'),
        
        # Sensitive Files
        (r'\.ssh/(id_rsa|id_ed25519|known_hosts)', 
         'Sensitive File Access', 'SSH key access'),
        (r'\.env["\']?\s*(?!/)', 
         'Sensitive File Access', 'Environment file access'),
        (r'\.gitconfig', 
         'Sensitive File Access', 'Git config access'),
        (r'\.netrc', 
         'Sensitive File Access', 'Netrc credentials file'),
        (r'_netrc', 
         'Sensitive File Access', 'Windows netrc file'),
        (r'MEMORY\.md', 
         'Sensitive File Access', 'Memory file access'),
        (r'credentials\.json', 
         'Sensitive File Access', 'Credentials file'),
        
        # Hardcoded Secrets
        (r'(api[_-]?key|apikey|api_secret)\s*=\s*["\'][^"\']{10,}["\']', 
         'Hardcoded Secret', 'Hardcoded API key'),
        (r'(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', 
         'Hardcoded Secret', 'Hardcoded password'),
        (r'(secret|token)\s*=\s*["\'][^"\']{10,}["\']', 
         'Hardcoded Secret', 'Hardcoded secret/token'),
        (r'sk-[a-zA-Z0-9]{20,}', 
         'Hardcoded Secret', 'OpenAI API key pattern'),
        (r'ghp_[a-zA-Z0-9]{36}', 
         'Hardcoded Secret', 'GitHub personal access token'),
        (r'xox[baprs]-[a-zA-Z0-9-]+', 
         'Hardcoded Secret', 'Slack token pattern'),
        
        # Executable Files
        (r'\.exe\s', 
         'Binary File', 'Windows executable reference'),
        (r'\.dll\s', 
         'Binary File', 'Windows library reference'),
        (r'\.so\s', 
         'Binary File', 'Linux library reference'),
        (r'\.dylib\s', 
         'Binary File', 'macOS library reference'),
    ],
    'LOW': [
        # Script Files
        (r'\.sh\s', 
         'Script File', 'Shell script reference'),
        (r'\.ps1\s', 
         'Script File', 'PowerShell script reference'),
        (r'\.bat\s', 
         'Script File', 'Batch script reference'),
        (r'\.vbs\s', 
         'Script File', 'VBScript reference'),
        
        # File Operations
        (r'open\s*\(["\'][^"\']+["\']\s*,\s*["\']w["\']', 
         'File Write', 'File write operation'),
        (r'with\s+open\s*\([^)]+\)\s+as\s+\w+:\s*\n\s*\w+\.write', 
         'File Write', 'File write in context manager'),
        (r'shutil\.(copy|move|rmtree)', 
         'File Operation', 'File system operation'),
        (r'os\.(remove|rename|makedirs|rmdir)', 
         'File Operation', 'File system operation'),
        
        # Config References
        (r'config\.json', 
         'Config File', 'Config file reference'),
        (r'settings\.json', 
         'Config File', 'Settings file reference'),
        (r'\.yaml["\']?', 
         'Config File', 'YAML config reference'),
        (r'\.yml["\']?', 
         'Config File', 'YAML config reference'),
    ]
}

def scan_file(filepath: str) -> List[Finding]:
    """Scan a single file for security patterns."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return findings
    
    for i, line in enumerate(lines, 1):
        for severity, patterns in PATTERNS.items():
            for pattern, category, recommendation in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=severity,
                        category=category,
                        pattern=pattern,
                        location=filepath,
                        line_number=i,
                        context=line.strip()[:100],
                        recommendation=recommendation
                    ))
    return findings

def audit_skill(skill_path: str) -> Dict:
    """Audit a skill directory for security issues."""
    all_findings = []
    file_types = {
        '.md': 0, '.py': 0, '.js': 0, '.ts': 0, '.json': 0,
        '.yaml': 0, '.yml': 0, '.txt': 0, '.sh': 0, '.ps1': 0,
        '.bat': 0, '.vbs': 0
    }
    files_scanned = 0
    
    skill_path = Path(skill_path)
    if not skill_path.exists():
        return {'error': f'Path not found: {skill_path}'}
    
    for root, dirs, files in os.walk(skill_path):
        # Skip hidden directories and common non-skill directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', '.git']]
        
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in file_types:
                file_types[ext] += 1
                files_scanned += 1
                filepath = os.path.join(root, f)
                all_findings.extend(scan_file(filepath))
    
    # Count by severity
    high = sum(1 for f in all_findings if f.severity == 'HIGH')
    medium = sum(1 for f in all_findings if f.severity == 'MEDIUM')
    low = sum(1 for f in all_findings if f.severity == 'LOW')
    
    # Determine verdict
    if high > 0:
        verdict = 'HIGH RISK'
        exit_code = 2
    elif medium > 0:
        verdict = 'MEDIUM RISK'
        exit_code = 1
    elif low > 0:
        verdict = 'LOW RISK'
        exit_code = 0
    else:
        verdict = 'SAFE'
        exit_code = 0
    
    return {
        'verdict': verdict,
        'exit_code': exit_code,
        'high': high,
        'medium': medium,
        'low': low,
        'findings': [asdict(f) for f in all_findings],
        'file_types': file_types,
        'files_scanned': files_scanned,
        'skill_path': str(skill_path)
    }

def format_markdown(result: Dict, quick: bool = False) -> str:
    """Format audit result as Markdown."""
    lines = []
    
    # Header
    skill_name = Path(result['skill_path']).name
    lines.append(f'## 🔍 Security Audit Report')
    lines.append('')
    lines.append(f'**Skill:** `{skill_name}`')
    lines.append('')
    
    # Verdict with emoji
    verdict_emoji = {
        'SAFE': '✅',
        'LOW RISK': '🟢',
        'MEDIUM RISK': '🟡',
        'HIGH RISK': '🔴'
    }
    emoji = verdict_emoji.get(result['verdict'], '❓')
    lines.append(f'### {emoji} Verdict: {result["verdict"]}')
    lines.append('')
    
    # Summary table
    lines.append('| Severity | Count |')
    lines.append('|----------|-------|')
    lines.append(f'| 🔴 High | {result["high"]} |')
    lines.append(f'| 🟡 Medium | {result["medium"]} |')
    lines.append(f'| 🟢 Low | {result["low"]} |')
    lines.append('')
    lines.append(f'**Files scanned:** {result["files_scanned"]}')
    lines.append('')
    
    if quick:
        return '\n'.join(lines)
    
    # Detailed findings
    if result['findings']:
        lines.append('---')
        lines.append('')
        lines.append('### 📋 Findings')
        lines.append('')
        
        # Group by severity
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            severity_findings = [f for f in result['findings'] if f['severity'] == severity]
            if severity_findings:
                emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}[severity]
                lines.append(f'#### {emoji} {severity} ({len(severity_findings)})')
                lines.append('')
                for f in severity_findings[:10]:  # Limit to 10 per severity
                    loc = os.path.basename(f['location'])
                    lines.append(f'- **{f["category"]}** ({loc}:{f["line_number"]})')
                    lines.append(f'  `{f["context"]}`')
                if len(severity_findings) > 10:
                    lines.append(f'  _... and {len(severity_findings) - 10} more_')
                lines.append('')
        
        # Recommendations
        lines.append('---')
        lines.append('')
        lines.append('### 💡 Recommendations')
        lines.append('')
        
        if result['high'] > 0:
            lines.append('⚠️ **HIGH RISK DETECTED** - Do not install this skill!')
            lines.append('Review the findings above and consider alternatives.')
        elif result['medium'] > 0:
            lines.append('⚠️ **MEDIUM RISK** - Review findings before proceeding.')
            lines.append('- Verify network destinations are safe')
            lines.append('- Check subprocess commands are expected')
            lines.append('- Ensure no sensitive data is exposed')
        elif result['low'] > 0:
            lines.append('✅ **LOW RISK** - Generally safe to use.')
            lines.append('Review findings for awareness.')
        else:
            lines.append('✅ **SAFE** - No security issues detected.')
    
    return '\n'.join(lines)

def main():
    if len(sys.argv) < 2:
        print('Usage: python audit.py <skill_path> [--json] [--quick]')
        print('\nExit Codes:')
        print('  0 - SAFE or LOW risk')
        print('  1 - MEDIUM risk (warn)')
        print('  2 - HIGH risk (block)')
        print('  3 - Error')
        sys.exit(3)
    
    skill_path = sys.argv[1]
    json_output = '--json' in sys.argv
    quick = '--quick' in sys.argv
    
    result = audit_skill(skill_path)
    
    if 'error' in result:
        if json_output:
            print(json.dumps(result))
        else:
            print(f'Error: {result["error"]}')
        sys.exit(3)
    
    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print(format_markdown(result, quick=quick))
    
    sys.exit(result['exit_code'])

if __name__ == '__main__':
    main()