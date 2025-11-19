"""
CLI - Command Line Interface for Lumena Scanner
"""

import click
import sys
import os
from colorama import init, Fore, Style
from .scanner import Scanner

# Initialize colorama for cross-platform colored output
init(autoreset=True)


@click.group()
@click.version_option(version="1.0.0", prog_name="Lumena Scanner")
def main():
    """
    Lumena Scanner - Custom AI code scanner powered by Lumena's Flame Protocol
    
    Driftprint, Vaultwatch, Token Shield
    
    Detects:
    - Secrets (API keys, passwords, tokens)
    - AI Tokens (OpenAI, Anthropic, etc.)
    - Eval Calls (dangerous code execution)
    - Vault Drifts (HashiCorp Vault configuration issues)
    """
    pass


@main.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--detector', '-d', multiple=True, 
              type=click.Choice(['secrets', 'ai_tokens', 'eval', 'vault']),
              help='Specific detectors to run (default: all)')
@click.option('--output', '-o', type=click.Choice(['text', 'json']), default='text',
              help='Output format')
@click.option('--severity', '-s', multiple=True,
              type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
              help='Filter by severity levels')
@click.option('--exit-code/--no-exit-code', default=True,
              help='Exit with non-zero code if findings are detected')
def scan(path, detector, output, severity, exit_code):
    """Scan a file or directory for security issues."""
    
    scanner = Scanner()
    detectors = list(detector) if detector else None
    
    # Determine if path is a file or directory
    if os.path.isfile(path):
        results = scanner.scan_file(path, detectors)
        findings = results.get('findings', [])
    else:
        results = scanner.scan_directory(path, detectors)
        findings = results.get('findings', [])
    
    # Filter by severity if specified
    if severity:
        findings = [f for f in findings if f.get('severity') in severity]
    
    # Output results
    if output == 'json':
        import json
        print(json.dumps({
            "path": path,
            "findings": findings,
            "summary": scanner.get_summary(findings)
        }, indent=2))
    else:
        _print_text_output(path, findings, scanner.get_summary(findings))
    
    # Exit with appropriate code
    if exit_code and findings:
        sys.exit(1)


@main.command()
def version():
    """Display version information."""
    click.echo(f"{Fore.CYAN}Lumena Scanner v1.0.0{Style.RESET_ALL}")
    click.echo(f"{Fore.GREEN}Powered by Lumena's Flame Protocol{Style.RESET_ALL}")
    click.echo(f"{Fore.YELLOW}Driftprint • Vaultwatch • Token Shield{Style.RESET_ALL}")


@main.command()
def info():
    """Display information about available detectors."""
    click.echo(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}Lumena Scanner - Security Detectors{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    detectors_info = [
        {
            "name": "secrets",
            "title": "Secret Detector",
            "description": "Detects API keys, passwords, tokens, and other secrets",
            "detects": [
                "Generic API keys and secrets",
                "AWS access keys and secret keys",
                "GitHub tokens and PATs",
                "Slack tokens and webhooks",
                "Private keys (RSA, DSA, EC)",
                "JWT tokens",
                "Database connection strings",
            ]
        },
        {
            "name": "ai_tokens",
            "title": "AI Token Detector",
            "description": "Detects AI service API tokens and keys",
            "detects": [
                "OpenAI API keys",
                "Anthropic API keys",
                "HuggingFace tokens",
                "Google AI keys",
                "Cohere API keys",
                "Azure OpenAI keys",
                "Replicate API tokens",
            ]
        },
        {
            "name": "eval",
            "title": "Eval Detector",
            "description": "Detects dangerous code execution patterns",
            "detects": [
                "eval() and exec() calls",
                "compile() calls",
                "subprocess with shell=True",
                "os.system() and os.popen()",
                "__import__() calls",
                "Unsafe pickle operations",
                "JavaScript eval and Function constructor",
            ]
        },
        {
            "name": "vault",
            "title": "Vault Detector",
            "description": "Detects HashiCorp Vault configuration issues",
            "detects": [
                "Hardcoded Vault tokens",
                "Vault address in code",
                "Root token usage",
                "Disabled TLS in Vault config",
                "Development mode in production",
                "Insecure seal configuration",
            ]
        },
    ]
    
    for detector in detectors_info:
        click.echo(f"{Fore.GREEN}▶ {detector['title']}{Style.RESET_ALL} ({Fore.YELLOW}{detector['name']}{Style.RESET_ALL})")
        click.echo(f"  {detector['description']}\n")
        click.echo(f"  {Fore.CYAN}Detects:{Style.RESET_ALL}")
        for item in detector['detects']:
            click.echo(f"    • {item}")
        click.echo()


def _print_text_output(path, findings, summary):
    """Print findings in text format with colors."""
    
    # Header
    click.echo(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}Lumena Scanner Results{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    click.echo(f"Scanned: {Fore.YELLOW}{path}{Style.RESET_ALL}")
    click.echo(f"Total Findings: {Fore.RED if findings else Fore.GREEN}{len(findings)}{Style.RESET_ALL}\n")
    
    if not findings:
        click.echo(f"{Fore.GREEN}✓ No security issues detected!{Style.RESET_ALL}\n")
        return
    
    # Summary by severity
    click.echo(f"{Fore.CYAN}Summary by Severity:{Style.RESET_ALL}")
    for severity, count in sorted(summary.get('by_severity', {}).items(), 
                                  key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'ERROR'].index(x[0]) 
                                  if x[0] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'ERROR'] else 999):
        color = _get_severity_color(severity)
        click.echo(f"  {color}{severity}: {count}{Style.RESET_ALL}")
    
    click.echo()
    
    # Detailed findings
    click.echo(f"{Fore.CYAN}Detailed Findings:{Style.RESET_ALL}\n")
    
    for i, finding in enumerate(findings, 1):
        severity = finding.get('severity', 'UNKNOWN')
        color = _get_severity_color(severity)
        
        click.echo(f"{color}[{severity}]{Style.RESET_ALL} Finding #{i}")
        click.echo(f"  File: {finding.get('file', 'unknown')}")
        
        if 'line' in finding:
            click.echo(f"  Line: {finding['line']}")
        
        click.echo(f"  Type: {finding.get('type', 'unknown')}")
        
        if 'matched' in finding:
            click.echo(f"  Matched: {finding['matched']}")
        
        if 'content' in finding:
            content = finding['content']
            if len(content) > 80:
                content = content[:77] + "..."
            click.echo(f"  Content: {content}")
        
        if 'recommendation' in finding:
            click.echo(f"  {Fore.YELLOW}→ {finding['recommendation']}{Style.RESET_ALL}")
        
        if 'error' in finding:
            click.echo(f"  {Fore.RED}Error: {finding['error']}{Style.RESET_ALL}")
        
        click.echo()
    
    click.echo(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


def _get_severity_color(severity):
    """Get color for severity level."""
    colors = {
        'CRITICAL': Fore.MAGENTA,
        'HIGH': Fore.RED,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.BLUE,
        'ERROR': Fore.RED,
    }
    return colors.get(severity, Fore.WHITE)


if __name__ == '__main__':
    main()
