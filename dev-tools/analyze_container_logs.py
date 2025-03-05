#!/usr/bin/env python3
"""
TrueFA Windows Container Log Analyzer

This script helps analyze the logs from running the TrueFA executable in a Windows container.
It identifies common issues and suggests solutions.
"""

import os
import re
import sys
import subprocess
import argparse
from datetime import datetime

# Define patterns to look for in the logs
PATTERNS = {
    "dll_not_found": (
        r"(?i)((failed to load|unable to load|cannot find).*?\.dll)",
        "Missing DLL dependency detected. The executable is trying to load a DLL that isn't available.",
        "1. Make sure the DLL is included in the distribution\n"
        "2. Check if Visual C++ Redistributable is properly installed\n"
        "3. Try using static linking for dependencies"
    ),
    
    "permission_denied": (
        r"(?i)(access denied|permission denied|cannot create directory|cannot write)",
        "Permission issues detected. The application can't write to required directories.",
        "1. Modify the code to check and handle permission errors gracefully\n"
        "2. Use the user's AppData directory instead of program directory\n"
        "3. Add proper error handling for file operations"
    ),
    
    "rust_crypto_timeout": (
        r"(?i)(timeout waiting for salt generation|fallback to python implementation)",
        "Crypto operation timeout detected. The Rust implementation might be hanging.",
        "1. Implement more aggressive timeouts for crypto operations\n"
        "2. Add a marker file to force fallback mode\n"
        "3. Review the Rust implementation for blocking operations"
    ),
    
    "test_file_removal": (
        r"(?i)(unable to remove test file|warning: cannot write to)",
        "Test file removal issues detected. The application can't clean up temporary files.",
        "1. Implement more robust file cleanup with multiple attempts\n"
        "2. Add fallback directory options\n"
        "3. Consider implementing the cleanup utility"
    ),
    
    "vcredist_missing": (
        r"(?i)(missing VCRUNTIME|missing MSVCP|entry point not found)",
        "Visual C++ Runtime issues detected. The executable requires Visual C++ Redistributable.",
        "1. Make sure the correct version of Visual C++ Redistributable is installed\n"
        "2. Consider bundling the required DLLs with the executable\n"
        "3. Use static linking for C++ libraries if possible"
    )
}

def capture_container_logs():
    """
    Capture logs from the running container.
    Returns the log content as a string.
    """
    try:
        result = subprocess.run(
            ["docker", "logs", "truefa-test"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error capturing container logs: {e}")
        print(f"stderr: {e.stderr}")
        return ""
    except FileNotFoundError:
        print("Docker not found. Make sure Docker is installed and in your PATH.")
        return ""

def save_logs_to_file(logs):
    """
    Save the logs to a timestamped file for future reference.
    Returns the path to the created file.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"container_test_{timestamp}.log")
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(logs)
    
    return log_file

def analyze_logs(logs):
    """
    Analyze container logs for common issues.
    Returns a list of detected issues and suggestions.
    """
    issues = []
    
    for issue_type, (pattern, description, solution) in PATTERNS.items():
        matches = re.findall(pattern, logs)
        if matches:
            unique_matches = set()
            for match in matches:
                if isinstance(match, tuple):  # Some regex matches return tuples
                    match = match[0]
                unique_matches.add(match)
            
            issues.append({
                "type": issue_type,
                "description": description,
                "matches": list(unique_matches),
                "solution": solution
            })
    
    return issues

def print_analysis(issues, log_file):
    """
    Print the analysis results in a readable format.
    """
    print("\n" + "=" * 80)
    print("TrueFA Windows Container Test Analysis")
    print("=" * 80)
    
    if not issues:
        print("\n✅ No known issues detected! The executable appears to be working correctly.")
        print("   However, please review the full logs for any application-specific issues.")
    else:
        print(f"\n⚠️ Found {len(issues)} potential issues:")
        
        for i, issue in enumerate(issues, 1):
            print(f"\n{i}. {issue['description']}")
            print("   Evidence:")
            for j, match in enumerate(issue['matches'][:3], 1):  # Show max 3 matches
                print(f"   {j}. {match}")
            if len(issue['matches']) > 3:
                print(f"   ... and {len(issue['matches']) - 3} more similar messages")
            
            print("\n   Suggested solutions:")
            print(f"   {issue['solution']}")
    
    print("\n" + "=" * 80)
    print(f"Full logs saved to: {log_file}")
    print("=" * 80)
    
    if issues:
        most_critical = sorted(issues, key=lambda x: len(x['matches']), reverse=True)[0]
        print("\nMost critical issue:")
        print(f"• {most_critical['description']}")
        print(f"• Try: {most_critical['solution'].split('\n')[0]}")

def main():
    """
    Main entry point for the script.
    """
    parser = argparse.ArgumentParser(description="Analyze TrueFA Windows container test logs")
    parser.add_argument("--log-file", help="Path to existing log file (optional)")
    args = parser.parse_args()
    
    if args.log_file:
        try:
            with open(args.log_file, "r", encoding="utf-8") as f:
                logs = f.read()
        except Exception as e:
            print(f"Error reading log file: {e}")
            return 1
    else:
        print("Capturing logs from Docker container...")
        logs = capture_container_logs()
        if not logs:
            print("No logs captured. Is the container running?")
            return 1
    
    log_file = save_logs_to_file(logs)
    issues = analyze_logs(logs)
    print_analysis(issues, log_file)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
