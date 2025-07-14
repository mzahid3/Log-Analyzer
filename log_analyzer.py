# log_analyzer.py

"""
Simple Log File Analyzer
Author: Naveed Z 
Description: Scans a log file for suspicious keywords and outputs matched lines.
"""

import sys

# Define suspicious keywords
SUSPICIOUS_KEYWORDS = [
    "failed",
    "error",
    "unauthorized",
    "denied",
    "root",
    "admin",
    "attack",
    "exploit",
    "brute force",
    "malware"
]

def scan_log(file_path):
    """
    Scans the given log file for suspicious keywords.
    """
    try:
        with open(file_path, "r") as log_file:
            lines = log_file.readlines()

        print(f"Scanning '{file_path}' for suspicious keywords...\n")

        suspicious_lines = []

        for line_num, line in enumerate(lines, start=1):
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword.lower() in line.lower():
                    suspicious_lines.append((line_num, line.strip()))
                    break  # Avoid duplicate keyword hits in same line

        if suspicious_lines:
            print(f"Suspicious lines found ({len(suspicious_lines)}):\n")
            for line_num, line_content in suspicious_lines:
                print(f"[Line {line_num}]: {line_content}")
        else:
            print("No suspicious keywords found in the log file.")

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python log_analyzer.py <log_file_path>")
    else:
        scan_log(sys.argv[1])
