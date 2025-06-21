🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥
🔥     ██████╗██╗      ██████╗ ███╗   ██╗███████╗██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗  🔥
🔥    ██╔════╝██║     ██╔═══██╗████╗  ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗ 🔥
🔥    ██║     ██║     ██║   ██║██╔██╗ ██║█████╗  ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝ 🔥
🔥    ██║     ██║     ██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗ 🔥
🔥    ╚██████╗███████╗╚██████╔╝██║ ╚████║███████╗██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║ 🔥
🔥     ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝ 🔥
🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥

# CloneReaper

A powerful and efficient duplicate file finder with interactive options for managing disk space.

## Overview

CloneReaper is a Python-based utility that helps you identify and manage duplicate files on your system. It uses a multi-stage approach to efficiently scan directories, identify potential duplicates, and provide interactive options for removing unnecessary copies.

## Features

- **Efficient scanning**: Uses file size as an initial filter to quickly identify potential duplicates
- **Accurate detection**: Performs cryptographic hash comparisons to ensure files are genuine duplicates
- **Performance optimized**:
    - Multi-core parallel processing for faster hash calculations
    - Optional partial hash pre-checking for improved performance with large files
    - Configurable hash algorithms
- **Windows hardlink detection**: Identifies hardlinked files to avoid false positives (Windows/NTFS only)
- **Interactive interface**:
    - Guided configuration setup
    - Multiple file retention strategies (keep oldest, newest, shortest path, etc.)
    - Space savings calculations
    - Confirmation prompts for safe operation
- **Detailed reporting**: Provides comprehensive information about duplicate sets

## Requirements

- Python 3.8+
- For Windows hardlink detection: `pywin32` package (optional)

## Installation

1. Clone or download this repository
2. Install optional dependencies if needed:

    `pip install pywin32    # For Windows hardlink detection`

## Usage

Simply run the script with Python and follow the interactive prompts:

`python CloneReaper.py`

The tool will guide you through:

1. Selecting a directory to scan
2. Setting minimum file size to consider
3. Choosing a hash algorithm
4. Configuring performance options
5. Reviewing results
6. Optional deletion with retention strategy selection

## Configuration Options

- **Directory**: The root folder to scan for duplicates
- **Minimum file size**: Ignore files smaller than this (bytes)
- **Hash algorithm**: Choose from any algorithm supported by your Python hashlib
- **Partial hash**: Enable faster pre-checking using only the first 64KB of files
- **Hardlink detection**: Find and report hardlinked files (Windows only)
- **Worker processes**: Number of parallel hash operations (default: half of CPU cores)

## Deletion Strategies

When removing duplicates, you can choose which file to keep:

- **First**: Keep the first file found in each set
- **Oldest**: Keep the file with the earliest modification time
- **Newest**: Keep the file with the latest modification time
- **Shortest**: Keep the file with the shortest path name
- **Longest**: Keep the file with the longest path name

## Safety Features

- Clear confirmation prompts before any file deletion
- Summary of space to be freed before confirmation
- Error handling to prevent accidental data loss

## Performance Tips

- For large file systems, enable partial hash pre-checking
- Adjust worker count based on your system capabilities
- Set a reasonable minimum file size to avoid processing tiny files
