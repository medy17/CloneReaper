#!/usr/bin/env python3

import os
import sys
import hashlib
import collections
import platform
import time
import logging
from multiprocessing import Pool, cpu_count
from typing import List, Dict, Tuple, Optional, Callable, Any, NamedTuple

# --- Optional Windows Hardlink Detection ---
win32api_available = False
if platform.system() == "Windows":
    try:
        import win32file
        import win32con

        win32api_available = True
    except ImportError:
        # No need for logging here, will inform user interactively if needed
        pass

# --- Constants ---
DEFAULT_HASH_ALGO = "sha256"
DEFAULT_CHUNK_SIZE = 65536  # 64KB for hashing
DEFAULT_MIN_FILE_SIZE = 1  # Minimum size in bytes to consider
DEFAULT_WORKERS = max(1, cpu_count() // 2)


# --- Configuration Structure ---
class ScanConfig(NamedTuple):
    directory: str
    min_size: int
    hash_algo: str
    partial_hash: bool
    check_hardlinks: bool
    workers: int
    log_level: int = logging.INFO # Keep logging internally


# --- Helper Functions (Mostly Unchanged) ---
def setup_logging(log_level: int):
    """Configures logging."""
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def format_bytes(size: int) -> str:
    """Formats bytes into a human-readable string."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size / 1024:.2f} KB"
    elif size < 1024**3:
        return f"{size / (1024**2):.2f} MB"
    elif size < 1024**4:
        return f"{size / (1024**3):.2f} GB"
    else:
        return f"{size / (1024**4):.2f} TB"


def get_file_id(file_path: str) -> Optional[Tuple[int, int]]:
    """Gets the unique file ID from NTFS MFT (Windows only)."""
    if not win32api_available:
        return None
    try:
        # Same implementation as before...
        handle = win32file.CreateFile(
            file_path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ
            | win32con.FILE_SHARE_WRITE
            | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        info = win32file.GetFileInformationByHandle(handle)
        handle.Close()
        return (info.nFileIndexHigh, info.nFileIndexLow)
    except Exception as e:
        logging.warning(f"Could not get file ID for {file_path}: {e}")
        return None


def compute_hash_worker(args_tuple: Tuple[str, str, int, bool]) -> Tuple[str, Optional[str]]:
    """Worker function for parallel hashing (handles full/partial)."""
    # Same implementation as before...
    file_path, hash_algo_name, chunk_size, partial = args_tuple
    try:
        hasher = hashlib.new(hash_algo_name)
        with open(file_path, "rb") as f:
            if partial:
                chunk = f.read(chunk_size)
                if not chunk:
                    return file_path, "" # Empty file hash
                hasher.update(chunk)
            else:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
        return file_path, hasher.hexdigest()
    except (OSError, IOError) as e:
        logging.warning(f"Could not hash file {file_path}: {e}")
        return file_path, None
    except Exception as e:
        logging.error(f"Unexpected error hashing {file_path}: {e}")
        return file_path, None


# --- Core Logic Functions (Mostly Unchanged) ---
def find_potential_duplicates_by_size(
    directory: str, min_size: int
) -> Dict[int, List[str]]:
    """Scans directory and groups files by size."""
    # Same implementation as before...
    files_by_size = collections.defaultdict(list)
    print(f"\nScanning directory: {directory} for files >= {min_size} bytes...")
    count = 0
    skipped_unreadable = 0
    for root, _, files in os.walk(directory, topdown=True):
        # Basic progress indicator
        if count % 5000 == 0 and count > 0:
             print(f"  ...scanned {count} files", end='\r')

        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                stat_info = os.stat(file_path)
                file_size = stat_info.st_size
                if file_size >= min_size:
                    files_by_size[file_size].append(file_path)
                    count += 1
            except FileNotFoundError:
                 logging.debug(f"File vanished during scan: {file_path}") # Less noisy
            except OSError as e:
                logging.warning(f"Could not access {file_path}: {e}")
                skipped_unreadable += 1

    print(f"  ...scanned {count} files total.                 ") # Clear progress line
    if skipped_unreadable > 0:
        print(f"Skipped {skipped_unreadable} unreadable files/directories.")

    potential_duplicates = {
        size: paths
        for size, paths in files_by_size.items()
        if len(paths) > 1
    }
    print(f"Found {len(potential_duplicates)} sizes with potential duplicates.")
    return potential_duplicates


def identify_hardlinks(
    potential_groups: Dict[int, List[str]]
) -> Tuple[Dict[int, List[str]], Dict[Tuple[int, int], List[str]], int]:
    """Identifies hardlinks within size groups (Windows only)."""
    # Same implementation as before, but using print for user feedback
    if not win32api_available:
        return potential_groups, {}, 0

    print("Checking for hardlinks (Windows specific)...")
    hardlinks_found: Dict[Tuple[int, int], List[str]] = collections.defaultdict(list)
    groups_to_check = {}
    hardlink_space = 0
    processed_files = 0
    total_files_to_process = sum(len(paths) for paths in potential_groups.values())

    for size, paths in potential_groups.items():
        files_by_id = collections.defaultdict(list)
        for path in paths:
            processed_files += 1
            if processed_files % 100 == 0: # Progress indicator
                 print(f"  ...checking hardlink {processed_files}/{total_files_to_process}", end='\r')
            file_id = get_file_id(path)
            if file_id:
                files_by_id[file_id].append(path)

        remaining_paths = []
        for file_id, linked_paths in files_by_id.items():
            if len(linked_paths) > 1:
                hardlinks_found[file_id].extend(linked_paths)
                hardlink_space += size * (len(linked_paths) - 1)
            else:
                remaining_paths.extend(linked_paths)

        paths_without_id = [p for p in paths if get_file_id(p) is None]
        remaining_paths.extend(paths_without_id)

        if len(remaining_paths) > 1:
            groups_to_check[size] = remaining_paths

    print(f"Hardlink check complete. Found {len(hardlinks_found)} sets.          ") # Clear progress
    if hardlink_space > 0:
        print(f"Space shared by hardlinks: {format_bytes(hardlink_space)}")

    return groups_to_check, hardlinks_found, hardlink_space


def identify_duplicates_by_hash(
    groups_to_check: Dict[int, List[str]],
    hash_algo: str,
    chunk_size: int,
    partial_hash: bool,
    num_workers: int,
) -> Dict[str, List[str]]:
    """Identifies duplicates by hashing files, potentially using parallel processing."""
    # Same implementation as before, using print for feedback
    if not groups_to_check:
        return {}

    print(f"\nStarting hash comparison (Algorithm: {hash_algo}, Partial Check: {partial_hash})...")
    duplicates: Dict[str, List[str]] = collections.defaultdict(list)
    files_to_hash_full = []
    total_potential = sum(len(paths) for paths in groups_to_check.values())

    # --- Stage 1: Partial Hashing (if enabled) ---
    if partial_hash:
        print("Performing partial hash check...")
        files_to_hash_partial = [
            (path, hash_algo, chunk_size, True)
            for paths in groups_to_check.values()
            for path in paths
        ]
        print(f"Hashing (partial) {len(files_to_hash_partial)} files using {num_workers} workers...")

        partial_hashes: Dict[str, Optional[str]] = {}
        with Pool(processes=num_workers) as pool:
            results = pool.map(compute_hash_worker, files_to_hash_partial)
            for path, h in results:
                partial_hashes[path] = h

        potential_full_hash_groups = collections.defaultdict(list)
        for size, paths in groups_to_check.items():
            for path in paths:
                phash = partial_hashes.get(path)
                if phash is not None:
                    potential_full_hash_groups[(size, phash)].append(path)

        for (size, phash), paths in potential_full_hash_groups.items():
            if len(paths) > 1:
                files_to_hash_full.extend(paths)
        print(f"Partial hash check complete. Identified {len(files_to_hash_full)} files needing full hash.")

    else:
        files_to_hash_full = [
            path for paths in groups_to_check.values() for path in paths
        ]
        print(f"Full hash check needed for {len(files_to_hash_full)} files.")

    # --- Stage 2: Full Hashing ---
    if not files_to_hash_full:
        print("No files require full hashing.")
        return {}

    print(f"Performing full hash check on {len(files_to_hash_full)} files using {num_workers} workers...")
    files_to_hash_args = [
        (path, hash_algo, chunk_size, False) for path in files_to_hash_full
    ]

    final_hashes: Dict[str, Optional[str]] = {}
    with Pool(processes=num_workers) as pool:
         results = pool.map(compute_hash_worker, files_to_hash_args)
         for path, h in results:
             final_hashes[path] = h

    files_by_full_hash = collections.defaultdict(list)
    for path, full_hash in final_hashes.items():
        if full_hash:
            files_by_full_hash[full_hash].append(path)

    for full_hash, paths in files_by_full_hash.items():
        if len(paths) > 1:
            duplicates[full_hash] = paths

    print(f"Hash comparison complete. Found {len(duplicates)} sets of duplicate files.")
    return duplicates


def calculate_wasted_space(
    duplicates: Dict[str, List[str]], min_size: int
) -> int:
    """Calculates the total wasted space from duplicate files."""
    # Same implementation as before...
    wasted_space = 0
    for file_list in duplicates.values():
        if not file_list:
            continue
        try:
            file_size = os.lstat(file_list[0]).st_size
            if file_size >= min_size:
                wasted_space += file_size * (len(file_list) - 1)
        except OSError as e:
            logging.warning(
                f"Could not get size for {file_list[0]} "
                f"during waste calculation: {e}"
            )
    return wasted_space


def select_file_to_keep(
    file_list: List[str], strategy: str
) -> Tuple[str, List[str]]:
    """Selects which file to keep based on the chosen strategy."""
    # Same implementation as before...
    if not file_list:
        return "", []

    if strategy == "first":
        return file_list[0], file_list[1:]

    sort_key: Optional[Callable[[str], Any]] = None
    reverse_sort = False

    if strategy == "shortest":
        sort_key = len
    elif strategy == "longest":
        sort_key = len
        reverse_sort = True
    elif strategy == "oldest":
        sort_key = lambda p: os.path.getmtime(p)
    elif strategy == "newest":
        sort_key = lambda p: os.path.getmtime(p)
        reverse_sort = True

    if sort_key:
        try:
            sorted_list = sorted(file_list, key=sort_key, reverse=reverse_sort)
            return sorted_list[0], sorted_list[1:]
        except OSError as e:
            logging.warning(f"Could not apply sort strategy due to error: {e}. Keeping first.")
            return file_list[0], file_list[1:]
        except Exception as e:
             logging.warning(f"Error during sorting strategy: {e}. Keeping first.")
             return file_list[0], file_list[1:]
    else:
        return file_list[0], file_list[1:]


# --- Interactive Input Functions ---
def ask_yes_no(prompt: str, default_yes: bool = False) -> bool:
    """Asks a yes/no question."""
    suffix = "(Y/n)" if default_yes else "(y/N)"
    while True:
        response = input(f"{prompt} {suffix}: ").strip().lower()
        if not response:
            return default_yes
        if response in ["y", "yes"]:
            return True
        if response in ["n", "no"]:
            return False
        print("Invalid input. Please enter 'yes' or 'no'.")


def get_directory_from_user() -> str:
    """Prompts user for a valid directory."""
    while True:
        path = input("Enter the directory path to scan: ").strip()
        if os.path.isdir(path):
            return path
        else:
            print(f"Error: '{path}' is not a valid directory. Please try again.")


def get_scan_options_from_user() -> ScanConfig:
    """Gets scanning configuration interactively."""
    print("\n--- Scan Configuration ---")
    directory = get_directory_from_user()

    # Minimum Size
    while True:
        try:
            size_str = input(f"Minimum file size to consider in bytes (default: {DEFAULT_MIN_FILE_SIZE}): ").strip()
            min_size = int(size_str) if size_str else DEFAULT_MIN_FILE_SIZE
            if min_size >= 0:
                break
            else:
                print("Minimum size cannot be negative.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    # Hash Algorithm
    available_algos = sorted(list(hashlib.algorithms_available))
    print("Available hash algorithms:")
    for i, algo in enumerate(available_algos):
        print(f"  {i+1}. {algo}", end="  ")
        if (i + 1) % 5 == 0: print() # Format nicely
    print()
    while True:
        algo_choice = input(f"Choose hash algorithm number or name (default: {DEFAULT_HASH_ALGO}): ").strip()
        if not algo_choice:
            hash_algo = DEFAULT_HASH_ALGO
            break
        try:
            # Try index first
            index = int(algo_choice) - 1
            if 0 <= index < len(available_algos):
                hash_algo = available_algos[index]
                break
            else:
                print("Invalid number.")
        except ValueError:
            # Try name
            if algo_choice in available_algos:
                hash_algo = algo_choice
                break
            else:
                print(f"Invalid algorithm name '{algo_choice}'.")

    # Partial Hash
    partial_hash = ask_yes_no("Use partial hash pre-check (faster for many large files)?", default_yes=False)

    # Hardlink Check
    check_hardlinks = False
    if platform.system() == "Windows":
        if win32api_available:
            check_hardlinks = ask_yes_no("Check for hardlinks (Windows NTFS only, recommended)?", default_yes=True)
        else:
            print("Note: pywin32 not found, cannot check for hardlinks.")
    else:
        print("Note: Hardlink check is only available on Windows.")


    # Workers
    max_workers = cpu_count()
    while True:
        try:
            workers_str = input(f"Number of parallel workers for hashing (1-{max_workers}, default: {DEFAULT_WORKERS}): ").strip()
            workers = int(workers_str) if workers_str else DEFAULT_WORKERS
            if 1 <= workers <= max_workers:
                break
            else:
                print(f"Please enter a number between 1 and {max_workers}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    config = ScanConfig(
        directory=directory,
        min_size=min_size,
        hash_algo=hash_algo,
        partial_hash=partial_hash,
        check_hardlinks=check_hardlinks,
        workers=workers,
    )

    print("\n--- Configuration Summary ---")
    print(f"Directory:       {config.directory}")
    print(f"Min File Size:   {config.min_size} bytes")
    print(f"Hash Algorithm:  {config.hash_algo}")
    print(f"Partial Hashing: {'Yes' if config.partial_hash else 'No'}")
    print(f"Check Hardlinks: {'Yes' if config.check_hardlinks else 'No'}")
    print(f"Parallel Workers:{config.workers}")

    if ask_yes_no("Proceed with this configuration?", default_yes=True):
        return config
    else:
        print("Configuration cancelled. Exiting.")
        sys.exit(0)


def get_deletion_options(duplicates: Dict[str, List[str]]) -> Optional[str]:
    """Asks user if they want to delete and how."""
    num_duplicates = sum(len(v) - 1 for v in duplicates.values())
    num_sets = len(duplicates)
    wasted_space = calculate_wasted_space(duplicates, 1) # Use 1 temporarily for display

    print("\n--- Deletion Options ---")
    print(f"Found {num_duplicates} duplicate files across {num_sets} sets.")
    print(f"Potential space savings: {format_bytes(wasted_space)}")

    if not ask_yes_no("Do you want to proceed with deleting duplicates?", default_yes=False):
        return None

    strategies = ["first", "oldest", "newest", "shortest", "longest"]
    print("Choose which file to KEEP in each duplicate set:")
    for i, strat in enumerate(strategies):
        print(f"  {i+1}. {strat.capitalize()}")

    while True:
        choice_str = input(f"Enter strategy number (default: 1 - First): ").strip()
        if not choice_str:
            return strategies[0]
        try:
            index = int(choice_str) - 1
            if 0 <= index < len(strategies):
                return strategies[index]
            else:
                print("Invalid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")


def confirm_deletion(num_files: int, total_size: int) -> bool:
    """Final confirmation before deleting files."""
    print("\n--- FINAL CONFIRMATION ---")
    print(f"You are about to permanently delete {num_files} files.")
    print(f"Total size to be deleted: {format_bytes(total_size)}")
    print("This action CANNOT be undone.")
    return ask_yes_no("Are you absolutely sure you want to delete these files?", default_yes=False)


def delete_duplicates_interactive(
    duplicates: Dict[str, List[str]],
    keep_strategy: str,
) -> Tuple[int, int]:
    """Deletes duplicate files based on keep strategy, with progress."""
    if not duplicates:
        return 0, 0

    total_to_delete_count = sum(len(v) - 1 for v in duplicates.values())
    total_deleted_count = 0
    total_deleted_size = 0

    print(f"\nProcessing deletions (keeping: {keep_strategy})...")

    for file_hash, file_list in duplicates.items():
        if len(file_list) < 2:
            continue

        try:
            keep_file, delete_list = select_file_to_keep(file_list, keep_strategy)
            logging.debug(f"Keeping: {keep_file} (Strategy: {keep_strategy})")

            for file_to_delete in delete_list:
                try:
                    file_size = os.lstat(file_to_delete).st_size
                    print(f"  Deleting: {file_to_delete} ({format_bytes(file_size)})", end='\r')
                    os.remove(file_to_delete)
                    total_deleted_count += 1
                    total_deleted_size += file_size
                except OSError as e:
                    print() # Ensure error message is on new line
                    logging.error(f"Error deleting {file_to_delete}: {e}")
                # Basic progress for deletion
                if total_deleted_count % 10 == 0:
                    print(f"  Deleted {total_deleted_count}/{total_to_delete_count} files...", end='\r')

        except Exception as e:
            print() # Ensure error message is on new line
            logging.error(f"Error processing group for hash {file_hash}: {e}")

    print(f"Deletion process complete. Deleted {total_deleted_count} files.          ") # Clear progress line
    return total_deleted_count, total_deleted_size


# --- Main Execution ---
def main():
    setup_logging(logging.INFO) # Setup basic logging for warnings/errors
    print("--- Duplicate File Finder ---")

    # 1. Get Configuration
    config = get_scan_options_from_user()

    start_time = time.time()

    # 2. Find potential duplicates by size
    potential_groups = find_potential_duplicates_by_size(
        config.directory, config.min_size
    )

    # 3. (Optional) Identify and filter out hardlinks
    groups_to_hash = potential_groups
    hardlinks_found = {}
    hardlink_space = 0
    if config.check_hardlinks:
        groups_to_hash, hardlinks_found, hardlink_space = identify_hardlinks(
            potential_groups
        )

    # 4. Identify duplicates by hashing
    duplicates = identify_duplicates_by_hash(
        groups_to_hash,
        config.hash_algo,
        DEFAULT_CHUNK_SIZE,
        config.partial_hash,
        config.workers,
    )

    # 5. Report results
    print("\n--- Scan Results ---")
    if not duplicates and not hardlinks_found:
        print("No duplicate files or hardlinks found.")
    else:
        if hardlinks_found:
            print("\nHardlinks Found (sharing space, not true duplicates):")
            for file_id, paths in hardlinks_found.items():
                 # Truncate ID display if too long? For now, show full.
                 print(f"  ID: {file_id} ({len(paths)} links, Size: {format_bytes(os.path.getsize(paths[0]))})")
                 for p in paths:
                     print(f"    - {p}")

        if duplicates:
            print("\nDuplicate Files Found:")
            wasted_space = calculate_wasted_space(duplicates, config.min_size)
            print(f"(Total potential space savings: {format_bytes(wasted_space)})")
            for file_hash, paths in duplicates.items():
                print(f"  Hash: {file_hash[:12]}... ({len(paths)} files, Size: {format_bytes(os.path.getsize(paths[0]))})")
                for p in paths:
                    print(f"    - {p}")

            # 6. Handle Deletion (if requested and duplicates exist)
            keep_strategy = get_deletion_options(duplicates)
            if keep_strategy:
                files_to_delete_count = sum(len(v) - 1 for v in duplicates.values())
                size_to_delete = calculate_wasted_space(duplicates, config.min_size)

                if confirm_deletion(files_to_delete_count, size_to_delete):
                    deleted_count, deleted_size = delete_duplicates_interactive(
                        duplicates, keep_strategy
                    )
                    print(f"\nSuccessfully deleted {deleted_count} files, freeing {format_bytes(deleted_size)}.")
                else:
                    print("Deletion cancelled.")
            else:
                 print("\nNo files were deleted.")

        elif not hardlinks_found: # Only print if no duplicates *and* no hardlinks
             print("No duplicate files found.")


    end_time = time.time()
    print(f"\nScript finished in {end_time - start_time:.2f} seconds.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        logging.exception("An unexpected error occurred:") # Log the full traceback
        print(f"\nAn unexpected error occurred: {e}")
        sys.exit(1)
