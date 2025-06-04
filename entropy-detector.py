import argparse
import math
import os
import re
import sys
import threading
from typing import List, NamedTuple
from pathlib import Path

MIN_CHARACTERS_DEFAULT = 8
RESULT_COUNT_DEFAULT = 10
EXPLORE_HIDDEN_DEFAULT = False
EXTENSIONS_TO_IGNORE_DEFAULT = ".pyc,yarn.lock,go.mod,go.sum,go.work.sum,package-lock.json,.wasm,.pdf"


class Entropy(NamedTuple):
    entropy: float
    file: str
    line_num: int
    line: str


class Entropies:
    def __init__(self, n: int):
        self.entropies = [Entropy(0.0, "", 0, "")] * n
        self.max_length = n
        self.lock = threading.Lock()

    def add(self, e: Entropy) -> None:
        if self.entropies[-1].entropy >= e.entropy:
            return

        if not disable_advanced_mode:
            line = e.line.lower().replace("'", "").replace('"', '')
            if (media_base64_regex.search(line) or
                    line.startswith("http") or
                    "abcdefghijklmnopqrstuvwxyz" in line or
                    "aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz" in line):
                return

        with self.lock:
            if self.entropies[-1].entropy >= e.entropy:
                return

            insert_idx = 0
            for i, item in enumerate(self.entropies):
                if e.entropy > item.entropy:
                    insert_idx = i
                    break

            self.entropies = (
                    self.entropies[:insert_idx] +
                    [e] +
                    self.entropies[insert_idx:-1]
            )


def entropy(text: str) -> float:
    if not text:
        return 0.0

    char_count = {}
    for char in text:
        char_count[char] = char_count.get(char, 0) + 1

    entropy_val = 0.0
    text_len = len(text)
    for count in char_count.values():
        prob = count / text_len
        if prob > 0:
            entropy_val -= prob * math.log2(prob)
    print(f'{entropy_val}, {text_len},  {char_count}')
    return entropy_val


def is_file_hidden(filename: str) -> bool:
    if filename == ".":
        return False
    filename = filename.lstrip("./")
    return filename.startswith(".") or filename == "node_modules"


def is_file_included(filename: str) -> bool:
    for ext in extensions_to_ignore:
        if filename.endswith(ext):
            return False

    if not extensions:
        return True

    return any(filename.endswith(ext) for ext in extensions)


def remove_empty_strings(items: List[str]) -> List[str]:
    items = sorted(set(items))
    return [item for item in items if item]


def read_file(entropies: Entropies, file_name: str) -> None:
    try:
        file_info = os.stat(file_name)
    except OSError as e:
        print(f"Error reading file {file_name}: {e}", file=sys.stderr)
        return

    if is_file_hidden(file_name) and not explore_hidden:
        return

    if os.path.isdir(file_name):
        try:
            for item in os.listdir(file_name):
                threading.Thread(
                    target=read_file,
                    args=(entropies, os.path.join(file_name, item))
                ).start()
        except OSError as e:
            print(f"Error reading directory {file_name}: {e}", file=sys.stderr)
        return

    if not is_file_included(file_name):
        return

    try:
        with open(file_name, 'r', encoding='utf-8', errors='ignore') as file:
            for i, line in enumerate(file, 1):
                line = line.strip()

                if i == 1 and not include_binary_files:
                    try:
                        line.encode('utf-8')
                    except UnicodeEncodeError:
                        break

                for field in line.split():
                    if len(field) < min_characters:
                        continue

                    entropies.add(Entropy(
                        entropy=entropy(field),
                        file=file_name,
                        line_num=i,
                        line=field
                    ))
    except OSError as e:
        print(f"Error reading file {file_name}: {e}", file=sys.stderr)


def main():
    global min_characters, result_count, explore_hidden, extensions
    global extensions_to_ignore, discrete, include_binary_files
    global disable_advanced_mode, media_base64_regex

    parser = argparse.ArgumentParser(
        description="Finds the highest entropy strings in files. The higher the entropy, the more random the string is. Useful for finding secrets (and alphabets, it seems).",
        epilog="Please support me on GitHub: https://github.com/EwenQuim",
        usage="%(prog)s [options] file1 file2 file3 ..."
    )
    parser.add_argument(
        "-min", type=int, default=MIN_CHARACTERS_DEFAULT,
        help="Minimum number of characters in the line to consider computing entropy"
    )
    parser.add_argument(
        "-top", type=int, default=RESULT_COUNT_DEFAULT,
        help="Number of results to display"
    )
    parser.add_argument(
        "-include-hidden", action="store_true", default=EXPLORE_HIDDEN_DEFAULT,
        help="Search in hidden files and folders (.git, .env...). Slows down the search."
    )
    parser.add_argument(
        "-ext", type=str, default="",
        help="Search only in files with these extensions. Comma separated list, e.g. go,py,js (default all files)"
    )
    parser.add_argument(
        "-ignore-ext", type=str, default="",
        help="Ignore files with these suffixes. Comma separated list, e.g. min.css,_test.go,pdf,Test.php. Adds ignored extensions to the default ones."
    )
    parser.add_argument(
        "-ignore-ext-no-defaults", action="store_true",
        help=f"Remove the default ignored extensions (default {EXTENSIONS_TO_IGNORE_DEFAULT})"
    )
    parser.add_argument(
        "-discrete", action="store_true",
        help="Only show the entropy and file, not the line containing the possible secret"
    )
    parser.add_argument(
        "-binaries", action="store_true",
        help="Include binary files in search. Slows down the search and creates many false positives."
    )
    parser.add_argument(
        "-dumb", action="store_true",
        help="Just dumb entropy. Disable filters that removes alphabets, urls, base64 encoded images and other false positives."
    )
    parser.add_argument("files", nargs="*", help="Files or directories to scan")

    args = parser.parse_args()

    min_characters = args.min
    result_count = args.top
    explore_hidden = args.include_hidden
    discrete = args.discrete
    include_binary_files = args.binaries
    disable_advanced_mode = args.dumb
    extensions = remove_empty_strings(args.ext.split(","))
    extensions_to_ignore_str = (
        args.ignore_ext + "," + EXTENSIONS_TO_IGNORE_DEFAULT
        if not args.ignore_ext_no_defaults
        else args.ignore_ext
    )
    extensions_to_ignore = remove_empty_strings(extensions_to_ignore_str.split(","))
    media_base64_regex = re.compile(r"(audio|video|image|font)/[-+.\w]+;base64")

    file_names = args.files if args.files else ["."]
    entropies = Entropies(result_count)

    threads = []
    for file_name in file_names:
        t = threading.Thread(target=read_file, args=(entropies, file_name))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    is_terminal = sys.stdout.isatty()
    red_mark = "\033[31m" if is_terminal else ""
    reset_mark = "\033[0m" if is_terminal else ""

    for entropy_item in entropies.entropies:
        if entropy_item.entropy == 0.0:
            continue
        line = "" if discrete else entropy_item.line
        print(f"{entropy_item.entropy:.3f}: {red_mark}{entropy_item.file}:{entropy_item.line_num}{reset_mark} {line}")


if __name__ == "__main__":
    main()
