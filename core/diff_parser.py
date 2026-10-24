import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

@dataclass
class ChangedLine:
    line_number_old: Optional[int]
    line_number_new: Optional[int]
    line_type: str  # '+', '-', ' '
    content: str

@dataclass
class DiffHunk:
    header: str
    old_start: int
    old_length: int
    new_start: int
    new_length: int
    lines: List[ChangedLine] = field(default_factory=list)

@dataclass
class ParsedFileDiff:
    filename_old: str
    filename_new: str
    hunks: List[DiffHunk] = field(default_factory=list)
    is_noise: bool = False

class DiffParser:
    """
    Hospital-grade unified git diff & code snippet parser.
    Filters out noise files (lockfiles, minified bundles, assets)
    so developers never receive spam notifications.
    """
    
    NOISE_EXTENSIONS = {
        '.lock', '.json.lock', '.min.js', '.min.css', '.map',
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.csv'
    }
    
    NOISE_FILENAMES = {
        'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
        'cargo.lock', 'poetry.lock', 'gemfile.lock', 'requirements.lock'
    }

    @classmethod
    def is_noise_file(cls, filename: str) -> bool:
        base = filename.split('/')[-1].split('\\')[-1].lower()
        if base in cls.NOISE_FILENAMES:
            return True
        for ext in cls.NOISE_EXTENSIONS:
            if base.endswith(ext):
                return True
        return False

    @classmethod
    def parse_git_diff(cls, raw_diff: str) -> List[ParsedFileDiff]:
        files: List[ParsedFileDiff] = []
        if not raw_diff or not raw_diff.strip():
            return files

        raw_files = re.split(r'^diff --git ', raw_diff, flags=re.MULTILINE)
        
        for rf in raw_files:
            if not rf.strip():
                continue
            lines = rf.splitlines()
            header_line = lines[0] if lines else ""
            
            # Extract filenames
            fn_old = "unknown"
            fn_new = "unknown"
            match_header = re.match(r'a/(.*?)\s+b/(.*)', header_line)
            if match_header:
                fn_old, fn_new = match_header.groups()
            else:
                for line in lines[:5]:
                    if line.startswith('--- a/'):
                        fn_old = line[6:]
                    elif line.startswith('+++ b/'):
                        fn_new = line[6:]

            is_noise = cls.is_noise_file(fn_new or fn_old)
            parsed_file = ParsedFileDiff(filename_old=fn_old, filename_new=fn_new, is_noise=is_noise)
            
            if is_noise:
                files.append(parsed_file)
                continue

            current_hunk: Optional[DiffHunk] = None
            cur_old_line = 0
            cur_new_line = 0

            for line in lines:
                if line.startswith('@@'):
                    # Hunk header: @@ -10,5 +10,7 @@
                    hunk_match = re.match(r'@@\s*-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s*@@(.*)', line)
                    if hunk_match:
                        old_s = int(hunk_match.group(1))
                        old_l = int(hunk_match.group(2) or 1)
                        new_s = int(hunk_match.group(3))
                        new_l = int(hunk_match.group(4) or 1)
                        current_hunk = DiffHunk(
                            header=line,
                            old_start=old_s,
                            old_length=old_l,
                            new_start=new_s,
                            new_length=new_l
                        )
                        parsed_file.hunks.append(current_hunk)
                        cur_old_line = old_s
                        cur_new_line = new_s
                elif current_hunk is not None:
                    if line.startswith('+'):
                        current_hunk.lines.append(ChangedLine(
                            line_number_old=None,
                            line_number_new=cur_new_line,
                            line_type='+',
                            content=line[1:]
                        ))
                        cur_new_line += 1
                    elif line.startswith('-'):
                        current_hunk.lines.append(ChangedLine(
                            line_number_old=cur_old_line,
                            line_number_new=None,
                            line_type='-',
                            content=line[1:]
                        ))
                        cur_old_line += 1
                    elif line.startswith(' '):
                        current_hunk.lines.append(ChangedLine(
                            line_number_old=cur_old_line,
                            line_number_new=cur_new_line,
                            line_type=' ',
                            content=line[1:]
                        ))
                        cur_old_line += 1
                        cur_new_line += 1

            files.append(parsed_file)
            
        return files

    @classmethod
    def parse_raw_snippet(cls, filename: str, code: str) -> ParsedFileDiff:
        """Parses a full code snippet as a unified diff for single-file review."""
        lines = code.splitlines()
        hunk = DiffHunk(
            header=f"@@ -1,{len(lines)} +1,{len(lines)} @@",
            old_start=1,
            old_length=len(lines),
            new_start=1,
            new_length=len(lines)
        )
        for idx, line in enumerate(lines, 1):
            hunk.lines.append(ChangedLine(
                line_number_old=idx,
                line_number_new=idx,
                line_type='+',
                content=line
            ))
        return ParsedFileDiff(
            filename_old=filename,
            filename_new=filename,
            hunks=[hunk],
            is_noise=cls.is_noise_file(filename)
        )
