#!/usr/bin/env python3
"""Parse claude --output-format stream-json and write activity to a log file.

Usage:
    claude -p "prompt" --output-format stream-json --verbose | python3 tools/stream_parser.py <logfile>
"""
import json
import sys
from datetime import datetime


def main():
    if len(sys.argv) < 2:
        print("Usage: stream_parser.py <logfile>", file=sys.stderr)
        sys.exit(1)

    logfile = sys.argv[1]

    with open(logfile, "a", buffering=1) as f:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                msg_type = obj.get("type", "")

                if msg_type == "system":
                    ts = datetime.now().strftime("%H:%M:%S")
                    f.write(f"[{ts}] Session started\n")
                    f.flush()

                elif msg_type == "assistant":
                    # content can be at obj["content"] or obj["message"]["content"]
                    content = obj.get("content") or []
                    if not content:
                        msg = obj.get("message", {})
                        content = msg.get("content", [])

                    for block in content:
                        btype = block.get("type", "")
                        if btype == "text":
                            text = block.get("text", "")
                            if text:
                                f.write(text + "\n")
                                f.flush()
                        elif btype == "tool_use":
                            name = block.get("name", "")
                            inp = block.get("input", {})
                            ts = datetime.now().strftime("%H:%M:%S")
                            # Show useful context for each tool
                            detail = ""
                            if name == "Agent":
                                detail = inp.get("description", inp.get("subagent_type", ""))
                            elif name == "Read":
                                detail = inp.get("file_path", "")
                            elif name == "Bash":
                                cmd = inp.get("command", "")
                                detail = cmd[:80] + ("..." if len(cmd) > 80 else "")
                            elif name == "Write":
                                detail = inp.get("file_path", "")
                            elif name == "Edit":
                                detail = inp.get("file_path", "")
                            elif name in ("Grep", "Glob"):
                                detail = inp.get("pattern", "")
                            elif name == "WebFetch":
                                detail = inp.get("url", "")[:80]
                            elif name == "WebSearch":
                                detail = inp.get("query", "")[:80]
                            else:
                                # Generic: show first string value
                                for v in inp.values():
                                    if isinstance(v, str) and v:
                                        detail = v[:60]
                                        break

                            if detail:
                                f.write(f"[{ts}] >> {name}: {detail}\n")
                            else:
                                f.write(f"[{ts}] >> {name}\n")
                            f.flush()

                elif msg_type == "result":
                    result = obj.get("result", "")
                    if result:
                        f.write("\n" + result + "\n")
                        f.flush()
                    cost = obj.get("total_cost_usd")
                    duration = obj.get("duration_ms")
                    turns = obj.get("num_turns")
                    if cost is not None:
                        f.write(f"\n[cost: ${cost:.4f} | duration: {duration}ms | turns: {turns}]\n")
                        f.flush()

            except (json.JSONDecodeError, KeyError, TypeError):
                pass


if __name__ == "__main__":
    main()
