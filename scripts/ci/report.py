"""Write public CI evidence only; never collect configs, keys, or raw device IPC."""
import datetime
import json
import os
from pathlib import Path

data = {
    "kind": os.environ["PROBE_KIND"],
    "status": "passed" if os.environ.get("PROBE_OUTCOME") == "success" else "failed",
    "commit": os.environ["GITHUB_SHA"],
    "runner_os": os.environ["RUNNER_OS"],
    "runner_arch": os.environ["RUNNER_ARCH"],
    "image": os.environ.get("ImageOS", "unknown"),
    "image_version": os.environ.get("ImageVersion", "unknown"),
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "run_url": f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}",
}
Path(os.environ["RUNNER_TEMP"], "peerimeter-result.json").write_text(json.dumps(data, indent=2) + "\n")
with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
    summary.write("```json\n" + json.dumps(data, indent=2) + "\n```\n")
