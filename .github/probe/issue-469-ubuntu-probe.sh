#!/usr/bin/env bash
# Copyright (C) 2026-2026 Huawei Technologies Co., Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Compare /proc/<pid>/exe visibility and the runner-binary prune decision.
# The product script keeps a 64-hex deployment when `readlink /proc/<pid>/exe`
# contains "/<name>". This probe runs that decision against a live copy of
# /bin/sleep and prints the readlink result instead of treating a deleted file
# as the only signal.
set -u

busy_name="$(printf 'b%.0s' {1..64})"
current_name="$(printf 'a%.0s' {1..64})"

echo "PROBE_IMAGE pretty=$(. /etc/os-release && printf '%s' "$PRETTY_NAME") kernel=$(uname -r)"
echo "PROBE_PTRACE scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo missing)"
echo "PROBE_READLINK path=$(command -v readlink || echo missing)"
if command -v readlink >/dev/null 2>&1; then
  readlink_bin="$(command -v readlink)"
  echo "PROBE_READLINK resolved=$(readlink -f "$readlink_bin" 2>/dev/null || echo unresolved)"
  dpkg -S "$readlink_bin" 2>/dev/null | sed 's/^/PROBE_READLINK package=/' || echo "PROBE_READLINK package=unknown"
  readlink --version 2>&1 | head -n 3 | sed 's/^/PROBE_READLINK version=/' || true
fi
echo "PROBE_TOOLS sh=$(command -v sh || true) dash=$(command -v dash || true) bash=$(command -v bash || true)"
dpkg -l | awk '/^ii +(coreutils|gnu-coreutils|rust-coreutils|coreutils-from-)/ {print "PROBE_PKG "$2" "$3}'

run_one() {
  local label="$1"
  local root="$2"
  mkdir -p "$root"
  python3 - "$label" "$root" "$busy_name" "$current_name" <<'PY'
import os, shutil, subprocess, sys, time

label, root, busy_name, current_name = sys.argv[1:5]
superseded = ["c" * 64, "d" * 64]
path = os.path.join(root, busy_name)
shutil.copy("/bin/sleep", path)
os.chmod(path, 0o700)
for name in [current_name, *superseded, "sciencediscovery-runner"]:
    with open(os.path.join(root, name), "w", encoding="utf-8") as handle:
        handle.write("x")
with open(os.path.join(root, ".upload-" + "f" * 24), "w", encoding="utf-8") as handle:
    handle.write("x")

mount = subprocess.run(["findmnt", "-T", root, "-o", "TARGET,FSTYPE,OPTIONS", "-n"],
                       capture_output=True, text=True)
print(f"PROBE_MOUNT {label} {mount.stdout.strip() or mount.stderr.strip()}")

proc = subprocess.Popen([path, "30"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
seen = None
deadline = time.time() + 5
while time.time() < deadline:
    try:
        seen = os.readlink(f"/proc/{proc.pid}/exe")
    except OSError as error:
        seen = f"ERR {error.errno} {error.strerror}"
    if seen == path:
        break
    time.sleep(0.05)
alive = proc.poll() is None
print(f"PROBE_PARENT {label} pid={proc.pid} alive={alive} seen={seen} want={path}")

sibling = subprocess.run(
    ["python3", "-c",
     "import os,sys\n"
     "try:\n"
     " print(os.readlink(sys.argv[1]))\n"
     "except OSError as error:\n"
     " print(f'ERR {error.errno} {error.strerror}')\n",
     f"/proc/{proc.pid}/exe"],
    capture_output=True, text=True)
print(f"PROBE_SIBLING_PY {label} code={sibling.returncode} out={sibling.stdout.strip()} err={sibling.stderr.strip()}")

visible = subprocess.run(
    ["python3", "-c",
     "import os,sys\n"
     "pid=sys.argv[1]\n"
     "names=('cmdline','comm','maps','stat','status','wchan','loginuid','cwd','root')\n"
     "for name in names:\n"
     " path=f'/proc/{pid}/{name}'\n"
     " try:\n"
     "  with open(path,'rb') as handle:\n"
     "   data=handle.read(180)\n"
     "  shown=data.replace(b'\\x00',b'|').decode('utf-8','replace').replace('\\n',' ')[:160]\n"
     "  print(f'{name} ok {shown}')\n"
     " except OSError as error:\n"
     "  print(f'{name} ERR {error.errno} {error.strerror}')\n",
     str(proc.pid)],
    capture_output=True, text=True)
print(f"PROBE_VISIBLE {label} code={visible.returncode}")
for line in visible.stdout.splitlines():
    print(f"PROBE_VISIBLE {label} {line}")
if visible.stderr.strip():
    print(f"PROBE_VISIBLE_ERR {label} {visible.stderr.strip()}")

for shell in ("/bin/sh", "/bin/dash", "/bin/bash"):
    if not os.path.exists(shell):
        print(f"PROBE_SIBLING_SH {label} shell={shell} missing")
        continue
    result = subprocess.run(
        [shell, "-c", f'readlink "/proc/{proc.pid}/exe"; printf "\\nEXIT:%s\\n" "$?"'],
        capture_output=True, text=True)
    print(f"PROBE_SIBLING_SH {label} shell={shell} code={result.returncode} out={result.stdout.strip()} err={result.stderr.strip()}")

stat_link = subprocess.run(["stat", "-L", "-c", "%d:%i", f"/proc/{proc.pid}/exe"],
                           capture_output=True, text=True)
stat_file = subprocess.run(["stat", "-c", "%d:%i", path], capture_output=True, text=True)
print(f"PROBE_STAT {label} link={stat_link.returncode}:{stat_link.stdout.strip()}:{stat_link.stderr.strip()} file={stat_file.returncode}:{stat_file.stdout.strip()}")

def prune(mode, directory):
    binary = os.path.join(directory, busy_name)
    if mode == "old":
        body = r'''
busy=$(for process in /proc/[0-9]*; do readlink "$process/exe" 2>/dev/null || true; done)
printf '%s\n' "$busy" | grep -F -- "$3" >&2 || true
for candidate in *; do
  case "$candidate" in *[!0-9a-f]*) continue ;; esac
  [ "${#candidate}" -eq 64 ] || continue
  [ "$candidate" = "$2" ] && continue
  printf '%s\n' "$busy" | grep -Fq -- "/$candidate" && continue
  rm -f -- "$candidate" && printf 'pruned %s\n' "$candidate"
done
exit 0
'''
    else:
        body = r'''
for candidate in *; do
  case "$candidate" in *[!0-9a-f]*) continue ;; esac
  [ "${#candidate}" -eq 64 ] || continue
  [ "$candidate" = "$2" ] && continue
  busy=$(for process in /proc/[0-9]*; do readlink "$process/exe" 2>/dev/null || true; done)
  printf '%s\n' "$busy" | grep -F -- "$3" >&2 || true
  printf '%s\n' "$busy" | grep -Fq -- "/$candidate" && continue
  rm -f -- "$candidate" && printf 'pruned %s\n' "$candidate"
done
exit 0
'''
    script = "set -eu\ncd \"$1\" || exit 0\n" + body
    result = subprocess.run(["/bin/sh", "-c", script, "prune", directory, current_name, binary],
                            capture_output=True, text=True)
    names = sorted(os.listdir(directory))
    kept = busy_name in names
    print(f"PROBE_SCRIPT {label} mode={mode} code={result.returncode} kept_busy={kept}")
    print(f"PROBE_SCRIPT_STDOUT {label} mode={mode} {result.stdout.strip()}")
    print(f"PROBE_SCRIPT_NAMES {label} mode={mode} {names}")
    matched = [line for line in result.stderr.splitlines() if binary in line or busy_name in line]
    print(f"PROBE_SCRIPT_MATCH {label} mode={mode} {matched or ['<none>']}")

# Two directories: each script deletes, and the live process must stay on its own file.
old_root = root + "-old"
new_root = root + "-new"
os.makedirs(old_root, exist_ok=True)
os.makedirs(new_root, exist_ok=True)
for name in os.listdir(root):
    source = os.path.join(root, name)
    if os.path.isfile(source):
        shutil.copy(source, os.path.join(old_root, name))
        shutil.copy(source, os.path.join(new_root, name))
# The copies are different inodes. Start one sleep in each directory.
proc.kill()
proc.wait(timeout=5)

def start(directory):
    binary = os.path.join(directory, busy_name)
    os.chmod(binary, 0o700)
    child = subprocess.Popen([binary, "30"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 5
    seen_path = None
    while time.time() < deadline:
        try:
            seen_path = os.readlink(f"/proc/{child.pid}/exe")
        except OSError as error:
            seen_path = f"ERR {error.errno} {error.strerror}"
        if seen_path == binary:
            break
        time.sleep(0.05)
    print(f"PROBE_EXEC {label} dir={directory} pid={child.pid} alive={child.poll() is None} seen={seen_path}")
    return child

old_child = start(old_root)
new_child = start(new_root)
prune("old", old_root)
prune("new", new_root)
for child in (old_child, new_child):
    if child.poll() is None:
        child.kill()
        child.wait(timeout=5)
PY
}

base="${PROBE_BASE:-$PWD/.tmp/issue-469-probe}"
tmp_root="${PROBE_TMP_ROOT:-$base/tmp}"
rm -rf "$base" "$tmp_root"
mkdir -p "$base" "$tmp_root"
# PROBE_TMP_ROOT is /tmp on the runner, which is where Node's os.tmpdir()
# places the unit test. The workspace directory stays on the root disk.
run_one "tmp" "$tmp_root/case"
run_one "workspace" "$base/workspace"
rm -rf "$tmp_root" "$base"
echo "PROBE_DONE"
