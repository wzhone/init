#!/usr/bin/env python3
"""Run with python3 tests/check_init.py; all writes and system commands are isolated."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]


def function(script, name):
    return re.search(rf"(?ms)^{name}\(\) \{{\n.*?^\}}", (REPO / script).read_text())[0]


def run(code, data="", expected=0, **env):
    result = subprocess.run(["bash", "-c", code], input=data, text=True,
                            capture_output=True, timeout=15, env={**os.environ, **env})
    assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
    return result.stdout


with tempfile.TemporaryDirectory(prefix="init-check-") as directory:
    root = Path(directory)

    def mapped(code):
        return re.sub(r"/(?:etc|proc|var|usr/local|root)/|/swapfile\b",
                      lambda match: directory + match[0], code)

    def write(name, content=""):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return target

    status = 'print_status() { printf "%s %s\\n" "$1" "$2"; };\n'
    detect = status + mapped(function("el.sh", "check_os")) + '\ncheck_os; echo "$OS_FAMILY"'
    cases = [
        ('ID=rhel\nVERSION_ID=10.0\nPLATFORM_ID=platform:el10', '13', 'el'),
        ('ID=rocky\nVERSION_ID=9.8', '13', 'el'),
        ('ID=almalinux\nVERSION_ID=8.10', '13', None),
        ('ID=ol\nVERSION_ID=10.0', '13', 'el'),
        ('ID=centos\nVERSION_ID=9', '13', 'el'),
        ('ID=custom\nID_LIKE="rhel fedora"\nVERSION_ID=1\nPLATFORM_ID=platform:el9', '13', 'el'),
        ('ID=debian\nVERSION_ID=12', '12.12', 'debian'),
        ('ID=debian\nVERSION_ID=13', '13.1', 'debian'),
        ('ID=debian\nVERSION_ID=11', '11.11', None),
        ('ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble', 'trixie/sid', 'debian'),
        ('ID=ubuntu\nVERSION_ID=26.04\nVERSION_CODENAME=resolute', 'trixie/sid', 'debian'),
        ('ID=ubuntu\nVERSION_ID=22.04\nVERSION_CODENAME=jammy', 'bookworm/sid', None),
        ('ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID=22\nUBUNTU_CODENAME=noble', 'trixie/sid', 'debian'),
        ('ID=fedora\nVERSION_ID=44', '13', None),
    ]
    for release, debian, family in cases:
        write("etc/os-release", release)
        write("etc/debian_version", debian)
        output = run(detect, expected=0 if family else 1)
        if family:
            assert output.rstrip().endswith(family), output
    for version, expected in [('3.23.4', 0), ('3.24.2', 0), ('3.22.5', 1), ('edge', 1)]:
        write("etc/os-release", f'ID=alpine\nVERSION_ID={version}\nPRETTY_NAME=Alpine')
        run(status + mapped(function("alpine.sh", "check_os")) + '\ncheck_os', expected=expected)

    mocks = mapped(r'''
print_status() { printf '%s %s\n' "$1" "$2"; }
sudo() { "$@"; }
install_packages() { printf 'install %s\n' "$*" >> "$TEST_ROOT/calls"; }
apk() { printf 'apk %s\n' "$*" >> "$TEST_ROOT/calls"; }
modprobe() { return 0; }
zramctl() { printf '%s' "${ACTIVE_ZRAM:-}"; }
systemctl() {
    printf 'systemctl %s\n' "$*" >> "$TEST_ROOT/calls"
    [ "$1" != cat ] || return 1
    [ "${FAIL_SERVICE:-}" != "$1" ] || return 1
    if [ "$*" = 'start dev-zram0.swap' ]; then
        printf '/dev/zram0 partition 65536 0 100\n' >> /proc/swaps
    fi
}
rc-update() { printf 'rc-update %s\n' "$*" >> "$TEST_ROOT/calls"; }
rc-service() {
    [ "${FAIL_SERVICE:-}" != "$1" ] || return 1
    if [ "$*" = 'zram-init start' ]; then
        printf '/dev/zram0 partition 65536 0 100\n' >> /proc/swaps
    fi
}
fallocate() { truncate -s "$2" "$3"; }
mkswap() { return 0; }
swapon() {
    [ "$1" != --show ] || return 0
    printf '%s file 65536 0 -2\n' "$1" >> /proc/swaps
}
swapoff() { return 1; }
crontab() { cp "$3" /etc/crontabs/root; }
''')
    write("proc/meminfo", "MemTotal: 8388608 kB\n")
    write("etc/fstab")
    for script in ("el.sh", "alpine.sh"):
        code = mocks + function(script, "check_result") + '\n'
        if script == "el.sh":
            code += function(script, "prompt_user") + '\n'
        code += mapped(function(script, "configure_swap")) + '\nconfigure_swap'
        env = dict(TEST_ROOT=directory, OS_FAMILY="el")
        write("proc/swaps", "Filename Type Size Used Priority\n")
        write("calls")
        run(code, "0\n", expected=77, **env)
        run(code, "1\n", expected=77, **env)  # EOF never starts work.
        run(code, "1\n0\nbad\n64\n", **env)
        assert (root / "swapfile").stat().st_size == 64 * 1024 * 1024
        assert (root / "etc/fstab").read_text().count(directory + "/swapfile ") == 1
        before = (root / "swapfile").stat().st_size
        run(code, "1\n128\ny\n", expected=1, **env)  # Failed swapoff preserves data.
        assert (root / "swapfile").stat().st_size == before
        write("etc/conf.d/zram-init", "num_devices=2\n")
        run(code, "2\n128\n", **env)  # A disk swap must not block adding zram.
        if script == "el.sh":
            config = (root / "etc/systemd/zram-generator.conf.d/80-init.conf").read_text()
            assert "zram-size = 128" in config and "swap-priority = 100" in config
        else:
            config = (root / "etc/conf.d/zram-init").read_text()
            assert "num_devices=1" in config and "size0=128" in config and "flag0=100" in config
        run(code, "2\n256\n", expected=77, ACTIVE_ZRAM="zram0", **env)
        (root / "swapfile").unlink()
        write("etc/fstab")

    aide = write("bin/aide", '#!/bin/sh\nprintf "aide %s\\n" "$*" >> "$TEST_ROOT/calls"\nprintf baseline > "$AIDE_NEW_DB"\n')
    aide.chmod(0o755)
    for family, suffix in (("el", ".gz"), ("debian", "")):
        baseline = write("var/lib/aide/aide.db" + suffix, "original trusted baseline")
        (root / "etc/systemd/system").mkdir(parents=True, exist_ok=True)
        code = mocks + function("el.sh", "check_result") + '\n' + mapped(function("el.sh", "configure_aide")) + '\nconfigure_aide'
        env = dict(TEST_ROOT=directory, OS_FAMILY=family,
                   PATH=str(aide.parent) + os.pathsep + os.environ["PATH"],
                   AIDE_NEW_DB=str(root / ("var/lib/aide/aide.db.new" + suffix)))
        write("calls")
        run(code, **env)
        assert baseline.read_text() == "original trusted baseline"
        assert "aide --config" not in (root / "calls").read_text()
        service = (root / "etc/systemd/system/init-aide-check.service").read_text()
        timer = (root / "etc/systemd/system/init-aide-check.timer").read_text()
        assert "--check" in service and "SuccessExitStatus" not in service
        assert "Persistent=true" in timer and "OnCalendar=" in timer
        baseline.unlink()
        run(code, **env)
        assert baseline.read_text() == "baseline"
        run(code, expected=1, FAIL_SERVICE="start", **env)

    write("etc/crontabs/root", '17 * * * * /unrelated-task\n')
    write("etc/periodic/daily/apk-auto-upgrade", 'old job\n')
    (root / "root").mkdir(exist_ok=True)
    code = mocks + function("alpine.sh", "check_result") + '\n' + mapped(function("alpine.sh", "setup_auto_updates")) + '\nsetup_auto_updates'
    run(code, "25:00\n04:05\n", TEST_ROOT=directory)
    run(code, "06:07\n", TEST_ROOT=directory)
    cron = (root / "etc/crontabs/root").read_text()
    assert '/unrelated-task' in cron and cron.count('# init-apk-upgrade') == 1
    assert '7 6 * * *' in cron
    assert not (root / "etc/periodic/daily/apk-auto-upgrade").exists()
    run(code, "\n", TEST_ROOT=directory, FAIL_SERVICE="crond", expected=1)

    write("etc/alpine-release", "3.24.2\n")
    write("etc/apk/repositories", '\n'.join([
        'https://dl-cdn.alpinelinux.org/alpine/v3.24/main',
        'https://dl-cdn.alpinelinux.org/alpine/v3.24/community # local comment',
        '@edge https://dl-cdn.alpinelinux.org/alpine/edge/testing',
        'https://dl-cdn.alpinelinux.org/alpine/v3.23/main',
    ]))
    apk = write("bin/apk", r'''#!/bin/sh
printf '%s\n' "$*" >> "$TEST_ROOT/apk-calls"
cp "$2" "$TEST_ROOT/selected-repositories"
case "$*" in *update) exit "${FAIL_UPDATE:-0}" ;; esac
''')
    apk.chmod(0o755)
    logger = write("bin/logger", '#!/bin/sh\nexit 0\n')
    logger.chmod(0o755)
    update = root / "usr/local/sbin/init-apk-upgrade"
    env = dict(TEST_ROOT=directory, PATH=str(apk.parent) + os.pathsep + os.environ["PATH"])
    run(str(update), **env)
    selected = (root / "selected-repositories").read_text()
    assert '/v3.24/main' in selected and '/v3.24/community' in selected
    assert 'edge' not in selected and '/v3.23/' not in selected
    write("apk-calls")
    run(str(update), expected=1, FAIL_UPDATE="1", **env)
    assert 'upgrade' not in (root / "apk-calls").read_text()
    write("etc/apk/repositories", 'https://dl-cdn.alpinelinux.org/alpine/edge/main\n')
    write("apk-calls")
    run(str(update), expected=1, **env)
    assert not (root / "apk-calls").read_text()

print("PASS: OS boundaries, Swap/zram, AIDE baseline/timer, Alpine update scope/schedule/failures")
