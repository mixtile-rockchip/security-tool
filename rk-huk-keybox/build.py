#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Build the ARM64 CA and signed TA using an external Rockchip SDK devkit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

DEFAULT_TA_UUID = "6bada6f2-74f7-49cc-8d0f-4195a3c62fb0"


def main():
    project = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-source", required=True, type=Path,
                        help="external rk_tee_user source root containing v2/")
    parser.add_argument("--cc", required=True, type=Path,
                        help="ARM64 target GCC executable, for example aarch64-linux-musl-gcc")
    parser.add_argument("--sysroot", required=True, type=Path,
                        help="target sysroot with libteec headers and library")
    parser.add_argument("--uuid", default=DEFAULT_TA_UUID,
                        help="TA UUID (default: fixed protocol UUID " + DEFAULT_TA_UUID + ")")
    parser.add_argument("--output", type=Path, default=project / "build",
                        help="build directory (default: this project's build/)")
    parser.add_argument("--python-deps", type=Path,
                        help="optional Python module path for Cryptodome and elftools")
    parser.add_argument("--ta-sign-key", type=Path,
                        help="external TA signing PEM; default: SDK devkit's native selection")
    args = parser.parse_args()
    sdk = args.sdk_source.resolve()
    cc = args.cc.resolve()
    sysroot = args.sysroot.resolve()
    try:
        uuid_text = args.uuid
        identity = uuid.UUID(uuid_text)
        if str(identity) != uuid_text or not identity.int:
            raise ValueError("noncanonical UUID")
    except (OSError, ValueError):
        parser.error("TA UUID must be a canonical nonzero lowercase UUID")
    if not cc.is_file() or not os.access(cc, os.X_OK) or not cc.name.endswith("gcc"):
        parser.error("--cc must name an executable GCC whose filename ends in gcc")
    if not sysroot.is_dir() or not (sdk / "v2/export-ta_arm64/mk/ta_dev_kit.mk").is_file():
        parser.error("missing target sysroot or SDK ARM64 TA devkit")
    signing_key = args.ta_sign_key.resolve() if args.ta_sign_key else None
    if signing_key and not signing_key.is_file():
        parser.error("--ta-sign-key must name an existing external PEM file")
    if args.output.is_symlink():
        parser.error("--output must not be a symlink")
    output = args.output.resolve()
    marker = output / ".rk-huk-keybox-build"
    if output.exists() and (not output.is_dir() or
                            (any(output.iterdir()) and not marker.is_file())):
        parser.error("--output must be empty or an existing build.py output directory")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.chmod(0o700)
    marker.write_text("rk-huk-keybox build output v1\n")
    work = output / "work"
    if work.is_symlink():
        parser.error("build work directory must not be a symlink")
    if work.exists():
        shutil.rmtree(work)
    source = work / "sdk" / "v2"
    ta = source / "ta" / "keybox_app"
    (source / "host/keybox_app").mkdir(parents=True)
    shutil.copytree(project / "ta", ta)
    shutil.copytree(sdk / "v2/export-ta_arm64", source / "export-ta_arm64")
    api = source / "ta/rk_public_api"
    api.mkdir()
    for name in ("rk_derive_key_api.c", "rk_derive_key_api.h"):
        shutil.copyfile(sdk / "v2/ta/rk_public_api" / name, api / name)
    shutil.copyfile(project / "ca/main.c", source / "host/keybox_app/main.c")
    fields = identity.fields
    definition = "{ 0x%08x, 0x%04x, 0x%04x, { %s } }" % (
        fields[0], fields[1], fields[2], ", ".join("0x%02x" % x for x in identity.bytes[8:]))
    header = (project / "include/ta_keybox.h.in").read_text()
    header = header.replace("@TA_KEYBOX_UUID@", definition)
    header = header.replace("@NAOS_UUID_BYTES@", ", ".join("0x%02x" % x for x in identity.bytes))
    (ta / "include").mkdir(exist_ok=True)
    (ta / "include/ta_keybox.h").write_text(header)
    env = dict(os.environ, PATH=str(cc.parent) + os.pathsep + os.environ.get("PATH", ""))
    if args.python_deps:
        env["PYTHONPATH"] = str(args.python_deps.resolve()) + os.pathsep + env.get("PYTHONPATH", "")

    def run(command, logfile):
        result = subprocess.run([str(x) for x in command], env=env,
                                capture_output=True, text=True)
        (output / logfile).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("build failed; see " + str(output / logfile))

    run([cc, "--sysroot=" + str(sysroot), "-O2", "-Wall", "-Wextra", "-Werror",
         "-I" + str(sysroot / "usr/include"),
         "-I" + str(source / "export-ta_arm64/host_include"), "-I" + str(ta / "include"),
         source / "host/keybox_app/main.c", "-L" + str(sysroot / "usr/lib"),
         "-lteec", "-lpthread", "-o", output / "keybox_app"], "ca-build.log")
    libgcc = subprocess.check_output([str(cc), "--sysroot=" + str(sysroot),
                                    "-print-libgcc-file-name"], env=env, text=True).strip()
    prefix = cc.name[:-3]
    command = ["make", "-C", ta, "O=" + str(work / "ta-build"),
               "BINARY=" + str(identity),
               "TA_DEV_KIT_DIR=" + str(source / "export-ta_arm64"),
               "CROSS_COMPILE=" + prefix, "CROSS_COMPILE64=" + prefix,
               "CROSS_COMPILE_ta_arm64=" + prefix, "HOSTCC=gcc", "PYTHON3=" + sys.executable,
               "libgccta_arm64=" + libgcc, "CFLAGS=", "CPPFLAGS=", "LDFLAGS="]
    if signing_key:
        # SDK link.mk defines TA_SIGN_KEY without 'override'; GNU make's
        # command-line assignment preserves the caller's signing-key choice.
        command.append("TA_SIGN_KEY=" + str(signing_key))
    run(command, "ta-build.log")
    signed_ta = output / (str(identity) + ".ta")
    shutil.copyfile(work / "ta-build" / signed_ta.name, signed_ta)
    (output / "ta.uuid").write_text(str(identity) + "\n")
    artifacts = [output / "keybox_app", signed_ta]
    report = {
        "uuid": str(identity), "system_key_read": False,
        "ta_signing": "external-key" if signing_key else "sdk-default",
        "artifacts": {x.name: {"bytes": x.stat().st_size,
                               "sha256": hashlib.sha256(x.read_bytes()).hexdigest()}
                      for x in artifacts},
    }
    (output / "build-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
