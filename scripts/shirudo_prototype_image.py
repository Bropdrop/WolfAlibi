#!/usr/bin/env python3
"""Build explicit, separate immutable-image inputs for the pinned Shirudo LAB.

This operator-side build writes only a new output directory. It does not alter
upstream tracked files, boot a VM, mount a device, or publish an artifact.
Run as root in the disposable integration builder so every packaged inode has
its final root ownership. Python and generic tools never enter Shirudo's
authority-bearing runtime image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from shirudo_adapter.bootstrap import (ENTRYPOINT, MAX_ANCHOR_BYTES, MOUNT_POINT,
                                      validate_anchors, validate_image_manifest)
from shirudo_adapter.model import (AdapterError, UPSTREAM_COMMIT, canonical_json,
                                  digest, read_bounded_file, strict_json)

INITRD_MODULES = "base systemd systemd-initrd dracut-systemd rootfs-block fs-lib udev-rules terminfo shirudo wolfalibi"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value, mode=0o644):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("xb") as stream:
        stream.write(canonical_json(value) + b"\n")
    Path(path).chmod(mode)


class Builder:
    def __init__(self, args):
        self.upstream = Path(args.upstream).resolve(strict=True)
        self.original_bundle = Path(args.bundle).resolve(strict=True)
        self.repo = Path(args.repo).resolve(strict=True)
        self.python = Path(args.python).absolute()
        self.output = Path(args.output).absolute()
        require(not self.output.exists() and not self.output.is_symlink(), "output must be a new directory")
        require(os.geteuid() == 0, "image build needs root ownership in a disposable builder")
        self.anchors = validate_anchors(strict_json(read_bounded_file(args.anchors, MAX_ANCHOR_BYTES), MAX_ANCHOR_BYTES))
        self.output.mkdir(mode=0o755, parents=False)
        self.output.chmod(0o755)
        self.public = self.output / "public"
        self.private = self.output / "private"
        self.work = self.output / "work"
        self.root = self.work / "gate-root"
        for directory in (self.public, self.work, self.root):
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
        self.private.mkdir(mode=0o700)
        self.logs = self.output / "build-commands.jsonl"
        self.bundle = self.output / "bundle"
        self.helper = self.upstream / "tools/shirudo-build/shirudo-build"
        self.operator = self.upstream / "shirudo"

    def run(self, command, *, cwd=None, timeout=180, allow_failure=False, input=None, env=None):
        command = [str(item) for item in command]
        result = subprocess.run(command, cwd=cwd, input=input, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False, env=env)
        require(len(result.stdout) <= 8 * 1024 * 1024 and len(result.stderr) <= 8 * 1024 * 1024,
                "build command exceeded output limit")
        with self.logs.open("ab") as stream:
            stream.write(canonical_json({"argv": command, "cwd": str(cwd) if cwd else None,
                         "returncode": result.returncode, "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                         "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}) + b"\n")
        if result.returncode and not allow_failure:
            raise RuntimeError(f"build command failed ({result.returncode}): {command[0]} {command[1:3]}; "
                               + result.stderr[-4096:].decode("utf-8", "replace"))
        return result

    def check_source(self):
        revision = self.run(["git", "-c", f"safe.directory={self.upstream}", "-C", self.upstream, "rev-parse", "HEAD"]).stdout.decode().strip()
        require(revision == UPSTREAM_COMMIT, "upstream source revision does not match the supported pin")
        dirty = self.run(["git", "-c", f"safe.directory={self.upstream}", "-C", self.upstream,
                          "status", "--porcelain", "--untracked-files=no"]).stdout
        require(not dirty, "upstream tracked source must be clean")
        for path in (self.operator, self.helper, self.original_bundle / "verity/config-boot-keys.img",
                     self.original_bundle / "root/usr/local/bin/shirudo"):
            require(path.is_file(), f"required built input is missing: {path}")
        self.run(["sha256sum", "--check", "manifest"], cwd=self.original_bundle / "verity")
        for command in ("veritysetup", "mkfs.ext4", "debugfs", "readelf", "ldd", "llvm-strip", "dracut", "chroot"):
            require(shutil.which(command) is not None, f"required build program is unavailable: {command}")
        shutil.copytree(self.original_bundle, self.bundle, symlinks=True)
        for path in [self.bundle, *self.bundle.rglob("*")]:
            if path.is_symlink():
                continue
            if path.is_dir():
                path.chmod(0o755)
            elif path.is_file():
                path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)

    def python_info(self):
        script = r'''
import importlib.metadata, importlib.util, json, os, sys, sysconfig
packages={}
for name in ('cryptography','cffi','pycparser','_cffi_backend'):
    spec=importlib.util.find_spec(name)
    if spec is None: raise RuntimeError('missing dependency '+name)
    packages[name]=list(spec.submodule_search_locations)[0] if spec.submodule_search_locations else spec.origin
distributions={}
for name in ('cryptography','cffi','pycparser'):
    dist=importlib.metadata.distribution(name)
    distributions[name]={'version':dist.version,'metadata':str(dist._path)}
print(json.dumps({'executable':os.path.realpath(sys.executable), 'version':sys.version.split()[0],
 'major_minor':str(sys.version_info.major)+'.'+str(sys.version_info.minor),
 'stdlib':sysconfig.get_path('stdlib'),'platstdlib':sysconfig.get_path('platstdlib'),
 'packages':packages,'distributions':distributions}))
'''
        result = self.run([self.python, "-I", "-c", script])
        info = json.loads(result.stdout)
        require(info["distributions"]["cryptography"]["version"] == "50.0.0", "the image requires cryptography 50.0.0")
        require(re.fullmatch(r"3\.(1[1-9]|[2-9][0-9])", info["major_minor"]) is not None, "unsupported Python version")
        return info

    def copy_file(self, source, target):
        source = Path(source).resolve(strict=True)
        require(source.is_file(), f"not a regular build input: {source}")
        target = Path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            require(sha(source) == sha(target), f"conflicting dependency at {target}")
        else:
            shutil.copyfile(source, target)

    def package_python(self):
        info = self.python_info()
        self.python_metadata = info
        stdlib_target = self.root / f"usr/lib/python{info['major_minor']}"
        excluded = {"site-packages", "dist-packages", "__pycache__", "test", "tests", "idlelib", "tkinter", "ensurepip"}
        def ignore(_directory, names):
            return [name for name in names if name in excluded or name.endswith((".pyc", ".pyo"))]
        shutil.copytree(info["stdlib"], stdlib_target, symlinks=False, ignore=ignore)
        for additional in {info["platstdlib"]} - {info["stdlib"]}:
            native = Path(additional) / "lib-dynload"
            if native.is_dir():
                shutil.copytree(native, stdlib_target / "lib-dynload", dirs_exist_ok=True, symlinks=False, ignore=ignore)
        self.copy_file(info["executable"], self.root / "usr/bin/python3")
        (self.root / "usr/bin/python3").chmod(0o755)
        packages = stdlib_target / "site-packages"
        packages.mkdir()
        for name, source in info["packages"].items():
            source = Path(source)
            if source.is_dir():
                shutil.copytree(source, packages / name, symlinks=False, ignore=ignore)
            else:
                self.copy_file(source, packages / source.name)
        for name, item in info["distributions"].items():
            source = Path(item["metadata"])
            shutil.copytree(source, packages / source.name, symlinks=False)
            extra = source.parent / (name + ".libs")
            if extra.is_dir():
                shutil.copytree(extra, packages / extra.name, symlinks=False)
        self.resolve_elf_dependencies()
        return info

    def resolve_elf_dependencies(self):
        """Resolve every packaged extension too, not only the Python executable.

        ldd is used only on trusted interpreter/package/build inputs, matching
        upstream's image generator. Resolved libraries retain absolute paths.
        """
        examined = set()
        while True:
            pending = []
            for path in self.root.rglob("*"):
                if path.is_file() and path not in examined:
                    with path.open("rb") as stream:
                        if stream.read(4) == b"\x7fELF":
                            pending.append(path)
                    examined.add(path)
            if not pending:
                break
            for path in pending:
                result = self.run(["ldd", path], allow_failure=True)
                output = (result.stdout + result.stderr).decode("utf-8", "replace")
                require("not found" not in output, f"unresolved ELF dependency: {path}")
                require(result.returncode == 0 or "statically linked" in output
                        or "not a dynamic executable" in output, f"cannot inspect ELF dependencies: {path}")
                libraries = set()
                for line in output.splitlines():
                    match = re.search(r"=>\s+(/[^\s]+)", line) or re.match(r"\s*(/[^\s]+)", line)
                    if match:
                        libraries.add(match.group(1))
                program_headers = self.run(["readelf", "-l", path]).stdout.decode("utf-8", "replace")
                interpreter = re.search(r"Requesting program interpreter: (/[^\]]+)\]", program_headers)
                if interpreter:
                    libraries.add(interpreter.group(1))
                for library in libraries:
                    # $ORIGIN resolutions may already point into the staged
                    # tree. They are already present at the same chroot path.
                    source = Path(library)
                    if source.is_relative_to(self.root):
                        continue
                    self.copy_file(source, self.root / str(source).lstrip("/"))
                    # setup-python's interpreter has $ORIGIN/../lib RUNPATH.
                    # After relocation to /usr/bin it must find libpython and
                    # any equivalent dependencies in /usr/lib, without a host
                    # ld.so.cache or mutable LD_LIBRARY_PATH.
                    self.copy_file(source, self.root / "usr/lib" / source.name)

    def package_gate(self, python_info):
        package = self.root / "opt/wolfalibi/shirudo_adapter"
        package.mkdir(parents=True)
        names = sorted((self.repo / "shirudo_adapter").glob("*.py"))
        require(any(path.name == "bootstrap.py" for path in names), "bootstrap module is missing")
        for source in names:
            self.copy_file(source, package / source.name)
        version = python_info["major_minor"]
        entry = ("import sys\n"
                 f"sys.path[:] = ['/opt/wolfalibi', '/usr/lib/python{version}', "
                 f"'/usr/lib/python{version}/lib-dynload', '/usr/lib/python{version}/site-packages']\n"
                 "from shirudo_adapter.bootstrap import main\nraise SystemExit(main())\n")
        (self.root / "opt/wolfalibi/gate_entry.py").write_text(entry)
        write_json(self.root / "etc/wolfalibi/anchors.json", self.anchors)
        for directory in ("state", "socket", "run/wolfalibi"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        for name in ("config-manifest.json", "image-boot.json"):
            (self.root / "run/wolfalibi" / name).touch()
        # Immutable mode/ownership is an input to the ext4 image, rather than
        # depending on the builder's umask or the source package's ownership.
        for path in [self.root, *self.root.rglob("*")]:
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "image source contains an unsupported inode")
            os.chown(path, 0, 0, follow_symlinks=False)
            executable = path.is_dir()
            if path.is_file():
                with path.open("rb") as stream:
                    executable = stream.read(4) == b"\x7fELF"
            # PT_INTERP is opened for execution by the kernel as well.
            path.chmod(0o755 if executable else 0o644)
        files = {}
        for path in sorted(self.root.rglob("*")):
            if path.is_file():
                files["/" + path.relative_to(self.root).as_posix()] = {
                    "sha256": sha(path), "bytes": path.stat().st_size,
                    "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}"}
        source_manifest = {"schema": "wolfalibi.shirudo.image-source.v1",
                           "upstream_commit": UPSTREAM_COMMIT,
                           "adapter_commit": self.run(["git", "-c", f"safe.directory={self.repo}", "-C", self.repo,
                                                       "rev-parse", "HEAD"]).stdout.decode().strip(),
                           "python_version": python_info["version"],
                           "dependencies": {name: item["version"] for name, item in python_info["distributions"].items()},
                           "files": files,
                           "self_exclusion": "/etc/wolfalibi/image-files.json"}
        write_json(self.public / "image-source-manifest.json", source_manifest)
        write_json(self.root / "etc/wolfalibi/image-files.json", source_manifest)
        self.source_manifest = source_manifest
        probe = (f"import sys; sys.path[:] = ['/opt/wolfalibi', '/usr/lib/python{version}', "
                 f"'/usr/lib/python{version}/lib-dynload', '/usr/lib/python{version}/site-packages']; "
                 "import json, sqlite3, _ctypes, _ssl, _hashlib, cryptography; "
                 "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; "
                 "from shirudo_adapter.bootstrap import validate_anchors; "
                 "key=Ed25519PrivateKey.generate(); key.public_key().verify(key.sign(b'probe'),b'probe'); "
                 "sqlite3.connect(':memory:').execute('SELECT 1'); "
                 "print(json.dumps({'python':sys.version.split()[0],'cryptography':cryptography.__version__,'imports':'PASS'}))")
        result = self.run(["chroot", self.root, "/usr/bin/python3", "-I", "-B", "-S", "-c", probe],
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        write_json(self.public / "staged-runtime-probe.json", json.loads(result.stdout))

    def build_gate_image(self):
        apparent = sum(path.stat().st_size for path in self.root.rglob("*") if path.is_file())
        mib = max(64, ((apparent * 13 // 10 + 32 * 1024 ** 2) + 1024 ** 2 - 1) // 1024 ** 2)
        filesystem = self.work / "gate-filesystem.img"
        with filesystem.open("xb") as stream:
            stream.truncate(mib * 1024 ** 2)
        self.run(["mkfs.ext4", "-q", "-F", "-b", "4096", "-O", "^has_journal", "-E", "root_owner=0:0",
                  "-d", self.root, filesystem])
        self.config_keys = self.private / "config-key"
        self.run([self.operator, "genkey", "--keys-dir", self.config_keys])
        prefix = self.public / "gate"
        self.run([self.upstream / "tools/gen-image/shirudo-gen-verity", "--builder", self.helper,
                  filesystem, "--output", prefix, "--kind", "runtime", "--keys-dir", self.config_keys])
        self.gate_root = (self.public / "gate.roothash").read_text()
        require(HEX64.fullmatch(self.gate_root) is not None, "invalid generated gate root")
        self.run(["veritysetup", "verify", self.public / "gate.img", self.public / "gate.verity", self.gate_root])
        block_output = self.run(["debugfs", "-R", "blocks /opt/wolfalibi/shirudo_adapter/action_gate.py", self.public / "gate.img"]).stdout
        blocks = block_output.decode().split()
        require(blocks and all(block.isdecimal() for block in blocks), "cannot locate gate-code data block")
        self.corrupt_block = int(blocks[0])
        corrupt = self.public / "gate-corrupt.img"
        shutil.copyfile(self.public / "gate.img", corrupt)
        with corrupt.open("r+b") as stream:
            stream.seek(self.corrupt_block * 4096)
            old = stream.read(1)
            require(len(old) == 1, "gate corruption offset is out of bounds")
            stream.seek(-1, os.SEEK_CUR)
            stream.write(bytes([old[0] ^ 1]))
        rejected = self.run(["veritysetup", "verify", corrupt, self.public / "gate.verity", self.gate_root], allow_failure=True)
        require(rejected.returncode != 0, "altered gate code verified under the approved root")
        self.wrong_root = ("1" if self.gate_root[0] == "0" else "0") + self.gate_root[1:]
        wrong = self.run(["veritysetup", "verify", self.public / "gate.img", self.public / "gate.verity", self.wrong_root], allow_failure=True)
        require(wrong.returncode != 0, "wrong expected root was accepted")
        write_json(self.public / "offline-image-controls.json", {
            "schema": "wolfalibi.shirudo.image-controls.v1", "scope": "OPERATOR_OFFLINE_VERITY_VERIFICATION",
            "approved_root": self.gate_root, "good_exit_code": 0,
            "corrupt_file": "/opt/wolfalibi/shirudo_adapter/action_gate.py", "corrupt_block": self.corrupt_block,
            "corrupt_exit_code": rejected.returncode, "wrong_expected_root": self.wrong_root,
            "wrong_root_exit_code": wrong.returncode, "kernel_runtime_controls": "REQUIRED_AT_BOOT"})
        self.manifest = validate_image_manifest({"schema": "wolfalibi.shirudo.gate-image.v1",
            "gate_image_root": self.gate_root, "anchors_sha256": digest(self.anchors),
            "source_manifest_sha256": digest(self.source_manifest), "entrypoint": ENTRYPOINT,
            "mount_point": MOUNT_POINT, "authority": "NO_SHIRUDO_RUNTIME_AUTHORITY"})
        write_json(self.public / "gate-image.json", self.manifest)
        write_json(self.public / "anchors.json", self.anchors)

    def build_native_images(self):
        config_source = self.work / "config-root"
        config_source.mkdir()
        # Paths in debugfs commands are quoted and accepted only without the
        # characters that would change that command's tokenization.
        require(not any(char in str(config_source) for char in '\\"\n\r'), "unsupported build output path")
        self.run(["debugfs", "-R", f'rdump / "{config_source}"', self.original_bundle / "verity/config-boot-keys.img"])
        require((config_source / "etc/shirudo/shirudo.conf").is_file(), "original configuration could not be extracted")
        lost = config_source / "lost+found"
        if lost.exists():
            require(not any(lost.iterdir()), "unexpected nonempty original lost+found")
            lost.rmdir()
        write_json(config_source / "etc/wolfalibi/gate-image.json", self.manifest)
        config_source.chmod(0o755)
        (config_source / "etc/wolfalibi").chmod(0o755)
        config_size = max(2, self.original_bundle.joinpath("verity/config-boot-keys.img").stat().st_size // 1024 ** 2 + 1)
        config_prefix = self.work / "config-boot-keys"
        self.run([self.upstream / "tools/gen-image/shirudo-gen-image", "--source", config_source,
                  "--output", config_prefix, "--keys-dir", self.config_keys, "--kind", "config",
                  "--size", str(config_size), "--builder", self.helper])
        self.config_root = (self.work / "config-boot-keys.roothash").read_text()
        require(HEX64.fullmatch(self.config_root) is not None, "invalid generated configuration root")
        for suffix in (".img", ".verity", ".roothash", ".p7s"):
            shutil.copyfile(str(config_prefix) + suffix, self.bundle / ("verity/config-boot-keys" + suffix))
        runtime_conf = self.work / "runtime.conf"
        runtime_conf.write_text((self.upstream / "testing/vm/files/runtime.conf.in").read_text().replace("@config_image@", "config-boot-keys"))
        runtime_prefix = self.work / "runtime"
        runtime_unit = self.work / "runtime-service.conf"
        self.run([self.upstream / "tools/gen-image/shirudo-gen-runtime", "--binary", self.bundle / "root/usr/local/bin/shirudo",
                  "--bootstrap-conf", runtime_conf, "--cert", self.bundle / "fixtures/cert.der",
                  "--config-cert", self.config_keys / "cert.der", "--output", runtime_prefix,
                  "--keys-dir", self.config_keys, "--builder", self.helper, "--size", "64", "--unit-output", runtime_unit])
        for suffix in (".img", ".verity", ".roothash", ".p7s"):
            shutil.copyfile(str(runtime_prefix) + suffix, self.bundle / ("verity/runtime" + suffix))
        runtime_root = (self.work / "runtime.roothash").read_text()
        (self.bundle / "verity/runtime.root").write_text(runtime_root + "\n")
        shutil.copyfile(runtime_unit, self.bundle / "verity/runtime-service.conf")
        bootstrap = (self.upstream / "testing/vm/files/bootstrap.conf.in").read_text().replace("@root_hash@", runtime_root)
        (self.bundle / "verity/bootstrap.conf").write_text(bootstrap)
        commands = re.findall(r"^ExecStart=(.+) init$", runtime_unit.read_text(), re.MULTILINE)
        require(len(commands) == 1, "cannot determine generated runtime command")
        wrapper = (self.upstream / "testing/vm/files/shirudo-runtime.in").read_text().replace("@runtime_command@", commands[0])
        (self.bundle / "verity/shirudo-runtime").write_text(wrapper)
        (self.bundle / "verity/shirudo-runtime").chmod(0o755)
        shutil.copyfile(self.config_keys / "cert.der", self.public / "config-signing-certificate.der")
        self.runtime_root = runtime_root

    def prepare_dracut(self):
        base = self.output / "dracut-base"
        base.mkdir()
        (base / "modules.d").mkdir()
        original = Path(os.environ.get("dracutbasedir", "/usr/lib/dracut")).resolve(strict=True)
        require((original / "modules.d").is_dir(), "dracut base has no modules")
        for path in original.iterdir():
            if path.name != "modules.d":
                (base / path.name).symlink_to(path)
        for path in (original / "modules.d").iterdir():
            require(path.name != "91wolfalibi", "preexisting wolfalibi dracut module is ambiguous")
            (base / "modules.d" / path.name).symlink_to(path)
        module = base / "modules.d/91wolfalibi"
        module.mkdir()
        # Module input symlinks are host-side build references only. dracut
        # copies their bytes into the initrd; no image points back at the host.
        for name in ("gate.img", "gate.verity", "gate-corrupt.img", "gate-image.json", "anchors.json"):
            (module / name).symlink_to(self.public / name)
        shutil.copyfile(self.repo / "scripts/shirudo_prototype_boot.sh", module / "boot.sh")
        data_bytes = (self.public / "gate.img").stat().st_size
        config_bytes = (self.bundle / "verity/config-boot-keys.img").stat().st_size
        descriptor = {"schema": "wolfalibi.shirudo.boot-inputs.v1", "gate_image_root": self.gate_root,
                      "config_root": self.config_root, "runtime_root": self.runtime_root,
                      "anchors_sha256": digest(self.anchors), "data_bytes": data_bytes,
                      "config_bytes": config_bytes, "corrupt_block": self.corrupt_block,
                      "wrong_gate_root": self.wrong_root, "mount_point": MOUNT_POINT,
                      "config_witness_mount": "/run/wolfalibi/config-witness"}
        write_json(self.public / "boot-descriptor.json", descriptor)
        assignments = {"expected_gate_root": self.gate_root, "expected_config_root": self.config_root,
                       "expected_anchors_sha256": digest(self.anchors), "expected_data_bytes": data_bytes,
                       "expected_config_bytes": config_bytes, "corrupt_block": self.corrupt_block,
                       "wrong_gate_root": self.wrong_root}
        (module / "boot.conf").write_text("".join(f"{name}='{value}'\n" for name, value in assignments.items()))
        (module / "wolfalibi-image.service").write_text("""[Unit]
Description=WolfAlibi LAB immutable gate and configuration witness
DefaultDependencies=no
ConditionPathExists=/etc/initrd-release
Requires=shirudo-test-seed.service
After=initrd-root-fs.target shirudo-test-seed.service
Before=shirudo-initrd.service initrd-switch-root.target
RequiresMountsFor=/sysroot
[Service]
Type=oneshot
RemainAfterExit=yes
SyslogIdentifier=wolfalibi-image
StandardOutput=journal+console
StandardError=journal+console
ExecStart=/bin/sh /usr/lib/wolfalibi/prototype-boot.sh
[Install]
WantedBy=initrd.target
""")
        (module / "shirudo-requires-wolfalibi.conf").write_text("[Unit]\nRequires=wolfalibi-image.service\nAfter=wolfalibi-image.service\n")
        (module / "module-setup.sh").write_text("""#!/bin/bash
check() { return 0; }
depends() { echo 'systemd systemd-initrd'; }
installkernel() { hostonly='' instmods dm_mod dm_verity loop ext4; }
install() {
    inst_multiple veritysetup dmsetup mount umount blockdev dd cp chmod mkdir rm mv awk cmp stat grep || return 1
    inst_simple "$moddir/boot.sh" /usr/lib/wolfalibi/prototype-boot.sh || return 1
    inst_simple "$moddir/boot.conf" /etc/wolfalibi-boot.conf || return 1
    inst_simple "$(readlink -f "$moddir/gate-image.json")" /etc/wolfalibi-approved-gate-image.json || return 1
    inst_simple "$(readlink -f "$moddir/anchors.json")" /etc/wolfalibi-approved-anchors.json || return 1
    inst_simple "$(readlink -f "$moddir/gate.img")" /wolfalibi-images/gate.img || return 1
    inst_simple "$(readlink -f "$moddir/gate.verity")" /wolfalibi-images/gate.verity || return 1
    inst_simple "$(readlink -f "$moddir/gate-corrupt.img")" /wolfalibi-images/gate-corrupt.img || return 1
    inst_simple "$moddir/wolfalibi-image.service" "$systemdsystemunitdir/wolfalibi-image.service" || return 1
    inst_simple "$moddir/shirudo-requires-wolfalibi.conf" "$systemdsystemunitdir/shirudo-initrd.service.d/wolfalibi.conf" || return 1
    $SYSTEMCTL -q --root "$initdir" enable wolfalibi-image.service || return 1
}
""")
        (module / "module-setup.sh").chmod(0o755)
        for path in [base, base / "modules.d", module, *module.iterdir()]:
            if path.is_symlink():
                continue
            path.chmod(0o755 if path.is_dir() or path.name == "module-setup.sh" else 0o644)
        self.dracut_base = base
        # run.sh's cache key hashes every file below bundle/verity, but not
        # external dracut modules. Include the exact external bytes explicitly.
        inputs = {}
        for path in sorted(module.iterdir()):
            if path.is_file():
                inputs[path.name] = {"sha256": sha(path), "bytes": path.stat().st_size}
        write_json(self.bundle / "verity/wolfalibi-prototype-inputs.json", {
            "schema": "wolfalibi.shirudo.initrd-inputs.v1", "module": "wolfalibi",
            "modules": INITRD_MODULES, "inputs": inputs, "boot_descriptor": descriptor})
        # The upstream build also verifies this manifest before seeding files.
        files = sorted(path for path in (self.bundle / "verity").iterdir() if path.is_file() and path.name != "manifest")
        (self.bundle / "verity/manifest").write_text("".join(f"{sha(path)}  {path.name}\n" for path in files))
        self.run(["sha256sum", "--check", "manifest"], cwd=self.bundle / "verity")

    def finish(self):
        for path in [self.public, *self.public.rglob("*")]:
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() else 0o644)
        environment = {"TEST_VM_HOST_BUNDLE": str(self.bundle), "dracutbasedir": str(self.dracut_base),
                       "TEST_VM_INITRD_MODULES": INITRD_MODULES}
        result = {"schema": "wolfalibi.shirudo.prototype-image-build.v1", "output_dir": str(self.output),
                  "bundle": str(self.bundle), "dracutbasedir": str(self.dracut_base),
                  "test_vm_initrd_modules": INITRD_MODULES, "environment": environment,
                  "gate_image_root": self.gate_root, "config_root": self.config_root,
                  "runtime_root": self.runtime_root, "anchors_sha256": digest(self.anchors),
                  "gate_image_manifest": str(self.public / "gate-image.json"),
                  "source_manifest": str(self.public / "image-source-manifest.json"),
                  "boot_descriptor": str(self.public / "boot-descriptor.json"),
                  "image_files": {"data": str(self.public / "gate.img"), "hashes": str(self.public / "gate.verity"),
                                  "root_hash": str(self.public / "gate.roothash"), "corrupt_data": str(self.public / "gate-corrupt.img")},
                  "entrypoint": ENTRYPOINT, "mount_point": MOUNT_POINT,
                  "configuration_witness": "/run/wolfalibi/config-witness/etc/wolfalibi/gate-image.json",
                  "boot_report": "/run/wolfalibi/image-boot.json",
                  "kernel_runtime_controls": "REQUIRED_AT_BOOT", "upstream_tracked_changes": False}
        write_json(self.output / "build-result.json", result)
        self.run(["git", "-c", f"safe.directory={self.upstream}", "-C", self.upstream, "diff", "--exit-code"])
        return result

    def build(self):
        self.check_source()
        python = self.package_python()
        self.package_gate(python)
        self.build_gate_image()
        self.build_native_images()
        self.prepare_dracut()
        return self.finish()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=("build",))
    for flag in ("upstream", "bundle", "anchors", "output"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--repo", default=str(REPO))
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args(argv)
    try:
        result = Builder(args).build()
        print(json.dumps(result, sort_keys=True))
        return 0
    except (AdapterError, OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": "IMAGE_BUILD_FAILED", "message": str(exc)[:4096]}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
