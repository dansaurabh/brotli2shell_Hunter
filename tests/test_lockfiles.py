import json

from b2s_hunter.layers.lockfiles import layer_lockfiles
from b2s_hunter.model import CLEAN, PATCHED, REVIEW, VULNERABLE


def run(tmp_path):
    f = []
    layer_lockfiles([str(tmp_path)], f)
    return f


def by(f, comp):
    return [x for x in f if x.component == comp]


def test_package_lock_v3_transitive(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "1"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"a": "1"}},
        "node_modules/a": {"version": "1.0.0"},
        "node_modules/a/node_modules/brotli-wasm": {"version": "2.0.0"}}}))
    r = by(run(tmp_path), "brotli-wasm")
    assert r and r[0].layer == "lockfile" and "transitive" in r[0].note
    assert r[0].purl == "pkg:npm/brotli-wasm@2.0.0"


def test_package_lock_v1(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"dependencies": {
        "x": {"version": "1", "dependencies": {"brotli": {"version": "1.3.2"}}}}}))
    r = by(run(tmp_path), "brotli")
    assert r and "transitive" in r[0].note


def test_yarn_lock(tmp_path):
    (tmp_path / "yarn.lock").write_text('# yarn lockfile v1\n\nbrotli@^1.3.0:\n  version "1.3.2"\n  resolved "x"\n')
    assert by(run(tmp_path), "brotli")[0].version == "1.3.2"


def test_pnpm_lock(tmp_path):
    (tmp_path / "pnpm-lock.yaml").write_text("packages:\n\n  /brotli-wasm@2.0.1:\n    resolution: {}\n")
    assert by(run(tmp_path), "brotli-wasm")[0].version == "2.0.1"


def test_requirements_pin_and_extra(tmp_path):
    (tmp_path / "requirements-dev.txt").write_text(
        "Brotli==1.2.0\nbrotlicffi==1.2.1.0\nurllib3[brotli]==2.2.0\nbrotli>=1.0\n")
    f = run(tmp_path)
    assert {x.verdict for x in f if x.component == "brotli"} == {VULNERABLE, REVIEW}
    assert by(f, "brotlicffi")[0].verdict == PATCHED
    ex = by(f, "urllib3[brotli]")[0]
    assert ex.verdict == REVIEW and "auto-enabled" in ex.note


def test_poetry_and_pipfile(tmp_path):
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "Brotli"\nversion = "1.2.1"\n')
    (tmp_path / "Pipfile.lock").write_text(json.dumps({"default": {"brotlicffi": {"version": "==1.1.0.0"}}}))
    f = run(tmp_path)
    assert by(f, "brotli")[0].verdict == PATCHED
    assert by(f, "brotlicffi")[0].verdict == VULNERABLE


def test_go_mod_indirect(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module x\n\nrequire (\n\tgithub.com/andybalholm/brotli v1.1.0 // indirect\n)\n")
    (tmp_path / "go.sum").write_text("github.com/andybalholm/brotli v1.1.0 h1:x\n")
    r = by(run(tmp_path), "github.com/andybalholm/brotli")
    assert len(r) == 1 and "transitive" in r[0].note and r[0].verdict == REVIEW


def test_cargo_and_gem(tmp_path):
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "brotli-decompressor"\nversion = "4.0.1"\n')
    (tmp_path / "Gemfile.lock").write_text("GEM\n  specs:\n    brotli (0.9.0)\n")
    f = run(tmp_path)
    assert by(f, "brotli-decompressor")[0].verdict == CLEAN
    assert by(f, "brotli")[0].verdict == VULNERABLE


def test_nuget(tmp_path):
    (tmp_path / "packages.lock.json").write_text(json.dumps({"dependencies": {"net8.0": {
        "Microsoft.NETCore.App.Runtime.linux-x64": {"type": "Transitive", "resolved": "8.0.10"}}}}))
    (tmp_path / "a.csproj").write_text(
        '<Project><ItemGroup><PackageReference Include="Brotli.Net" Version="[1.0,2.0)" />'
        '</ItemGroup></Project>')
    f = run(tmp_path)
    assert by(f, "Microsoft.NETCore.App.Runtime.linux-x64")[0].verdict == VULNERABLE
    assert by(f, "Brotli.Net")[0].verdict == REVIEW


def test_dockerfile_and_nvmrc(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM --platform=linux/amd64 node:20.11.0-alpine AS b\nFROM python:3.12\n")
    (tmp_path / ".nvmrc").write_text("22.23.4\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / ".node-version").write_text("lts/*\n")
    f = run(tmp_path)
    node = [x for x in f if x.component == "Node.js"]
    assert {x.verdict for x in node} == {VULNERABLE, PATCHED, REVIEW}
    assert any(x.component == "python base image" for x in f)


def test_skips_node_modules_and_engines(tmp_path):
    nm = tmp_path / "node_modules" / "p"
    nm.mkdir(parents=True)
    (nm / "yarn.lock").write_text('brotli@1:\n  version "1.0.0"\n')
    (tmp_path / "package.json").write_text(json.dumps({"engines": {"node": ">=20"}}))
    f = run(tmp_path)
    assert not by(f, "brotli")
    assert f[0].verdict == REVIEW and "range" in f[0].evidence
