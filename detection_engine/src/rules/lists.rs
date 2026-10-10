//! Every name and path the rules match on, in one place, so tuning a list never
//! touches rule logic. The lists follow "SecRisk Detection Rules"; where the
//! correlation-engine plan left an open question, the choice made here is
//! marked **Decision**.

use crate::mitre::Tactic;

/// Package managers and build tools: a process answering to one of these is a
/// dependency anchor.
pub const DEPENDENCY_TOOLS: &[&str] = &[
    "npm", "npx", "yarn", "pnpm", "pip", "pip3", "pipx", "poetry", "cargo", "gem", "bundle",
    "composer", "go", "make", "mvn", "gradle",
];

/// A chain with one of these anywhere above the acting process is a *build*
/// chain (L5–L8). **Decision:** configure, dpkg-buildpackage and rpmbuild set
/// this flag but are not anchors.
pub const BUILD_TOOLS: &[&str] = &[
    "make",
    "configure",
    "dpkg-buildpackage",
    "rpmbuild",
    "mvn",
    "gradle",
    "cargo",
    "go",
];

/// C4: a script under one of these is an installed dependency.
pub const DEPENDENCY_DIRS: &[&str] = &["/node_modules/", "/site-packages/", "/dist-packages/"];

/// Programs whose first non-flag argument is the script that names them.
pub const INTERPRETERS: &[&str] = &[
    "node", "nodejs", "python", "python3", "python2", "ruby", "perl", "php", "bun", "deno",
];

pub const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "fish"];

/// P2.
pub const DOWNLOADERS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat", "socat"];

/// P3, F2.
pub const STAGING_DIRS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/"];

/// L3: a shell decoding or piping into itself.
pub const DECODE_AND_RUN: &[&str] = &[
    "base64 -d",
    "base64 --decode",
    "| sh",
    "|sh",
    "| bash",
    "|bash",
];

/// L5.
pub const DECOMPRESSORS: &[&str] = &["xz", "unxz", "xzcat", "lzma", "unlzma"];

/// L6: what may legitimately write an object file. **Decision:** the rule
/// doc's list plus the drivers, back ends and linkers a real build runs.
pub const COMPILERS: &[&str] = &[
    "cc", "gcc", "g++", "c++", "clang", "clang++", "cc1", "cc1plus", "collect2", "ld", "ld.bfd",
    "ld.gold", "ld.lld", "lld", "mold", "as", "ar", "ranlib", "rustc", "go",
];
/// Versioned and cross-compiler spellings: gcc-13, clang-18, x86_64-linux-gnu-gcc.
pub const COMPILER_PREFIXES: &[&str] = &[
    "gcc-",
    "g++-",
    "clang-",
    "clang++-",
    "x86_64-linux-gnu-",
    "aarch64-linux-gnu-",
];
/// Go's compiler and linker live under `$GOROOT/pkg/tool/` with generic names.
pub const GO_TOOL_DIR: &str = "/pkg/tool/";

pub const OBJECT_SUFFIXES: &[&str] = &[".o", ".so", ".a"];

/// L7.
pub const SYSTEM_BIN_DIRS: &[&str] = &[
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
];

/// L8.
pub const ENV_DUMPERS: &[&str] = &["env", "printenv"];

/// L9.
pub const CONTAINER_TOOLS: &[&str] = &["docker", "kubectl", "crictl", "ctr", "nsenter"];

/// L10: file, technique, tactic.
pub const SYSTEM_FILES: &[(&str, &str, Option<Tactic>)] = &[
    ("/etc/passwd", "T1136.001", Some(Tactic::Persistence)),
    ("/etc/shadow", "T1136.001", Some(Tactic::Persistence)),
    (
        "/etc/sudoers",
        "T1548.003",
        Some(Tactic::PrivilegeEscalation),
    ),
    ("/etc/resolv.conf", "heuristic", None),
    ("/etc/hosts", "heuristic", None),
];

/// L11.
pub const PACKAGE_CACHES: &[&str] = &[
    "/.npm/_cacache/",
    "/.cache/pip/",
    "/.m2/repository/",
    "/.cargo/registry/",
    "/.gradle/caches/",
];
/// JVM build daemons that own their caches but run as plain `java`.
pub const CACHE_OWNER_MARKERS: &[&str] = &["org.gradle.", "plexus.classworlds"];

/// N3.
pub const SAFE_PORTS: &[u16] = &[22, 53, 80, 443];

/// F1: what each watched secret is, who normally reads it, and how it maps.
pub struct Secret {
    pub suffixes: &'static [&'static str],
    pub readers: &'static [&'static str],
    pub reader_prefixes: &'static [&'static str],
    pub technique: &'static str,
    /// **Decision:** counted only inside a package or build chain. An app
    /// reading its own .env is normal; a dependency reading it is not.
    pub dependency_only: bool,
}

/// First match wins, so `.git-credentials` sits before `credentials`.
pub const SECRETS: &[Secret] = &[
    Secret {
        suffixes: &["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"],
        readers: &[
            "ssh",
            "ssh-add",
            "ssh-agent",
            "ssh-keygen",
            "scp",
            "sftp",
            "git",
        ],
        reader_prefixes: &[],
        technique: "T1552.004",
        dependency_only: false,
    },
    Secret {
        suffixes: &[".pem"],
        readers: &[],
        reader_prefixes: &[],
        technique: "T1552.004",
        dependency_only: false,
    },
    Secret {
        suffixes: &[".npmrc"],
        readers: &["npm", "node"],
        reader_prefixes: &[],
        technique: "T1552.001",
        dependency_only: false,
    },
    Secret {
        suffixes: &[".pypirc"],
        readers: &["pip", "twine"],
        reader_prefixes: &[],
        technique: "T1552.001",
        dependency_only: false,
    },
    Secret {
        suffixes: &[".git-credentials"],
        readers: &["git"],
        reader_prefixes: &["git-credential-"],
        technique: "T1552.001",
        dependency_only: false,
    },
    Secret {
        suffixes: &["credentials"],
        readers: &["aws", "gcloud"],
        reader_prefixes: &[],
        technique: "T1552.001",
        dependency_only: false,
    },
    Secret {
        suffixes: &[".kube/config"],
        readers: &["kubectl", "helm"],
        reader_prefixes: &[],
        technique: "T1552.001",
        dependency_only: false,
    },
    Secret {
        suffixes: &[".netrc"],
        readers: &["git", "ftp"],
        reader_prefixes: &[],
        technique: "T1552.001",
        dependency_only: false,
    },
    Secret {
        suffixes: &[".env", "credentials.txt"],
        readers: &[],
        reader_prefixes: &[],
        technique: "T1552.001",
        dependency_only: true,
    },
];

/// Public certificate stores. The sensor's `.pem` suffix matches CA bundles
/// here that every TLS client reads; they are not secrets.
pub const PUBLIC_CERT_DIRS: &[&str] = &[
    "/etc/ssl/",
    "/etc/pki/",
    "/etc/ca-certificates/",
    "/usr/share/ca-certificates/",
    "/usr/lib/ssl/",
];
