use criterion::{Criterion, black_box, criterion_group, criterion_main};

use shakti::{
    check_authorization, command_matches, parse_policy, sanitize_environment, validate_command,
    validate_username,
};

fn sample_policy_str() -> &'static str {
    r#"
[defaults]
timestamp_ttl = 300
require_auth = true
audit_log = true
env_keep = ["EDITOR", "VISUAL"]
max_command_len = 4096

[[rules]]
user = "admin"
run_as = "root"
commands = []
require_auth = true

[[rules]]
group = "wheel"
run_as = "root"
commands = ["/usr/bin/systemctl", "/usr/bin/journalctl"]
require_auth = true

[[rules]]
user = "deploy"
run_as = "root"
commands = ["/usr/bin/systemctl restart *", "/usr/bin/docker"]
deny_commands = ["/usr/bin/systemctl stop firewall"]
require_auth = false

[[rules]]
user = "*"
run_as = "root"
commands = ["/usr/bin/passwd"]
require_auth = true
"#
}

fn bench_parse_policy(c: &mut Criterion) {
    let input = sample_policy_str();
    c.bench_function("parse_policy", |b| {
        b.iter(|| parse_policy(black_box(input)).unwrap());
    });
}

fn bench_check_authorization(c: &mut Criterion) {
    let policy = parse_policy(sample_policy_str()).unwrap();
    let groups = vec!["wheel".to_string()];

    c.bench_function("check_authorization_user_match", |b| {
        b.iter(|| {
            check_authorization(
                black_box(&policy),
                black_box("admin"),
                black_box(&[]),
                black_box("root"),
                black_box("/usr/bin/ls"),
            )
        });
    });

    c.bench_function("check_authorization_group_match", |b| {
        b.iter(|| {
            check_authorization(
                black_box(&policy),
                black_box("jdoe"),
                black_box(&groups),
                black_box("root"),
                black_box("/usr/bin/systemctl"),
            )
        });
    });

    c.bench_function("check_authorization_denied", |b| {
        b.iter(|| {
            check_authorization(
                black_box(&policy),
                black_box("unknown"),
                black_box(&[]),
                black_box("root"),
                black_box("/usr/bin/rm"),
            )
        });
    });
}

fn bench_command_matches(c: &mut Criterion) {
    c.bench_function("command_matches_exact", |b| {
        b.iter(|| command_matches(black_box("/usr/bin/ls"), black_box("/usr/bin/ls")));
    });

    c.bench_function("command_matches_glob", |b| {
        b.iter(|| command_matches(black_box("/usr/bin/ls"), black_box("/usr/bin/*")));
    });

    c.bench_function("command_matches_basename", |b| {
        b.iter(|| command_matches(black_box("/usr/bin/systemctl"), black_box("systemctl")));
    });
}

fn bench_validate_command(c: &mut Criterion) {
    let args = vec![
        "/usr/bin/systemctl".to_string(),
        "restart".to_string(),
        "nginx".to_string(),
    ];
    c.bench_function("validate_command", |b| {
        b.iter(|| validate_command(black_box(&args), black_box(4096)).unwrap());
    });
}

fn bench_sanitize_environment(c: &mut Criterion) {
    let policy = parse_policy(sample_policy_str()).unwrap();
    c.bench_function("sanitize_environment", |b| {
        b.iter(|| {
            sanitize_environment(
                black_box(&policy),
                black_box("alice"),
                black_box("root"),
                black_box("/root"),
                black_box("/bin/bash"),
            )
        });
    });
}

fn bench_validate_username(c: &mut Criterion) {
    c.bench_function("validate_username", |b| {
        b.iter(|| validate_username(black_box("alice_deploy_123")).unwrap());
    });
}

criterion_group!(
    benches,
    bench_parse_policy,
    bench_check_authorization,
    bench_command_matches,
    bench_validate_command,
    bench_sanitize_environment,
    bench_validate_username,
);
criterion_main!(benches);
