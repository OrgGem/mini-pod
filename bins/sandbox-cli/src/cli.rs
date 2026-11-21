//! CLI argument parsing, environment defaults, and `SandboxClient` command dispatch.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use sandbox_client::{ClientOutputKind, ControlEndpoint, SandboxClient};
use sandbox_core::{
    normalize_egress_domain, AccelerationPolicy, DestroyStatus, EgressRule, EnforcementLevel,
    ExecExitStatus, ExecRequest, ExecTarget, IsolationMode, NetworkPolicy, ResourceBudget,
    SandboxError, SandboxId, SandboxSpec,
};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use crate::compose::{execute_compose, ComposeAction};
use crate::doctor::execute_doctor;
use crate::image_build::{build_image_in_sandbox, ImageBuildSpec};
use crate::run::{execute_run, RunSpec};

pub const USAGE_TEXT: &str = "\
mini-pod sandbox command-line interface (routed via SandboxClient)

USAGE:
    sandbox-cli [GLOBAL_OPTIONS] <SUBCOMMAND> [OPTIONS]

GLOBAL OPTIONS:
    --endpoint <URI>    Local daemon endpoint (unix://... or npipe://...; env: MINIPOD_ENDPOINT)
    --json              Emit machine-readable JSON output
    -h, --help          Show this help text

SUBCOMMANDS:
    status
    doctor [--smoke [--accel <required|preferred|software>]]
    list
    tui [--refresh-ms <N>]
    spawn [OPTIONS]
        --isolation <vm|shared-kernel>
        --accel <required|preferred|software>
        --network <isolated|internet|allow:<domain>:<port>|unrestricted> (repeatable for allow:)
        --vcpus <N>
        --ram-mb <N>
        --rss-mb <N>
        --cpu-millicores <N>
        --disk-mb <N>
        --storage-mb <N>
        --ttl-secs <N>
    run [SPAWN_OPTIONS] [EXEC_OPTIONS] [--input <SRC_HOST> <DST_GUEST>] [--output <SRC_GUEST> <DST_HOST>] -- <ARGV...>
        SPAWN_OPTIONS are the options listed for spawn above.
        EXEC_OPTIONS are --cwd, --user, --env, --deadline-secs, --stdout-budget-bytes, and --stderr-budget-bytes.
    exec <SANDBOX_ID> [OPTIONS] -- <ARGV...>
        --container <NAME>
        --cwd <DIR>
        --user <USER>
        --env <K=V> (repeatable)
        --deadline-secs <N>
        --stdout-budget-bytes <N>
        --stderr-budget-bytes <N>
    renew <SANDBOX_ID> --ttl-secs <N>
    copy-in <SANDBOX_ID> <SRC_HOST> <DST_GUEST>
    copy-out <SANDBOX_ID> <SRC_GUEST> <DST_HOST>
    build <SANDBOX_ID> <CONTEXT_DIR> -t <IMAGE[:TAG]> [OPTIONS]
        -t, --tag <TAG>             Image name/tag (repeatable; required)
        -f, --file <DOCKERFILE>     Dockerfile path relative to CONTEXT_DIR
        --build-arg <K=V>           Build-time variable (repeatable)
        --target <STAGE>            Target build stage
        --no-cache                  Disable build layer cache
        -o, --output-tar <PATH>     Export built image to a host .tar archive
        --deadline-secs <N>         Build timeout in seconds (default: 300)
    compose <SANDBOX_ID> <up|ps|logs|down> [OPTIONS]
        -f, --file <COMPOSE_FILE>   Compose file path (default: compose.yaml / docker-compose.yml)
        -p, --project-name <NAME>   Override Compose project name
        --build                     Force rebuild of `build:` services (`up`)
        --deadline-secs <N>         Build/pull timeout in seconds (`up`, default: 300)
        --tail <N>                  Lines per container (`logs`, default: 100)
        -v, --volumes               Remove named project volumes (`down`)
    docker-endpoint <SANDBOX_ID> [--allow-reaper-socket]
    destroy <SANDBOX_ID>
";

const DEFAULT_EXEC_DEADLINE_SECS: u64 = 30;
const DEFAULT_EXEC_BUDGET_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCli {
    pub endpoint: ControlEndpoint,
    pub json: bool,
    pub command: CliCommand,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliOutcome {
    Help(&'static str),
    Run(ParsedCli),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliCommand {
    Status,
    Doctor { smoke: Option<SandboxSpec> },
    List,
    Tui {
        refresh_interval: Duration,
    },
    Spawn(SandboxSpec),
    Run(Box<RunSpec>),
    Exec {
        id: SandboxId,
        req: ExecRequest,
    },
    Renew {
        id: SandboxId,
        ttl: Duration,
    },
    CopyIn {
        id: SandboxId,
        src_host: PathBuf,
        dst_guest: String,
    },
    CopyOut {
        id: SandboxId,
        src_guest: String,
        dst_host: PathBuf,
    },
    Build {
        id: SandboxId,
        spec: Box<ImageBuildSpec>,
    },
    Compose {
        id: SandboxId,
        action: ComposeAction,
    },
    DockerEndpoint {
        id: SandboxId,
        allow_reaper_socket: bool,
    },
    Destroy {
        id: SandboxId,
    },
}

/// Parses process arguments using host environment variables.
pub fn parse_env_args() -> Result<CliOutcome, SandboxError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    parse_args_with(&args, |key| std::env::var(key).ok())
}

/// Pure argument parser taking explicit `args` and an environment lookup closure for tests.
pub fn parse_args_with<F>(args: &[String], get_env: F) -> Result<CliOutcome, SandboxError>
where
    F: Fn(&str) -> Option<String>,
{
    if args.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "missing subcommand (run with --help)".to_owned(),
        ));
    }

    let mut endpoint_raw: Option<String> = None;
    let mut json_output = false;
    let mut i = 0usize;

    while i < args.len() {
        let arg = args[i].as_str();
        if matches!(arg, "-h" | "--help" | "help") {
            return Ok(CliOutcome::Help(USAGE_TEXT));
        }
        let (flag, inline_val) = split_flag(arg);
        match flag {
            "--json" => {
                if inline_val.is_some() {
                    return Err(SandboxError::InvalidSpec(
                        "--json does not take a value".to_owned(),
                    ));
                }
                json_output = true;
                i += 1;
            }
            "--endpoint" => {
                endpoint_raw = Some(take_flag_value(args, &mut i, flag, inline_val)?);
                i += 1;
            }
            _ if arg.starts_with('-') => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown global option '{arg}' (run with --help)"
                )));
            }
            _ => break,
        }
    }

    let Some(subcmd) = args.get(i).map(String::as_str) else {
        return Err(SandboxError::InvalidSpec(
            "missing subcommand (run with --help)".to_owned(),
        ));
    };
    let rest = &args[i + 1..];

    let command = match subcmd {
        "status" => {
            parse_no_args_subcommand(rest, "status", &mut endpoint_raw, &mut json_output)?;
            match check_help_in_rest(rest) {
                true => return Ok(CliOutcome::Help(USAGE_TEXT)),
                false => CliCommand::Status,
            }
        }
        "doctor" => {
            if check_help_in_rest(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            CliCommand::Doctor {
                smoke: parse_doctor(rest, &mut endpoint_raw, &mut json_output)?,
            }
        }
        "list" => {
            parse_no_args_subcommand(rest, "list", &mut endpoint_raw, &mut json_output)?;
            match check_help_in_rest(rest) {
                true => return Ok(CliOutcome::Help(USAGE_TEXT)),
                false => CliCommand::List,
            }
        }
        "tui" => {
            if check_help_in_rest(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            let refresh_interval = parse_tui(rest, &mut endpoint_raw, &mut json_output)?;
            if json_output {
                return Err(SandboxError::InvalidSpec(
                    "--json is not supported with interactive 'tui'".to_owned(),
                ));
            }
            CliCommand::Tui { refresh_interval }
        }
        "spawn" => {
            if check_help_in_rest(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            CliCommand::Spawn(parse_spawn(rest, &mut endpoint_raw, &mut json_output)?)
        }
        "run" => {
            if check_help_before_double_dash(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            CliCommand::Run(Box::new(parse_run(
                rest,
                &mut endpoint_raw,
                &mut json_output,
            )?))
        }
        "exec" => {
            if check_help_before_double_dash(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            let (id, req) = parse_exec(rest, &mut endpoint_raw, &mut json_output)?;
            CliCommand::Exec { id, req }
        }
        "renew" => {
            if check_help_in_rest(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            let (id, ttl) = parse_renew(rest, &mut endpoint_raw, &mut json_output)?;
            CliCommand::Renew { id, ttl }
        }
        "copy-in" => {
            if check_help_in_rest(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            let (id, src_host, dst_guest) =
                parse_copy_pair(rest, "copy-in", &mut endpoint_raw, &mut json_output)?;
            CliCommand::CopyIn {
                id,
                src_host: PathBuf::from(src_host),
                dst_guest,
            }
        }
        "copy-out" => {
            if check_help_in_rest(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            let (id, src_guest, dst_host) =
                parse_copy_pair(rest, "copy-out", &mut endpoint_raw, &mut json_output)?;
            CliCommand::CopyOut {
                id,
                src_guest,
                dst_host: PathBuf::from(dst_host),
            }
        }
        "build" => {
            if check_help_in_rest(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            let (id, spec) = parse_build(rest, &mut endpoint_raw, &mut json_output)?;
            CliCommand::Build {
                id,
                spec: Box::new(spec),
            }
        }
        "compose" => {
            if check_help_in_rest(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            let (id, action) = parse_compose(rest, &mut endpoint_raw, &mut json_output)?;
            CliCommand::Compose { id, action }
        }
        "docker-endpoint" => {
            if check_help_in_rest(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            let (id, allow_reaper_socket) =
                parse_docker_endpoint(rest, &mut endpoint_raw, &mut json_output)?;
            CliCommand::DockerEndpoint {
                id,
                allow_reaper_socket,
            }
        }
        "destroy" => {
            if check_help_in_rest(rest) {
                return Ok(CliOutcome::Help(USAGE_TEXT));
            }
            let id = parse_single_id(rest, "destroy", &mut endpoint_raw, &mut json_output)?;
            CliCommand::Destroy { id }
        }
        other => {
            return Err(SandboxError::InvalidSpec(format!(
                "unknown subcommand '{other}' (run with --help)"
            )));
        }
    };

    let endpoint = match endpoint_raw {
        Some(raw) => ControlEndpoint::parse(&raw)?,
        None => default_control_endpoint_with(&get_env)?,
    };

    Ok(CliOutcome::Run(ParsedCli {
        endpoint,
        json: json_output,
        command,
    }))
}

fn check_help_in_rest(rest: &[String]) -> bool {
    rest.iter().any(|a| matches!(a.as_str(), "-h" | "--help"))
}

fn check_help_before_double_dash(rest: &[String]) -> bool {
    for a in rest {
        if a == "--" {
            break;
        }
        if matches!(a.as_str(), "-h" | "--help") {
            return true;
        }
    }
    false
}

fn parse_no_args_subcommand(
    rest: &[String],
    subcmd: &str,
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<(), SandboxError> {
    let mut i = 0usize;
    while i < rest.len() {
        let arg = rest[i].as_str();
        if matches!(arg, "-h" | "--help") {
            return Ok(());
        }
        if !try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            return Err(SandboxError::InvalidSpec(format!(
                "unexpected argument '{arg}' for '{subcmd}'"
            )));
        }
        i += 1;
    }
    Ok(())
}

fn parse_tui(
    rest: &[String],
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<Duration, SandboxError> {
    let mut refresh_ms: u64 = 1000;
    let mut i = 0usize;
    while i < rest.len() {
        if try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            i += 1;
            continue;
        }
        let arg = rest[i].as_str();
        let (flag, inline_val) = split_flag(arg);
        match flag {
            "--refresh-ms" => {
                let raw = take_flag_value(rest, &mut i, flag, inline_val)?;
                refresh_ms = parse_int(&raw, flag)?;
                if refresh_ms < 100 {
                    return Err(SandboxError::InvalidSpec(
                        "--refresh-ms must be at least 100".to_owned(),
                    ));
                }
            }
            other => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown option '{other}' for 'tui'"
                )));
            }
        }
        i += 1;
    }
    Ok(Duration::from_millis(refresh_ms))
}

fn parse_doctor(
    rest: &[String],
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<Option<SandboxSpec>, SandboxError> {
    let mut smoke = false;
    let mut spawn_args = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        if try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            i += 1;
            continue;
        }
        let (flag, inline) = split_flag(&rest[i]);
        match flag {
            "--smoke" if inline.is_none() => smoke = true,
            "--accel" => {
                let value = take_flag_value(rest, &mut i, flag, inline)?;
                spawn_args.extend([flag.to_owned(), value]);
            }
            _ => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown option '{}' for 'doctor'",
                    rest[i]
                )))
            }
        }
        i += 1;
    }
    if !smoke {
        if !spawn_args.is_empty() {
            return Err(SandboxError::InvalidSpec(
                "--accel requires --smoke".to_owned(),
            ));
        }
        return Ok(None);
    }
    Ok(Some(parse_spawn(&spawn_args, endpoint_raw, json_output)?))
}

fn parse_spawn(
    rest: &[String],
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<SandboxSpec, SandboxError> {
    let mut isolation = IsolationMode::VmRequired;
    let mut acceleration = AccelerationPolicy::Preferred;
    let mut simple_network: Option<NetworkPolicy> = None;
    let mut allow_rules: Vec<EgressRule> = Vec::new();
    let mut vcpus: u8 = 1;
    let mut ram_mb: u32 = 256;
    let mut rss_mb: Option<u32> = None;
    let mut cpu_millicores: Option<u32> = None;
    let mut disk_mb: u32 = 512;
    let mut storage_mb: u32 = 1024;
    let mut ttl_secs: u64 = 300;

    let mut i = 0usize;
    while i < rest.len() {
        if try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            i += 1;
            continue;
        }

        let arg = rest[i].as_str();
        let (flag, inline_val) = split_flag(arg);
        match flag {
            "--isolation" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                isolation = match val.as_str() {
                    "vm" => IsolationMode::VmRequired,
                    "shared-kernel" => IsolationMode::SharedKernelAllowed,
                    other => {
                        return Err(SandboxError::InvalidSpec(format!(
                            "invalid --isolation '{other}'; expected 'vm' or 'shared-kernel'"
                        )));
                    }
                };
            }
            "--accel" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                acceleration = match val.as_str() {
                    "required" => AccelerationPolicy::Required,
                    "preferred" => AccelerationPolicy::Preferred,
                    "software" => AccelerationPolicy::SoftwareOnly,
                    other => {
                        return Err(SandboxError::InvalidSpec(format!(
                            "invalid --accel '{other}'; expected 'required', 'preferred', or 'software'"
                        )));
                    }
                };
            }
            "--network" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                if let Some(rule_raw) = val.strip_prefix("allow:") {
                    if simple_network.is_some() {
                        return Err(SandboxError::InvalidSpec(
                            "cannot combine '--network allow:...' with another network policy"
                                .to_owned(),
                        ));
                    }
                    allow_rules.push(parse_allow_rule(rule_raw)?);
                } else {
                    if !allow_rules.is_empty() || simple_network.is_some() {
                        return Err(SandboxError::InvalidSpec(
                            "conflicting '--network' policies specified".to_owned(),
                        ));
                    }
                    simple_network = Some(match val.as_str() {
                        "isolated" => NetworkPolicy::Isolated,
                        "internet" => NetworkPolicy::InternetOnly,
                        "unrestricted" => NetworkPolicy::Unrestricted,
                        other => {
                            return Err(SandboxError::InvalidSpec(format!(
                                "invalid --network '{other}'; expected isolated|internet|allow:<domain>:<port>|unrestricted"
                            )));
                        }
                    });
                }
            }
            "--vcpus" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                vcpus = parse_int(&val, flag)?;
            }
            "--ram-mb" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                ram_mb = parse_int(&val, flag)?;
            }
            "--rss-mb" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                rss_mb = Some(parse_int(&val, flag)?);
            }
            "--cpu-millicores" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                cpu_millicores = Some(parse_int(&val, flag)?);
            }
            "--disk-mb" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                disk_mb = parse_int(&val, flag)?;
            }
            "--storage-mb" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                storage_mb = parse_int(&val, flag)?;
            }
            "--ttl-secs" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                ttl_secs = parse_int(&val, flag)?;
            }
            other => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown option '{other}' for 'spawn'"
                )));
            }
        }
        i += 1;
    }

    if ttl_secs == 0 {
        return Err(SandboxError::InvalidSpec(
            "--ttl-secs must be greater than zero".to_owned(),
        ));
    }

    let network = if !allow_rules.is_empty() {
        NetworkPolicy::DomainAllowList { rules: allow_rules }
    } else {
        simple_network.unwrap_or(NetworkPolicy::Isolated)
    };

    let spec = SandboxSpec {
        isolation,
        acceleration,
        network,
        budget: ResourceBudget {
            guest_vcpus: vcpus,
            host_cpu_quota_Millicores: cpu_millicores,
            guest_ram_mb: ram_mb,
            host_rss_budget_mb: rss_mb,
            virtual_disk_mb: disk_mb,
            host_storage_budget_mb: storage_mb,
        },
        lease_ttl: Duration::from_secs(ttl_secs),
    };
    spec.validate_for_host_os(std::env::consts::OS)?;
    Ok(spec)
}

fn parse_allow_rule(raw: &str) -> Result<EgressRule, SandboxError> {
    let (domain, port_str) = raw.rsplit_once(':').ok_or_else(|| {
        SandboxError::InvalidSpec(format!(
            "invalid allow rule '{raw}'; expected allow:<domain>:<port>"
        ))
    })?;
    let port: u16 = port_str.parse().map_err(|err| {
        SandboxError::InvalidSpec(format!("invalid port '{port_str}' in allow rule '{raw}': {err}"))
    })?;
    if port == 0 {
        return Err(SandboxError::InvalidSpec(
            "egress rule port must be greater than zero".to_owned(),
        ));
    }
    let normalized = normalize_egress_domain(domain)?;
    Ok(EgressRule {
        domain: normalized,
        port,
    })
}

fn parse_exec(
    rest: &[String],
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<(SandboxId, ExecRequest), SandboxError> {
    let mut id_str: Option<String> = None;
    let mut container: Option<String> = None;
    let mut cwd: Option<String> = None;
    let mut user: Option<String> = None;
    let mut env = BTreeMap::new();
    let mut deadline_secs = DEFAULT_EXEC_DEADLINE_SECS;
    let mut stdout_budget_bytes = DEFAULT_EXEC_BUDGET_BYTES;
    let mut stderr_budget_bytes = DEFAULT_EXEC_BUDGET_BYTES;
    let mut argv: Vec<String> = Vec::new();

    let mut i = 0usize;
    while i < rest.len() {
        let arg = rest[i].as_str();
        if arg == "--" {
            argv.extend(rest[i + 1..].iter().cloned());
            break;
        }
        if try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            i += 1;
            continue;
        }

        let (flag, inline_val) = split_flag(arg);
        match flag {
            "--container" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                if val.is_empty() {
                    return Err(SandboxError::InvalidSpec(
                        "--container must not be empty".to_owned(),
                    ));
                }
                container = Some(val);
            }
            "--cwd" => {
                cwd = Some(take_flag_value(rest, &mut i, flag, inline_val)?);
            }
            "--user" => {
                user = Some(take_flag_value(rest, &mut i, flag, inline_val)?);
            }
            "--env" => {
                let kv = take_flag_value(rest, &mut i, flag, inline_val)?;
                let (k, v) = kv.split_once('=').ok_or_else(|| {
                    SandboxError::InvalidSpec(format!("invalid --env '{kv}'; expected K=V"))
                })?;
                if k.is_empty() {
                    return Err(SandboxError::InvalidSpec(
                        "--env key must not be empty".to_owned(),
                    ));
                }
                env.insert(k.to_owned(), v.to_owned());
            }
            "--deadline-secs" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                deadline_secs = parse_int(&val, flag)?;
            }
            "--stdout-budget-bytes" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                stdout_budget_bytes = parse_int(&val, flag)?;
            }
            "--stderr-budget-bytes" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                stderr_budget_bytes = parse_int(&val, flag)?;
            }
            _ if arg.starts_with('-') => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown option '{arg}' for 'exec'"
                )));
            }
            _ => {
                if id_str.is_none() {
                    id_str = Some(arg.to_owned());
                } else {
                    argv.extend(rest[i..].iter().cloned());
                    break;
                }
            }
        }
        i += 1;
    }

    let id = req_sandbox_id(id_str, "exec")?;
    if argv.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "exec requires command arguments after '--'".to_owned(),
        ));
    }
    if deadline_secs == 0 {
        return Err(SandboxError::InvalidSpec(
            "--deadline-secs must be greater than zero".to_owned(),
        ));
    }
    if stdout_budget_bytes == 0 || stderr_budget_bytes == 0 {
        return Err(SandboxError::InvalidSpec(
            "output budget bytes must be greater than zero".to_owned(),
        ));
    }

    let target = match container {
        Some(id_or_name) => ExecTarget::Container { id_or_name },
        None => ExecTarget::Guest,
    };

    Ok((
        id,
        ExecRequest {
            target,
            argv,
            env,
            cwd,
            user,
            deadline: Duration::from_secs(deadline_secs),
            stdout_budget_bytes,
            stderr_budget_bytes,
        },
    ))
}

fn parse_run(
    rest: &[String],
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<RunSpec, SandboxError> {
    let mut spawn_args = Vec::new();
    let mut exec_args = vec!["run-sandbox".to_owned()];
    let mut input = None;
    let mut output = None;
    let mut i = 0;

    while i < rest.len() {
        let arg = &rest[i];
        if arg == "--" {
            exec_args.extend(rest[i..].iter().cloned());
            break;
        }
        if try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            i += 1;
            continue;
        }
        let (flag, inline) = split_flag(arg);
        match flag {
            "--input" | "--output" => {
                let first = take_flag_value(rest, &mut i, flag, inline)?;
                i += 1;
                let second = rest
                    .get(i)
                    .filter(|value| !value.is_empty() && *value != "--")
                    .ok_or_else(|| SandboxError::InvalidSpec(format!("{flag} requires two paths")))?
                    .clone();
                if first.is_empty() {
                    return Err(SandboxError::InvalidSpec(format!(
                        "{flag} paths must not be empty"
                    )));
                }
                let target = if flag == "--input" {
                    &mut input
                } else {
                    &mut output
                };
                if target.replace((first, second)).is_some() {
                    return Err(SandboxError::InvalidSpec(format!(
                        "{flag} may only be specified once"
                    )));
                }
            }
            "--isolation" | "--accel" | "--network" | "--vcpus" | "--ram-mb" | "--rss-mb"
            | "--cpu-millicores" | "--disk-mb" | "--storage-mb" | "--ttl-secs" => {
                let value = take_flag_value(rest, &mut i, flag, inline)?;
                spawn_args.extend([flag.to_owned(), value]);
            }
            "--cwd"
            | "--user"
            | "--env"
            | "--deadline-secs"
            | "--stdout-budget-bytes"
            | "--stderr-budget-bytes" => {
                let value = take_flag_value(rest, &mut i, flag, inline)?;
                exec_args.extend([flag.to_owned(), value]);
            }
            _ => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown option '{arg}' for 'run'"
                )))
            }
        }
        i += 1;
    }
    if i == rest.len() {
        return Err(SandboxError::InvalidSpec(
            "run requires '--' followed by command arguments".to_owned(),
        ));
    }
    let spec = parse_spawn(&spawn_args, endpoint_raw, json_output)?;
    let (_, request) = parse_exec(&exec_args, endpoint_raw, json_output)?;
    Ok(RunSpec {
        spec,
        request,
        input: input.map(|(host, guest)| (PathBuf::from(host), guest)),
        output: output.map(|(guest, host)| (guest, PathBuf::from(host))),
    })
}

fn parse_renew(
    rest: &[String],
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<(SandboxId, Duration), SandboxError> {
    let mut id_str: Option<String> = None;
    let mut ttl_secs: Option<u64> = None;

    let mut i = 0usize;
    while i < rest.len() {
        if try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            i += 1;
            continue;
        }
        let arg = rest[i].as_str();
        let (flag, inline_val) = split_flag(arg);
        match flag {
            "--ttl-secs" => {
                let val = take_flag_value(rest, &mut i, flag, inline_val)?;
                ttl_secs = Some(parse_int(&val, flag)?);
            }
            _ if arg.starts_with('-') => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown option '{arg}' for 'renew'"
                )));
            }
            _ => {
                if id_str.is_some() {
                    return Err(SandboxError::InvalidSpec(format!(
                        "unexpected argument '{arg}' for 'renew'"
                    )));
                }
                id_str = Some(arg.to_owned());
            }
        }
        i += 1;
    }

    let id = req_sandbox_id(id_str, "renew")?;
    let secs = ttl_secs.ok_or_else(|| {
        SandboxError::InvalidSpec("'renew' requires --ttl-secs <N>".to_owned())
    })?;
    if secs == 0 {
        return Err(SandboxError::InvalidSpec(
            "--ttl-secs must be greater than zero".to_owned(),
        ));
    }
    Ok((id, Duration::from_secs(secs)))
}

fn parse_copy_pair(
    rest: &[String],
    subcmd: &str,
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<(SandboxId, String, String), SandboxError> {
    let mut positionals: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        if try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            i += 1;
            continue;
        }
        let arg = rest[i].as_str();
        if arg.starts_with('-') {
            return Err(SandboxError::InvalidSpec(format!(
                "unknown option '{arg}' for '{subcmd}'"
            )));
        }
        positionals.push(arg.to_owned());
        i += 1;
    }

    if positionals.len() != 3 {
        return Err(SandboxError::InvalidSpec(format!(
            "'{subcmd}' requires <sandbox-id> <src> <dst> (got {} positional arguments)",
            positionals.len()
        )));
    }
    let mut iter = positionals.into_iter();
    let id = req_sandbox_id(iter.next(), subcmd)?;
    let src = iter.next().expect("checked len 3");
    let dst = iter.next().expect("checked len 3");
    if src.is_empty() || dst.is_empty() {
        return Err(SandboxError::InvalidSpec(format!(
            "'{subcmd}' paths must not be empty"
        )));
    }
    Ok((id, src, dst))
}

fn parse_build(
    rest: &[String],
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<(SandboxId, ImageBuildSpec), SandboxError> {
    const DEFAULT_BUILD_DEADLINE_SECS: u64 = 300;

    let mut positionals: Vec<String> = Vec::new();
    let mut tags: Vec<String> = Vec::new();
    let mut dockerfile: Option<String> = None;
    let mut build_args: Vec<(String, String)> = Vec::new();
    let mut target: Option<String> = None;
    let mut no_cache = false;
    let mut output_tar: Option<PathBuf> = None;
    let mut deadline_secs = DEFAULT_BUILD_DEADLINE_SECS;

    let mut i = 0usize;
    while i < rest.len() {
        if try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            i += 1;
            continue;
        }
        let arg = rest[i].as_str();
        let (flag, inline_val) = split_flag(arg);
        match flag {
            "-t" | "--tag" => {
                tags.push(take_flag_value(rest, &mut i, flag, inline_val)?);
            }
            "-f" | "--file" => {
                dockerfile = Some(take_flag_value(rest, &mut i, flag, inline_val)?);
            }
            "--build-arg" => {
                let raw = take_flag_value(rest, &mut i, flag, inline_val)?;
                let (k, v) = raw.split_once('=').ok_or_else(|| {
                    SandboxError::InvalidSpec(format!(
                        "invalid --build-arg '{raw}'; expected KEY=VALUE"
                    ))
                })?;
                build_args.push((k.to_owned(), v.to_owned()));
            }
            "--target" => {
                target = Some(take_flag_value(rest, &mut i, flag, inline_val)?);
            }
            "--no-cache" => {
                if inline_val.is_some() {
                    return Err(SandboxError::InvalidSpec(
                        "--no-cache does not take a value".to_owned(),
                    ));
                }
                no_cache = true;
            }
            "-o" | "--output-tar" => {
                let raw = take_flag_value(rest, &mut i, flag, inline_val)?;
                output_tar = Some(PathBuf::from(raw));
            }
            "--deadline-secs" => {
                let raw = take_flag_value(rest, &mut i, flag, inline_val)?;
                deadline_secs = parse_int(&raw, flag)?;
            }
            _ if arg.starts_with('-') => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown option '{arg}' for 'build'"
                )));
            }
            _ => positionals.push(arg.to_owned()),
        }
        i += 1;
    }

    if positionals.len() != 2 {
        return Err(SandboxError::InvalidSpec(format!(
            "'build' requires <sandbox-id> <context-dir> (got {} positional arguments)",
            positionals.len()
        )));
    }
    let mut iter = positionals.into_iter();
    let id = req_sandbox_id(iter.next(), "build")?;
    let ctx_raw = iter.next().expect("checked len 2");

    let mut spec = ImageBuildSpec {
        context_dir: PathBuf::from(ctx_raw),
        dockerfile,
        tags,
        build_args,
        target,
        no_cache,
        output_tar,
        deadline: Duration::from_secs(deadline_secs),
    };
    spec.validate_and_normalize()?;
    Ok((id, spec))
}

fn parse_compose(
    rest: &[String],
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<(SandboxId, ComposeAction), SandboxError> {
    const DEFAULT_COMPOSE_DEADLINE_SECS: u64 = 300;
    const DEFAULT_COMPOSE_TAIL: u32 = 100;

    let mut positionals: Vec<String> = Vec::new();
    let mut file: Option<PathBuf> = None;
    let mut project: Option<String> = None;
    let mut build = false;
    let mut volumes = false;
    let mut deadline_secs: Option<u64> = None;
    let mut tail: Option<u32> = None;

    let mut i = 0usize;
    while i < rest.len() {
        if try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            i += 1;
            continue;
        }
        let arg = rest[i].as_str();
        let (flag, inline_val) = split_flag(arg);
        match flag {
            "-f" | "--file" => {
                let raw = take_flag_value(rest, &mut i, flag, inline_val)?;
                file = Some(PathBuf::from(raw));
            }
            "-p" | "--project-name" => {
                project = Some(take_flag_value(rest, &mut i, flag, inline_val)?);
            }
            "--build" => {
                if inline_val.is_some() {
                    return Err(SandboxError::InvalidSpec(
                        "--build does not take a value".to_owned(),
                    ));
                }
                build = true;
            }
            "-v" | "--volumes" => {
                if inline_val.is_some() {
                    return Err(SandboxError::InvalidSpec(
                        "--volumes does not take a value".to_owned(),
                    ));
                }
                volumes = true;
            }
            "--deadline-secs" => {
                let raw = take_flag_value(rest, &mut i, flag, inline_val)?;
                let parsed: u64 = parse_int(&raw, flag)?;
                if parsed == 0 {
                    return Err(SandboxError::InvalidSpec(
                        "--deadline-secs must be greater than zero".to_owned(),
                    ));
                }
                deadline_secs = Some(parsed);
            }
            "--tail" => {
                let raw = take_flag_value(rest, &mut i, flag, inline_val)?;
                tail = Some(parse_int(&raw, flag)?);
            }
            "-d" | "--detach" => {
                // Accepted as a no-op alias on `compose up` since sandbox compose stacks always run detached.
                if inline_val.is_some() {
                    return Err(SandboxError::InvalidSpec(
                        "--detach does not take a value".to_owned(),
                    ));
                }
            }
            _ if arg.starts_with('-') => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown option '{arg}' for 'compose'"
                )));
            }
            _ => positionals.push(arg.to_owned()),
        }
        i += 1;
    }

    if positionals.len() < 2 {
        return Err(SandboxError::InvalidSpec(
            "'compose' requires <sandbox-id> <up|ps|logs|down>".to_owned(),
        ));
    }

    let id = req_sandbox_id(Some(positionals[0].clone()), "compose")?;
    let sub = positionals[1].as_str();

    let action = match sub {
        "up" => {
            if positionals.len() > 2 || volumes || tail.is_some() {
                return Err(SandboxError::InvalidSpec(
                    "invalid arguments for 'compose up'".to_owned(),
                ));
            }
            ComposeAction::Up {
                file,
                project,
                build,
                deadline: Duration::from_secs(deadline_secs.unwrap_or(DEFAULT_COMPOSE_DEADLINE_SECS)),
            }
        }
        "ps" => {
            if positionals.len() > 2 || build || volumes || deadline_secs.is_some() || tail.is_some() {
                return Err(SandboxError::InvalidSpec(
                    "invalid arguments for 'compose ps'".to_owned(),
                ));
            }
            ComposeAction::Ps { file, project }
        }
        "logs" => {
            if positionals.len() > 3 || build || volumes || deadline_secs.is_some() {
                return Err(SandboxError::InvalidSpec(
                    "invalid arguments for 'compose logs'".to_owned(),
                ));
            }
            ComposeAction::Logs {
                file,
                project,
                tail: tail.unwrap_or(DEFAULT_COMPOSE_TAIL),
                service: positionals.get(2).cloned(),
            }
        }
        "down" => {
            if positionals.len() > 2 || build || deadline_secs.is_some() || tail.is_some() {
                return Err(SandboxError::InvalidSpec(
                    "invalid arguments for 'compose down'".to_owned(),
                ));
            }
            ComposeAction::Down {
                file,
                project,
                volumes,
            }
        }
        other => {
            return Err(SandboxError::InvalidSpec(format!(
                "unknown compose action '{other}'; expected 'up', 'ps', 'logs', or 'down'"
            )));
        }
    };

    Ok((id, action))
}

fn parse_docker_endpoint(
    rest: &[String],
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<(SandboxId, bool), SandboxError> {
    let mut id_str: Option<String> = None;
    let mut allow_reaper = false;

    let mut i = 0usize;
    while i < rest.len() {
        if try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            i += 1;
            continue;
        }
        let arg = rest[i].as_str();
        match arg {
            "--allow-reaper-socket" => allow_reaper = true,
            _ if arg.starts_with('-') => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unknown option '{arg}' for 'docker-endpoint'"
                )));
            }
            _ => {
                if id_str.is_some() {
                    return Err(SandboxError::InvalidSpec(format!(
                        "unexpected argument '{arg}' for 'docker-endpoint'"
                    )));
                }
                id_str = Some(arg.to_owned());
            }
        }
        i += 1;
    }

    let id = req_sandbox_id(id_str, "docker-endpoint")?;
    Ok((id, allow_reaper))
}

fn parse_single_id(
    rest: &[String],
    subcmd: &str,
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<SandboxId, SandboxError> {
    let mut id_str: Option<String> = None;
    let mut i = 0usize;
    while i < rest.len() {
        if try_consume_global_flag(rest, &mut i, endpoint_raw, json_output)? {
            i += 1;
            continue;
        }
        let arg = rest[i].as_str();
        if arg.starts_with('-') {
            return Err(SandboxError::InvalidSpec(format!(
                "unknown option '{arg}' for '{subcmd}'"
            )));
        }
        if id_str.is_some() {
            return Err(SandboxError::InvalidSpec(format!(
                "unexpected argument '{arg}' for '{subcmd}'"
            )));
        }
        id_str = Some(arg.to_owned());
        i += 1;
    }
    req_sandbox_id(id_str, subcmd)
}

fn req_sandbox_id(id_str: Option<String>, subcmd: &str) -> Result<SandboxId, SandboxError> {
    let id = id_str.ok_or_else(|| {
        SandboxError::InvalidSpec(format!("'{subcmd}' requires <sandbox-id>"))
    })?;
    if id.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "sandbox-id must not be empty".to_owned(),
        ));
    }
    Ok(SandboxId::new(id))
}

fn try_consume_global_flag(
    args: &[String],
    idx: &mut usize,
    endpoint_raw: &mut Option<String>,
    json_output: &mut bool,
) -> Result<bool, SandboxError> {
    let arg = args[*idx].as_str();
    let (flag, inline_val) = split_flag(arg);
    match flag {
        "--json" => {
            if inline_val.is_some() {
                return Err(SandboxError::InvalidSpec(
                    "--json does not take a value".to_owned(),
                ));
            }
            *json_output = true;
            Ok(true)
        }
        "--endpoint" => {
            *endpoint_raw = Some(take_flag_value(args, idx, flag, inline_val)?);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn split_flag(arg: &str) -> (&str, Option<&str>) {
    if arg.starts_with("--") {
        if let Some((k, v)) = arg.split_once('=') {
            return (k, Some(v));
        }
    }
    (arg, None)
}

fn take_flag_value(
    args: &[String],
    idx: &mut usize,
    flag: &str,
    inline_val: Option<&str>,
) -> Result<String, SandboxError> {
    if let Some(val) = inline_val {
        return Ok(val.to_owned());
    }
    *idx += 1;
    args.get(*idx).cloned().ok_or_else(|| {
        SandboxError::InvalidSpec(format!("flag '{flag}' requires a value"))
    })
}

fn parse_int<T: std::str::FromStr>(raw: &str, flag: &str) -> Result<T, SandboxError>
where
    T::Err: std::fmt::Display,
{
    raw.parse::<T>().map_err(|err| {
        SandboxError::InvalidSpec(format!("invalid integer '{raw}' for {flag}: {err}"))
    })
}

/// Computes the platform owner-local default [`ControlEndpoint`] using the provided env lookup.
pub fn default_control_endpoint_with<F>(get_env: &F) -> Result<ControlEndpoint, SandboxError>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(ep) = get_env("MINIPOD_ENDPOINT").and_then(|v| {
        let t = v.trim();
        (!t.is_empty()).then(|| t.to_owned())
    }) {
        return ControlEndpoint::parse(&ep);
    }

    #[cfg(windows)]
    {
        let sanitized = get_env("USERNAME")
            .map(|u| {
                u.trim()
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                    .take(48)
                    .collect::<String>()
                    .trim_matches('.')
                    .to_owned()
            })
            .unwrap_or_default();
        let pipe_name = if sanitized.is_empty() {
            "minipod-sandboxd".to_owned()
        } else {
            format!("minipod-sandboxd-{sanitized}")
        };
        ControlEndpoint::parse(&format!(r"\\.\pipe\{pipe_name}"))
    }

    #[cfg(unix)]
    {
        const MAX_UNIX_SOCK_BYTES: usize = 103;
        if let Some(xdg) = get_env("XDG_RUNTIME_DIR").and_then(|v| {
            let t = v.trim();
            (!t.is_empty()).then(|| t.to_owned())
        }) {
            let candidate = PathBuf::from(xdg).join("minipod").join("ctl.sock");
            if is_valid_short_unix_socket(&candidate, MAX_UNIX_SOCK_BYTES) {
                return Ok(ControlEndpoint::UnixSocket(candidate));
            }
        }

        let uid = current_unix_uid()?;
        let temp_candidate = std::env::temp_dir()
            .join(format!("minipod-{uid}"))
            .join("ctl.sock");
        if is_valid_short_unix_socket(&temp_candidate, MAX_UNIX_SOCK_BYTES) {
            return Ok(ControlEndpoint::UnixSocket(temp_candidate));
        }

        Ok(ControlEndpoint::UnixSocket(PathBuf::from(format!(
            "/tmp/minipod-{uid}/ctl.sock"
        ))))
    }
}

#[cfg(unix)]
fn is_valid_short_unix_socket(path: &Path, max_bytes: usize) -> bool {
    path.to_str().is_some_and(|s| {
        !s.is_empty()
            && s.len() <= max_bytes
            && !s.contains('\0')
            && !s.contains(',')
            && !s.contains("..")
    })
}

#[cfg(unix)]
fn current_unix_uid() -> Result<u32, SandboxError> {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(target_os = "linux")]
    if let Ok(meta) = fs::metadata("/proc/self") {
        return Ok(meta.uid());
    }

    static SEQ: AtomicU64 = AtomicU64::new(0);
    struct ProbeCleanup(PathBuf);
    impl Drop for ProbeCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    let tmp_dir = std::env::temp_dir();
    for _ in 0..8 {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let probe_path = tmp_dir.join(format!("mp-cli-uid-{}-{seq}", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe_path)
        {
            Ok(file) => {
                let _cleanup = ProbeCleanup(probe_path);
                let meta = file.metadata().map_err(|err| {
                    SandboxError::Internal(format!("failed to read UID probe metadata: {err}"))
                })?;
                return Ok(meta.uid());
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(SandboxError::Internal(format!(
                    "failed to determine current UID via temp probe '{}': {err}",
                    probe_path.display()
                )));
            }
        }
    }

    Err(SandboxError::Internal(
        "exhausted retries while creating UID probe file".to_owned(),
    ))
}

/// Executes a parsed [`ParsedCli`] command through [`SandboxClient`] and returns the process exit code.
pub async fn execute_cli(parsed: ParsedCli) -> Result<u8, SandboxError> {
    let client = SandboxClient::new(parsed.endpoint);
    execute_with_client(&client, parsed.json, parsed.command).await
}

pub async fn execute_with_client(
    client: &SandboxClient,
    json_mode: bool,
    command: CliCommand,
) -> Result<u8, SandboxError> {
    match command {
        CliCommand::Doctor { smoke } => execute_doctor(client, json_mode, smoke).await,
        CliCommand::Status => {
            let info = client.status().await?;
            if json_mode {
                print_json(&json!({
                    "active_sandboxes": info.active_sandboxes,
                    "warm_ready_vms": info.warm_ready_vms,
                    "effective_host_rss_mb": info.effective_host_rss_mb,
                    "reserved_host_storage_mb": info.reserved_host_storage_mb,
                    "version": info.version,
                }));
            } else {
                println!(
                    "version={} active_sandboxes={} warm_ready_vms={} effective_host_rss_mb={} reserved_host_storage_mb={}",
                    info.version,
                    info.active_sandboxes,
                    info.warm_ready_vms,
                    info.effective_host_rss_mb,
                    info.reserved_host_storage_mb
                );
            }
            Ok(0)
        }
        CliCommand::List => {
            let sandboxes = client.list_sandboxes().await?;
            if json_mode {
                let items: Vec<Value> = sandboxes
                    .iter()
                    .map(|s| s.to_json_value())
                    .collect();
                print_json(&json!({ "sandboxes": items }));
            } else if sandboxes.is_empty() {
                println!("no active sandboxes");
            } else {
                println!(
                    "{:<24} {:<8} {:<6} {:<16} {:<14} {:<10} DOCKER_ENDPOINT",
                    "SANDBOX_ID", "PID", "STATE", "NETWORK", "RSS_MB", "TTL_SECS"
                );
                for s in sandboxes {
                    let state_lbl = if s.alive { "alive" } else { "exited" };
                    let rss_lbl = match (s.live_rss_bytes, s.host_rss_budget_mb) {
                        (Some(b), Some(cap)) => {
                            format!("{}/{}", b.div_ceil(1024 * 1024), cap)
                        }
                        (Some(b), None) => format!("{}", b.div_ceil(1024 * 1024)),
                        (None, Some(cap)) => format!("-/{cap}"),
                        (None, None) => "-".to_owned(),
                    };
                    let docker_lbl = match (&s.docker_endpoint, s.allow_reaper_socket) {
                        (Some(uri), true) => format!("{uri} (ryuk)"),
                        (Some(uri), false) => uri.clone(),
                        (None, _) => "-".to_owned(),
                    };
                    println!(
                        "{:<24} {:<8} {:<6} {:<16} {:<14} {:<10} {}",
                        s.id.as_str(),
                        s.pid,
                        state_lbl,
                        format_network_short(&s.network),
                        rss_lbl,
                        s.remaining_ttl_ms / 1000,
                        docker_lbl,
                    );
                }
            }
            Ok(0)
        }
        CliCommand::Tui { refresh_interval } => {
            crate::tui::run_tui(client, refresh_interval).await
        }
        CliCommand::Run(spec) => execute_run(client, json_mode, *spec).await,
        CliCommand::Spawn(spec) => {
            let lease = client.spawn(spec).await?;
            if json_mode {
                print_json(&json!({
                    "id": lease.id.as_str(),
                    "ttl_secs": lease.ttl.as_secs(),
                    "capabilities": {
                        "cpu_quota": enforcement_str(lease.capabilities.cpu_quota),
                        "host_rss": enforcement_str(lease.capabilities.host_rss),
                        "host_storage": enforcement_str(lease.capabilities.host_storage),
                        "egress_filter": enforcement_str(lease.capabilities.egress_filter),
                    }
                }));
            } else {
                println!(
                    "{} (ttl={}s cpu={} rss={} storage={} egress={})",
                    lease.id,
                    lease.ttl.as_secs(),
                    enforcement_str(lease.capabilities.cpu_quota),
                    enforcement_str(lease.capabilities.host_rss),
                    enforcement_str(lease.capabilities.host_storage),
                    enforcement_str(lease.capabilities.egress_filter),
                );
            }
            Ok(0)
        }
        CliCommand::Exec { id, req } => {
            let mut stream = client.exec_stream(&id, req).await?;
            stream.close_stdin();

            if json_mode {
                let collected = stream.collect().await?;
                print_json(&json!({
                    "exit_code": collected.exit.code,
                    "timed_out": collected.exit.timed_out,
                    "stdout_truncated": collected.exit.stdout_truncated,
                    "stderr_truncated": collected.exit.stderr_truncated,
                    "stdout": String::from_utf8_lossy(&collected.stdout),
                    "stderr": String::from_utf8_lossy(&collected.stderr),
                }));
                Ok(exit_status_to_code(collected.exit))
            } else {
                let mut stdout = tokio::io::stdout();
                let mut stderr = tokio::io::stderr();
                while let Some(chunk) = stream.next_output().await {
                    match chunk.stream {
                        ClientOutputKind::Stdout => {
                            let _ = stdout.write_all(&chunk.data).await;
                            let _ = stdout.flush().await;
                        }
                        ClientOutputKind::Stderr => {
                            let _ = stderr.write_all(&chunk.data).await;
                            let _ = stderr.flush().await;
                        }
                    }
                }
                let exit = stream.wait_exit().await?;
                if exit.timed_out {
                    let _ = stderr.write_all(b"[sandbox-cli] execution timed out\n").await;
                }
                if exit.stdout_truncated {
                    let _ = stderr
                        .write_all(b"[sandbox-cli] stdout truncated at budget limit\n")
                        .await;
                }
                if exit.stderr_truncated {
                    let _ = stderr
                        .write_all(b"[sandbox-cli] stderr truncated at budget limit\n")
                        .await;
                }
                let _ = stderr.flush().await;
                Ok(exit_status_to_code(exit))
            }
        }
        CliCommand::Renew { id, ttl } => {
            client.renew_lease(&id, ttl).await?;
            if json_mode {
                print_json(&json!({
                    "id": id.as_str(),
                    "renewed": true,
                    "ttl_secs": ttl.as_secs(),
                }));
            } else {
                println!("renewed {} (+{}s)", id, ttl.as_secs());
            }
            Ok(0)
        }
        CliCommand::CopyIn {
            id,
            src_host,
            dst_guest,
        } => {
            client.copy_in_path(&id, &src_host, &dst_guest).await?;
            if json_mode {
                print_json(&json!({
                    "id": id.as_str(),
                    "src_host": src_host.display().to_string(),
                    "dst_guest": dst_guest,
                    "copied": true,
                }));
            } else {
                println!("copied {} -> {}:{}", src_host.display(), id, dst_guest);
            }
            Ok(0)
        }
        CliCommand::CopyOut {
            id,
            src_guest,
            dst_host,
        } => {
            let bytes = client.copy_out_to_path(&id, &src_guest, &dst_host).await?;
            if json_mode {
                print_json(&json!({
                    "id": id.as_str(),
                    "src_guest": src_guest,
                    "dst_host": dst_host.display().to_string(),
                    "bytes": bytes,
                }));
            } else {
                println!(
                    "copied {}:{} -> {} ({} bytes)",
                    id,
                    src_guest,
                    dst_host.display(),
                    bytes
                );
            }
            Ok(0)
        }
        CliCommand::Build { id, spec } => {
            let res = build_image_in_sandbox(client, &id, *spec, !json_mode).await?;
            let code = exit_status_to_code(res.exit);
            if json_mode {
                print_json(&json!({
                    "id": id.as_str(),
                    "tags": res.tags,
                    "exit_code": res.exit.code,
                    "timed_out": res.exit.timed_out,
                    "exported_tar_bytes": res.exported_tar_bytes,
                    "stdout": res.stdout,
                    "stderr": res.stderr,
                }));
            } else if code == 0 {
                if let Some(bytes) = res.exported_tar_bytes {
                    println!(
                        "built {} in {} (exported {} bytes)",
                        res.tags.join(", "),
                        id,
                        bytes
                    );
                } else {
                    println!("built {} in {}", res.tags.join(", "), id);
                }
            }
            Ok(code)
        }
        CliCommand::Compose { id, action } => {
            execute_compose(client, &id, json_mode, action).await
        }
        CliCommand::DockerEndpoint {
            id,
            allow_reaper_socket,
        } => {
            let uri = client.enable_docker_compat(&id, allow_reaper_socket).await?;
            if json_mode {
                print_json(&json!({
                    "id": id.as_str(),
                    "uri": uri,
                    "allow_reaper_socket": allow_reaper_socket,
                }));
            } else {
                println!("{uri}");
            }
            Ok(0)
        }
        CliCommand::Destroy { id } => {
            let status = client.destroy(&id).await?;
            if json_mode {
                let val = match &status {
                    DestroyStatus::AllResourcesCleaned => json!({
                        "id": id.as_str(),
                        "status": "AllResourcesCleaned",
                        "remaining_artifacts": [],
                    }),
                    DestroyStatus::ProcessExited {
                        remaining_artifacts,
                    } => json!({
                        "id": id.as_str(),
                        "status": "ProcessExited",
                        "remaining_artifacts": remaining_artifacts
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>(),
                    }),
                };
                print_json(&val);
            } else {
                println!("{id}: {status:?}");
            }
            Ok(0)
        }
    }
}

fn exit_status_to_code(exit: ExecExitStatus) -> u8 {
    match exit.code {
        Some(0) => 0,
        Some(code) => ((code & 0xff) as u8).max(1),
        None => {
            if exit.timed_out {
                124
            } else {
                1
            }
        }
    }
}

fn print_json(val: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(val).unwrap_or_else(|_| val.to_string())
    );
}

pub(crate) fn format_network_short(network: &NetworkPolicy) -> String {
    match network {
        NetworkPolicy::Isolated => "isolated".to_owned(),
        NetworkPolicy::InternetOnly => "internet".to_owned(),
        NetworkPolicy::DomainAllowList { rules } => format!("allowlist({})", rules.len()),
        NetworkPolicy::Unrestricted => "unrestricted".to_owned(),
    }
}

fn enforcement_str(level: EnforcementLevel) -> &'static str {
    match level {
        EnforcementLevel::HardLimit => "HardLimit",
        EnforcementLevel::BestEffort => "BestEffort",
        EnforcementLevel::Unsupported => "Unsupported",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn no_env(_key: &str) -> Option<String> {
        None
    }

    #[test]
    fn parses_help_and_rejects_tcp_endpoints() {
        assert!(matches!(
            parse_args_with(&args(&["--help"]), no_env),
            Ok(CliOutcome::Help(_))
        ));
        assert!(matches!(
            parse_args_with(&args(&["-h"]), no_env),
            Ok(CliOutcome::Help(_))
        ));
        assert!(matches!(
            parse_args_with(&args(&["spawn", "--help"]), no_env),
            Ok(CliOutcome::Help(_))
        ));
        assert!(matches!(
            parse_args_with(&args(&["exec", "sb-1", "--", "echo", "--help"]), no_env),
            Ok(CliOutcome::Run(_))
        ));

        for bad_ep in ["tcp://127.0.0.1:2375", "http://127.0.0.1:8080"] {
            assert!(
                matches!(
                    parse_args_with(&args(&["--endpoint", bad_ep, "status"]), no_env),
                    Err(SandboxError::PolicyViolation(_))
                ),
                "expected PolicyViolation for endpoint '{bad_ep}'"
            );
            assert!(
                matches!(
                    parse_args_with(&args(&["status", "--endpoint", bad_ep]), no_env),
                    Err(SandboxError::PolicyViolation(_))
                ),
                "expected PolicyViolation for trailing endpoint '{bad_ep}'"
            );
        }
    }

    #[test]
    fn parses_all_subcommands_and_spawn_domain_rules() {
        let ep = if cfg!(windows) {
            "npipe://cli-test"
        } else {
            "unix:///tmp/cli-test.sock"
        };

        let CliOutcome::Run(status) =
            parse_args_with(&args(&["status", "--json", "--endpoint", ep]), no_env).unwrap()
        else {
            panic!("expected Run");
        };
        assert!(status.json);
        assert_eq!(status.command, CliCommand::Status);

        let CliOutcome::Run(spawn) = parse_args_with(
            &args(&[
                "--endpoint",
                ep,
                "spawn",
                "--isolation",
                "vm",
                "--accel",
                "software",
                "--network",
                "allow:API.Example.COM.:443",
                "--network",
                "allow:*.crates.io:443",
                "--vcpus",
                "2",
                "--ram-mb",
                "512",
                "--rss-mb",
                "768",
                "--cpu-millicores",
                "1500",
                "--disk-mb",
                "1024",
                "--storage-mb",
                "2048",
                "--ttl-secs",
                "90",
            ]),
            no_env,
        )
        .unwrap() else {
            panic!("expected Run");
        };
        let CliCommand::Spawn(spec) = spawn.command else {
            panic!("expected Spawn");
        };
        assert_eq!(spec.isolation, IsolationMode::VmRequired);
        assert_eq!(spec.acceleration, AccelerationPolicy::SoftwareOnly);
        assert_eq!(
            spec.network,
            NetworkPolicy::DomainAllowList {
                rules: vec![
                    EgressRule {
                        domain: "api.example.com".to_owned(),
                        port: 443,
                    },
                    EgressRule {
                        domain: "*.crates.io".to_owned(),
                        port: 443,
                    },
                ],
            }
        );
        assert_eq!(spec.budget.guest_vcpus, 2);
        assert_eq!(spec.budget.guest_ram_mb, 512);
        assert_eq!(spec.budget.host_rss_budget_mb, Some(768));
        assert_eq!(spec.budget.host_cpu_quota_Millicores, Some(1500));
        assert_eq!(spec.budget.virtual_disk_mb, 1024);
        assert_eq!(spec.budget.host_storage_budget_mb, 2048);
        assert_eq!(spec.lease_ttl, Duration::from_secs(90));

        // Conflicting network policies or invalid domain allow rules rejected.
        assert!(matches!(
            parse_args_with(
                &args(&[
                    "spawn",
                    "--network",
                    "isolated",
                    "--network",
                    "allow:example.com:443"
                ]),
                no_env
            ),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            parse_args_with(&args(&["spawn", "--network", "allow:127.0.0.1:80"]), no_env),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            parse_args_with(&args(&["spawn", "--network", "allow:example.com:0"]), no_env),
            Err(SandboxError::InvalidSpec(_))
        ));

        // Exec with flags + `--` delimiter preserving flag-like argv tokens.
        let CliOutcome::Run(exec) = parse_args_with(
            &args(&[
                "exec",
                "sb-42",
                "--container",
                "web",
                "--cwd",
                "/app",
                "--user",
                "1000",
                "--env",
                "TOKEN=a=b=c",
                "--deadline-secs",
                "15",
                "--stdout-budget-bytes",
                "4096",
                "--stderr-budget-bytes",
                "2048",
                "--json",
                "--",
                "/bin/sh",
                "-c",
                "echo --endpoint tcp://ignored",
            ]),
            no_env,
        )
        .unwrap() else {
            panic!("expected Run");
        };
        assert!(exec.json);
        let CliCommand::Exec { id, req } = exec.command else {
            panic!("expected Exec");
        };
        assert_eq!(id.as_str(), "sb-42");
        assert_eq!(
            req.target,
            ExecTarget::Container {
                id_or_name: "web".to_owned()
            }
        );
        assert_eq!(req.cwd.as_deref(), Some("/app"));
        assert_eq!(req.user.as_deref(), Some("1000"));
        assert_eq!(req.env.get("TOKEN").map(String::as_str), Some("a=b=c"));
        assert_eq!(req.deadline, Duration::from_secs(15));
        assert_eq!(req.stdout_budget_bytes, 4096);
        assert_eq!(req.stderr_budget_bytes, 2048);
        assert_eq!(
            req.argv,
            vec!["/bin/sh", "-c", "echo --endpoint tcp://ignored"]
        );

        let CliOutcome::Run(renew) =
            parse_args_with(&args(&["renew", "sb-42", "--ttl-secs", "120"]), no_env).unwrap()
        else {
            panic!("expected Run");
        };
        assert_eq!(
            renew.command,
            CliCommand::Renew {
                id: SandboxId::new("sb-42"),
                ttl: Duration::from_secs(120),
            }
        );

        let CliOutcome::Run(copy_in) = parse_args_with(
            &args(&["copy-in", "sb-42", "./src", "/workspace"]),
            no_env,
        )
        .unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(
            copy_in.command,
            CliCommand::CopyIn {
                id: SandboxId::new("sb-42"),
                src_host: PathBuf::from("./src"),
                dst_guest: "/workspace".to_owned(),
            }
        );

        let CliOutcome::Run(copy_out) = parse_args_with(
            &args(&["copy-out", "sb-42", "/workspace/out", "./dst"]),
            no_env,
        )
        .unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(
            copy_out.command,
            CliCommand::CopyOut {
                id: SandboxId::new("sb-42"),
                src_guest: "/workspace/out".to_owned(),
                dst_host: PathBuf::from("./dst"),
            }
        );

        let CliOutcome::Run(docker_ep) = parse_args_with(
            &args(&["docker-endpoint", "sb-42", "--allow-reaper-socket"]),
            no_env,
        )
        .unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(
            docker_ep.command,
            CliCommand::DockerEndpoint {
                id: SandboxId::new("sb-42"),
                allow_reaper_socket: true,
            }
        );

        let CliOutcome::Run(destroy) =
            parse_args_with(&args(&["destroy", "sb-42"]), no_env).unwrap()
        else {
            panic!("expected Run");
        };
        assert_eq!(
            destroy.command,
            CliCommand::Destroy {
                id: SandboxId::new("sb-42"),
            }
        );

        let CliOutcome::Run(tui_default) = parse_args_with(&args(&["tui"]), no_env).unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(
            tui_default.command,
            CliCommand::Tui {
                refresh_interval: Duration::from_millis(1000),
            }
        );

        let CliOutcome::Run(tui_fast) =
            parse_args_with(&args(&["tui", "--refresh-ms", "250"]), no_env).unwrap()
        else {
            panic!("expected Run");
        };
        assert_eq!(
            tui_fast.command,
            CliCommand::Tui {
                refresh_interval: Duration::from_millis(250),
            }
        );
        assert!(matches!(
            parse_args_with(&args(&["tui", "--refresh-ms", "50"]), no_env),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            parse_args_with(&args(&["--json", "tui"]), no_env),
            Err(SandboxError::InvalidSpec(_))
        ));

        let CliOutcome::Run(build_cmd) = parse_args_with(
            &args(&[
                "build",
                "sb-42",
                "-t",
                "demo:v1",
                "-f",
                "docker/Dockerfile",
                "--build-arg",
                "MODE=release",
                "--no-cache",
                "-o",
                "./demo.tar",
                "./app",
            ]),
            no_env,
        )
        .unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(
            build_cmd.command,
            CliCommand::Build {
                id: SandboxId::new("sb-42"),
                spec: Box::new(ImageBuildSpec {
                    context_dir: PathBuf::from("./app"),
                    dockerfile: Some("docker/Dockerfile".to_owned()),
                    tags: vec!["demo:v1".to_owned()],
                    build_args: vec![("MODE".to_owned(), "release".to_owned())],
                    target: None,
                    no_cache: true,
                    output_tar: Some(PathBuf::from("./demo.tar")),
                    deadline: Duration::from_secs(300),
                }),
            }
        );

        let CliOutcome::Run(compose_up) = parse_args_with(
            &args(&[
                "compose",
                "sb-42",
                "up",
                "-d",
                "-f",
                "compose.yaml",
                "-p",
                "stack1",
                "--build",
            ]),
            no_env,
        )
        .unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(
            compose_up.command,
            CliCommand::Compose {
                id: SandboxId::new("sb-42"),
                action: ComposeAction::Up {
                    file: Some(PathBuf::from("compose.yaml")),
                    project: Some("stack1".to_owned()),
                    build: true,
                    deadline: Duration::from_secs(300),
                },
            }
        );

        let CliOutcome::Run(compose_down) = parse_args_with(
            &args(&["compose", "sb-42", "down", "-p", "stack1", "-v"]),
            no_env,
        )
        .unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(
            compose_down.command,
            CliCommand::Compose {
                id: SandboxId::new("sb-42"),
                action: ComposeAction::Down {
                    file: None,
                    project: Some("stack1".to_owned()),
                    volumes: true,
                },
            }
        );
    }

    #[test]
    fn default_endpoint_matches_daemon_conventions() {
        let mut env_map = HashMap::new();
        env_map.insert(
            "MINIPOD_ENDPOINT",
            if cfg!(windows) {
                r"\\.\pipe\custom-ep".to_owned()
            } else {
                "/tmp/custom-ep.sock".to_owned()
            },
        );
        let ep = default_control_endpoint_with(&|k| env_map.get(k).cloned()).unwrap();
        if cfg!(windows) {
            assert_eq!(
                ep,
                ControlEndpoint::NamedPipe(r"\\.\pipe\custom-ep".to_owned())
            );
        } else {
            assert_eq!(
                ep,
                ControlEndpoint::UnixSocket(PathBuf::from("/tmp/custom-ep.sock"))
            );
        }

        // Empty MINIPOD_ENDPOINT falls back to OS default.
        let fallback = default_control_endpoint_with(&no_env).unwrap();
        fallback.validate().unwrap();
    }

    #[tokio::test]
    async fn execute_with_client_propagates_exec_exit_codes_and_runs_rpcs() {
        use sandbox_client::{
            read_control_frame, write_control_frame, ControlRequest, ControlResponse,
            DaemonStatusInfo, ExecWireEvent, SandboxSummaryInfo,
        };
        use sandbox_core::{CapabilityReport, SandboxLease};
        use tokio::io::duplex;

        let ep = if cfg!(windows) {
            ControlEndpoint::NamedPipe(r"\\.\pipe\cli-exec-test".to_owned())
        } else {
            ControlEndpoint::UnixSocket(PathBuf::from("/tmp/cli-exec-test.sock"))
        };

        let client = SandboxClient::with_connector(ep, |_| async move {
            let (c, mut s) = duplex(64 * 1024);
            tokio::spawn(async move {
                let raw = read_control_frame(&mut s).await.unwrap().unwrap();
                match ControlRequest::from_json_bytes(&raw).unwrap() {
                    ControlRequest::Status => {
                        let resp = ControlResponse::Status(DaemonStatusInfo {
                            active_sandboxes: 1,
                            warm_ready_vms: 2,
                            effective_host_rss_mb: 512,
                            reserved_host_storage_mb: 1024,
                            version: "0.1.0".to_owned(),
                        });
                        write_control_frame(&mut s, &resp.to_json_bytes().unwrap())
                            .await
                            .unwrap();
                    }
                    ControlRequest::ListSandboxes => {
                        let resp = ControlResponse::SandboxList {
                            sandboxes: vec![SandboxSummaryInfo {
                                id: SandboxId::new("sb-cli-1"),
                                pid: 1234,
                                alive: true,
                                network: NetworkPolicy::Isolated,
                                remaining_ttl_ms: 120_000,
                                live_rss_bytes: Some(200 * 1024 * 1024),
                                reserved_rss_mb: 256,
                                host_rss_budget_mb: Some(512),
                                host_storage_budget_mb: 1024,
                                docker_endpoint: None,
                                allow_reaper_socket: false,
                            }],
                        };
                        write_control_frame(&mut s, &resp.to_json_bytes().unwrap())
                            .await
                            .unwrap();
                    }
                    ControlRequest::Spawn { spec } => {
                        let resp = ControlResponse::Spawned(SandboxLease {
                            id: SandboxId::new("sb-cli-1"),
                            ttl: spec.lease_ttl,
                            capabilities: CapabilityReport {
                                cpu_quota: EnforcementLevel::HardLimit,
                                host_rss: EnforcementLevel::BestEffort,
                                host_storage: EnforcementLevel::HardLimit,
                                egress_filter: EnforcementLevel::HardLimit,
                            },
                        });
                        write_control_frame(&mut s, &resp.to_json_bytes().unwrap())
                            .await
                            .unwrap();
                    }
                    ControlRequest::ExecStart { req, .. } => {
                        write_control_frame(
                            &mut s,
                            &ControlResponse::ExecStarted { stream_id: 1 }
                                .to_json_bytes()
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                        let code = if req.argv.first().map(String::as_str) == Some("fail") {
                            Some(42)
                        } else {
                            Some(0)
                        };
                        write_control_frame(
                            &mut s,
                            &ExecWireEvent::Exit(ExecExitStatus {
                                code,
                                timed_out: false,
                                stdout_truncated: false,
                                stderr_truncated: false,
                            })
                            .to_json_bytes()
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                    }
                    ControlRequest::EnableDockerCompat { .. } => {
                        let resp = ControlResponse::DockerCompatEndpoint {
                            uri: "http://127.0.0.1:45678".to_owned(),
                        };
                        write_control_frame(&mut s, &resp.to_json_bytes().unwrap())
                            .await
                            .unwrap();
                    }
                    ControlRequest::Destroy { .. } => {
                        let resp = ControlResponse::Destroyed(DestroyStatus::AllResourcesCleaned);
                        write_control_frame(&mut s, &resp.to_json_bytes().unwrap())
                            .await
                            .unwrap();
                    }
                    other => panic!("unexpected test request: {other:?}"),
                }
            });
            Ok(c)
        });

        assert_eq!(
            execute_with_client(&client, true, CliCommand::Status)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            execute_with_client(&client, false, CliCommand::List)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            execute_with_client(&client, true, CliCommand::List)
                .await
                .unwrap(),
            0
        );
        let CliOutcome::Run(spawn) = parse_args_with(&args(&["spawn"]), no_env).unwrap() else {
            panic!("expected spawn");
        };
        assert_eq!(
            execute_with_client(&client, true, spawn.command)
                .await
                .unwrap(),
            0
        );

        let CliOutcome::Run(ok_exec) =
            parse_args_with(&args(&["exec", "sb-cli-1", "--", "ok"]), no_env).unwrap()
        else {
            panic!("expected exec");
        };
        assert_eq!(
            execute_with_client(&client, false, ok_exec.command)
                .await
                .unwrap(),
            0
        );

        let CliOutcome::Run(fail_exec) =
            parse_args_with(&args(&["exec", "sb-cli-1", "--", "fail"]), no_env).unwrap()
        else {
            panic!("expected exec");
        };
        assert_eq!(
            execute_with_client(&client, false, fail_exec.command)
                .await
                .unwrap(),
            42
        );

        assert_eq!(
            execute_with_client(
                &client,
                true,
                CliCommand::DockerEndpoint {
                    id: SandboxId::new("sb-cli-1"),
                    allow_reaper_socket: false,
                },
            )
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            execute_with_client(
                &client,
                true,
                CliCommand::Destroy {
                    id: SandboxId::new("sb-cli-1"),
                },
            )
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            exit_status_to_code(ExecExitStatus {
                code: Some(256),
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            }),
            1
        );
        assert_eq!(
            exit_status_to_code(ExecExitStatus {
                code: None,
                timed_out: true,
                stdout_truncated: false,
                stderr_truncated: false,
            }),
            124
        );
    }
}
