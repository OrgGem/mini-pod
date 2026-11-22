//! Interactive terminal UI (`sandbox-cli tui`) for sandbox VM and guest Podman container management.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

use crossterm::cursor::Show;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{Frame, Terminal};
use sandbox_client::{ControlEndpoint, DaemonStatusInfo, SandboxClient, SandboxSummaryInfo};
use sandbox_core::safe_tar::{apply_open_no_follow, is_symlink_or_reparse};
use sandbox_core::{
    AccelerationPolicy, ExecRequest, ExecTarget, IsolationMode, NetworkPolicy, ResourceBudget,
    SandboxError, SandboxId, SandboxSpec,
};
use serde_json::{json, Map, Value};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::cli::format_network_short;
use crate::compose::{
    compose_up_in_sandbox, docker_http_error, docker_json_request, extract_inspected_host_ports,
    format_container_list_ports, insert_port_bindings_json, load_compose_spec_from_path,
    parse_restart_policy_str, parse_short_port, percent_encode_component, split_shell_words,
    validate_safe_identifier,
};
use crate::image_build::{build_image_in_sandbox, validate_image_tag, ImageBuildSpec};

// shortcut: cap TUI output buffer at 500 lines, add disk transcript export if full history is needed
const MAX_OUTPUT_LINES: usize = 500;
const DEFAULT_RENEW_SECS: u64 = 300;
const EXEC_BUDGET_BYTES: u64 = 1024 * 1024;
const IMAGE_STREAM_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusPane {
    Sandboxes,
    Containers,
    Output,
}

impl FocusPane {
    pub fn next(self) -> Self {
        match self {
            Self::Sandboxes => Self::Containers,
            Self::Containers => Self::Output,
            Self::Output => Self::Sandboxes,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Sandboxes => Self::Output,
            Self::Containers => Self::Sandboxes,
            Self::Output => Self::Containers,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnPreset {
    WarmIsolated,
    ContainerIsolated,
    ContainerInternet,
}

impl SpawnPreset {
    pub const ALL: [Self; 3] = [
        Self::WarmIsolated,
        Self::ContainerIsolated,
        Self::ContainerInternet,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::WarmIsolated => {
                "[1] Warm-Pool Isolated  (1 vCPU, 256 MiB RAM, 512 MiB disk, 300s TTL)"
            }
            Self::ContainerIsolated => {
                "[2] Container Isolated  (2 vCPU, 768 MiB RAM, 1024 MiB disk, air-gapped)"
            }
            Self::ContainerInternet => {
                "[3] Container Internet  (2 vCPU, 768 MiB RAM, 1024 MiB disk, HostEgressProxy)"
            }
        }
    }

    pub fn to_spec(self) -> SandboxSpec {
        match self {
            Self::WarmIsolated => SandboxSpec {
                isolation: IsolationMode::VmRequired,
                acceleration: AccelerationPolicy::Preferred,
                network: NetworkPolicy::Isolated,
                budget: ResourceBudget {
                    guest_vcpus: 1,
                    host_cpu_quota_Millicores: None,
                    guest_ram_mb: 256,
                    host_rss_budget_mb: Some(512),
                    virtual_disk_mb: 512,
                    host_storage_budget_mb: 1024,
                },
                lease_ttl: Duration::from_secs(300),
            },
            Self::ContainerIsolated => SandboxSpec {
                isolation: IsolationMode::VmRequired,
                acceleration: AccelerationPolicy::Preferred,
                network: NetworkPolicy::Isolated,
                budget: ResourceBudget {
                    guest_vcpus: 2,
                    host_cpu_quota_Millicores: None,
                    guest_ram_mb: 768,
                    host_rss_budget_mb: Some(1024),
                    virtual_disk_mb: 1024,
                    host_storage_budget_mb: 2048,
                },
                lease_ttl: Duration::from_secs(600),
            },
            Self::ContainerInternet => SandboxSpec {
                isolation: IsolationMode::VmRequired,
                acceleration: AccelerationPolicy::Preferred,
                network: NetworkPolicy::InternetOnly,
                budget: ResourceBudget {
                    guest_vcpus: 2,
                    host_cpu_quota_Millicores: None,
                    guest_ram_mb: 768,
                    host_rss_budget_mb: Some(1024),
                    virtual_disk_mb: 1024,
                    host_storage_budget_mb: 2048,
                },
                lease_ttl: Duration::from_secs(600),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerRow {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub ports: String,
}

impl ContainerRow {
    pub fn is_running(&self) -> bool {
        self.state.eq_ignore_ascii_case("running")
            || self.status.to_ascii_lowercase().starts_with("up")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogTone {
    Info,
    Success,
    Warn,
    Error,
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputLine {
    pub tone: LogTone,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromptKind {
    GuestExec {
        sandbox_id: SandboxId,
    },
    ContainerExec {
        sandbox_id: SandboxId,
        container: String,
    },
    RunContainer {
        sandbox_id: SandboxId,
    },
    LoadImageTar {
        sandbox_id: SandboxId,
    },
    BuildImage {
        sandbox_id: SandboxId,
    },
    ComposeUp {
        sandbox_id: SandboxId,
    },
}

impl PromptKind {
    fn title(&self) -> String {
        match self {
            Self::GuestExec { sandbox_id } => {
                format!(" Execute Shell Command in Guest VM ({sandbox_id}) ")
            }
            Self::ContainerExec {
                sandbox_id,
                container,
            } => format!(" Execute Shell Command in Container '{container}' ({sandbox_id}) "),
            Self::RunContainer { sandbox_id } => {
                format!(" Run Detached Podman Container in {sandbox_id} (podman run -d ...) ")
            }
            Self::LoadImageTar { sandbox_id } => {
                format!(" Load Host OCI Image Tarball into {sandbox_id} (podman load) ")
            }
            Self::BuildImage { sandbox_id } => {
                format!(" Build Image from Host Folder + Dockerfile in {sandbox_id} ")
            }
            Self::ComposeUp { sandbox_id } => {
                format!(" Deploy Compose Stack (compose.yaml) into {sandbox_id} ")
            }
        }
    }

    fn hint(&self) -> &'static str {
        match self {
            Self::GuestExec { .. } => "Example: uname -a && podman images",
            Self::ContainerExec { .. } => "Example: id && ps aux",
            Self::RunContainer { .. } => {
                "Arguments passed to `podman run -d` (e.g. --name web -p 8080:8080 echo-http:latest)"
            }
            Self::LoadImageTar { .. } => {
                "Host file path to `docker save` / `podman save` .tar (e.g. .cache/test-images/echo-http.tar)"
            }
            Self::BuildImage { .. } => {
                "Enter `<context_dir> <image:tag>` (e.g. ./my-app my-app:latest)"
            }
            Self::ComposeUp { .. } => {
                "Host path to `compose.yaml` / `docker-compose.yml` (e.g. ./docker-compose.yml)"
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptState {
    pub kind: PromptKind,
    pub input: String,
    pub cursor_chars: usize,
}

impl PromptState {
    pub fn new(kind: PromptKind, initial: &str) -> Self {
        let cursor_chars = initial.chars().count();
        Self {
            kind,
            input: initial.to_owned(),
            cursor_chars,
        }
    }

    fn insert_char(&mut self, ch: char) {
        let byte_idx = char_to_byte_idx(&self.input, self.cursor_chars);
        self.input.insert(byte_idx, ch);
        self.cursor_chars += 1;
    }

    fn backspace(&mut self) {
        if self.cursor_chars == 0 {
            return;
        }
        let end = char_to_byte_idx(&self.input, self.cursor_chars);
        let start = char_to_byte_idx(&self.input, self.cursor_chars - 1);
        self.input.replace_range(start..end, "");
        self.cursor_chars -= 1;
    }

    fn delete_forward(&mut self) {
        let total = self.input.chars().count();
        if self.cursor_chars >= total {
            return;
        }
        let start = char_to_byte_idx(&self.input, self.cursor_chars);
        let end = char_to_byte_idx(&self.input, self.cursor_chars + 1);
        self.input.replace_range(start..end, "");
    }
}

fn char_to_byte_idx(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(idx, _)| idx)
        .unwrap_or(s.len())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmAction {
    DestroySandbox {
        id: SandboxId,
    },
    RemoveContainer {
        sandbox_id: SandboxId,
        container_id: String,
        container_name: String,
    },
}

impl ConfirmAction {
    fn prompt_message(&self) -> String {
        match self {
            Self::DestroySandbox { id } => format!(
                "Destroy sandbox '{id}' and terminate all containers inside it?\n\nPress [y] or [Enter] to confirm, [n] or [Esc] to cancel."
            ),
            Self::RemoveContainer {
                sandbox_id,
                container_id,
                container_name,
            } => format!(
                "Force-remove container '{container_name}' ({container_id}) in '{sandbox_id}'?\n\nPress [y] or [Enter] to confirm, [n] or [Esc] to cancel."
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Modal {
    Spawn { selected: usize },
    DockerCompat { sandbox_id: SandboxId, selected: usize },
    Prompt(PromptState),
    Confirm(ConfirmAction),
    Help,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TuiCommand {
    RefreshAll {
        also_containers_for: Option<SandboxId>,
    },
    RefreshContainers {
        sandbox_id: SandboxId,
    },
    Spawn {
        preset: SpawnPreset,
    },
    RenewLease {
        sandbox_id: SandboxId,
        ttl_secs: u64,
    },
    EnableDockerCompat {
        sandbox_id: SandboxId,
        allow_reaper_socket: bool,
    },
    DestroySandbox {
        sandbox_id: SandboxId,
    },
    GuestExec {
        sandbox_id: SandboxId,
        shell_cmd: String,
    },
    ContainerExec {
        sandbox_id: SandboxId,
        container: String,
        shell_cmd: String,
    },
    RunContainer {
        sandbox_id: SandboxId,
        run_args: String,
    },
    LoadImageTar {
        sandbox_id: SandboxId,
        host_tar_path: PathBuf,
    },
    BuildImage {
        sandbox_id: SandboxId,
        context_dir: PathBuf,
        tag: String,
    },
    ComposeUp {
        sandbox_id: SandboxId,
        compose_path: PathBuf,
    },
    ToggleContainerState {
        sandbox_id: SandboxId,
        container_id: String,
        currently_running: bool,
    },
    ContainerLogs {
        sandbox_id: SandboxId,
        container_id: String,
    },
    RemoveContainer {
        sandbox_id: SandboxId,
        container_id: String,
    },
}

#[derive(Clone, Debug)]
pub enum BgEvent {
    Snapshot {
        status: Result<DaemonStatusInfo, String>,
        sandboxes: Result<Vec<SandboxSummaryInfo>, String>,
    },
    ContainersLoaded {
        sandbox_id: SandboxId,
        result: Result<Vec<ContainerRow>, String>,
    },
    ActionFinished {
        busy_done: bool,
        headline: OutputLine,
        stdout: String,
        stderr: String,
        refresh_all: bool,
        refresh_containers_for: Option<SandboxId>,
        select_sandbox: Option<SandboxId>,
    },
}

pub struct TuiApp {
    pub endpoint_label: String,
    pub focus: FocusPane,
    pub daemon_status: Option<DaemonStatusInfo>,
    pub daemon_error: Option<String>,
    pub sandboxes: Vec<SandboxSummaryInfo>,
    pub selected_sandbox: usize,
    pub containers_by_sandbox: HashMap<SandboxId, Vec<ContainerRow>>,
    pub container_errors: HashMap<SandboxId, String>,
    pub selected_container: usize,
    pub output: VecDeque<OutputLine>,
    pub output_scroll_from_bottom: usize,
    pub modal: Option<Modal>,
    pub busy_label: Option<String>,
    pub pending_select_sandbox: Option<SandboxId>,
    pub poll_in_flight: bool,
    pub should_quit: bool,
}

impl TuiApp {
    pub fn new(endpoint_label: String) -> Self {
        let mut app = Self {
            endpoint_label,
            focus: FocusPane::Sandboxes,
            daemon_status: None,
            daemon_error: None,
            sandboxes: Vec::new(),
            selected_sandbox: 0,
            containers_by_sandbox: HashMap::new(),
            container_errors: HashMap::new(),
            selected_container: 0,
            output: VecDeque::new(),
            output_scroll_from_bottom: 0,
            modal: None,
            busy_label: None,
            pending_select_sandbox: None,
            poll_in_flight: false,
            should_quit: false,
        };
        app.push_log(
            LogTone::Info,
            "Ready. Press [s] to spawn a sandbox, [c] to inspect containers, [?] for all shortcuts.",
        );
        app
    }

    pub fn current_sandbox(&self) -> Option<&SandboxSummaryInfo> {
        self.sandboxes.get(self.selected_sandbox)
    }

    pub fn current_containers(&self) -> Option<&[ContainerRow]> {
        let sb = self.current_sandbox()?;
        self.containers_by_sandbox.get(&sb.id).map(Vec::as_slice)
    }

    pub fn current_container(&self) -> Option<&ContainerRow> {
        self.current_containers()?.get(self.selected_container)
    }

    pub fn push_log(&mut self, tone: LogTone, text: impl Into<String>) {
        let raw = sanitize_terminal_text(&text.into());
        for line in raw.lines() {
            if self.output.len() >= MAX_OUTPUT_LINES {
                self.output.pop_front();
            }
            self.output.push_back(OutputLine {
                tone,
                text: line.to_owned(),
            });
        }
        if raw.is_empty() {
            if self.output.len() >= MAX_OUTPUT_LINES {
                self.output.pop_front();
            }
            self.output.push_back(OutputLine {
                tone,
                text: String::new(),
            });
        }
        self.output_scroll_from_bottom = 0;
    }

    fn clamp_selections(&mut self) {
        if self.sandboxes.is_empty() {
            self.selected_sandbox = 0;
            self.selected_container = 0;
            return;
        }
        if self.selected_sandbox >= self.sandboxes.len() {
            self.selected_sandbox = self.sandboxes.len() - 1;
        }
        let ctr_len = self.current_containers().map_or(0, <[ContainerRow]>::len);
        if ctr_len == 0 {
            self.selected_container = 0;
        } else if self.selected_container >= ctr_len {
            self.selected_container = ctr_len - 1;
        }
    }

    /// Processes a terminal event, filtering out Windows key-release/repeat duplicates.
    pub fn handle_event(&mut self, ev: Event) -> Option<TuiCommand> {
        let Event::Key(key) = ev else {
            return None;
        };
        if key.kind != KeyEventKind::Press {
            return None;
        }
        self.handle_key_press(key)
    }

    pub fn handle_key_press(&mut self, key: KeyEvent) -> Option<TuiCommand> {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            self.should_quit = true;
            return None;
        }

        if let Some(modal) = self.modal.take() {
            return self.handle_modal_key(modal, key);
        }

        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
                None
            }
            KeyCode::Char('?') | KeyCode::F(1) => {
                self.modal = Some(Modal::Help);
                None
            }
            KeyCode::Tab => {
                self.focus = self.focus.next();
                self.maybe_autoload_containers_on_focus()
            }
            KeyCode::BackTab => {
                self.focus = self.focus.prev();
                self.maybe_autoload_containers_on_focus()
            }
            KeyCode::Char('1') => {
                self.focus = FocusPane::Sandboxes;
                None
            }
            KeyCode::Char('2') => {
                self.focus = FocusPane::Containers;
                self.maybe_autoload_containers_on_focus()
            }
            KeyCode::Char('3') => {
                self.focus = FocusPane::Output;
                None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_up(1);
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_down(1);
                None
            }
            KeyCode::PageUp => {
                self.scroll_output_up(10);
                None
            }
            KeyCode::PageDown => {
                self.scroll_output_down(10);
                None
            }
            KeyCode::Enter if self.focus == FocusPane::Sandboxes => {
                let id = self.current_sandbox().map(|s| s.id.clone())?;
                self.focus = FocusPane::Containers;
                self.busy_label = Some(format!("Inspecting containers in {id}..."));
                Some(TuiCommand::RefreshContainers { sandbox_id: id })
            }
            KeyCode::Char('R') => {
                let ctr_target = self.current_sandbox().map(|s| s.id.clone());
                self.busy_label = Some("Refreshing daemon & sandboxes...".to_owned());
                Some(TuiCommand::RefreshAll {
                    also_containers_for: ctr_target,
                })
            }
            KeyCode::Char('s') => {
                self.modal = Some(Modal::Spawn { selected: 0 });
                None
            }
            KeyCode::Char('r') => {
                let Some(sb) = self.current_sandbox() else {
                    self.push_log(LogTone::Warn, "No active sandbox selected to renew lease.");
                    return None;
                };
                let id = sb.id.clone();
                self.busy_label = Some(format!("Renewing lease for {id}..."));
                Some(TuiCommand::RenewLease {
                    sandbox_id: id,
                    ttl_secs: DEFAULT_RENEW_SECS,
                })
            }
            KeyCode::Char('d') => {
                let Some(sb) = self.current_sandbox() else {
                    self.push_log(
                        LogTone::Warn,
                        "No active sandbox selected to enable Docker endpoint.",
                    );
                    return None;
                };
                let selected = usize::from(sb.allow_reaper_socket);
                self.modal = Some(Modal::DockerCompat {
                    sandbox_id: sb.id.clone(),
                    selected,
                });
                None
            }
            KeyCode::Char('e') => {
                let Some(sb) = self.current_sandbox() else {
                    self.push_log(LogTone::Warn, "No active sandbox selected for guest exec.");
                    return None;
                };
                self.modal = Some(Modal::Prompt(PromptState::new(
                    PromptKind::GuestExec {
                        sandbox_id: sb.id.clone(),
                    },
                    "",
                )));
                None
            }
            KeyCode::Char('c') => {
                let Some(sb) = self.current_sandbox() else {
                    self.push_log(
                        LogTone::Warn,
                        "No active sandbox selected to list containers.",
                    );
                    return None;
                };
                let id = sb.id.clone();
                self.busy_label = Some(format!("Listing Podman containers in {id}..."));
                Some(TuiCommand::RefreshContainers { sandbox_id: id })
            }
            KeyCode::Char('n') => {
                let Some(sb) = self.current_sandbox() else {
                    self.push_log(
                        LogTone::Warn,
                        "Spawn or select a sandbox first before running a container.",
                    );
                    return None;
                };
                self.modal = Some(Modal::Prompt(PromptState::new(
                    PromptKind::RunContainer {
                        sandbox_id: sb.id.clone(),
                    },
                    "",
                )));
                None
            }
            KeyCode::Char('i') => {
                let Some(sb) = self.current_sandbox() else {
                    self.push_log(
                        LogTone::Warn,
                        "Select a sandbox first before loading an OCI .tar image.",
                    );
                    return None;
                };
                self.modal = Some(Modal::Prompt(PromptState::new(
                    PromptKind::LoadImageTar {
                        sandbox_id: sb.id.clone(),
                    },
                    "",
                )));
                None
            }
            KeyCode::Char('b') => {
                let Some(sb) = self.current_sandbox() else {
                    self.push_log(
                        LogTone::Warn,
                        "Select a sandbox first before building a Dockerfile image.",
                    );
                    return None;
                };
                self.modal = Some(Modal::Prompt(PromptState::new(
                    PromptKind::BuildImage {
                        sandbox_id: sb.id.clone(),
                    },
                    "",
                )));
                None
            }
            KeyCode::Char('C') => {
                let Some(sb) = self.current_sandbox() else {
                    self.push_log(
                        LogTone::Warn,
                        "Select a sandbox first before deploying a Compose stack.",
                    );
                    return None;
                };
                self.modal = Some(Modal::Prompt(PromptState::new(
                    PromptKind::ComposeUp {
                        sandbox_id: sb.id.clone(),
                    },
                    "",
                )));
                None
            }
            KeyCode::Char('x') => {
                let Some(sb) = self.current_sandbox() else {
                    self.push_log(LogTone::Warn, "No sandbox selected.");
                    return None;
                };
                let Some(ctr) = self.current_container() else {
                    self.push_log(
                        LogTone::Warn,
                        "No container selected. Press [c] to load containers or [n] to run one.",
                    );
                    return None;
                };
                self.modal = Some(Modal::Prompt(PromptState::new(
                    PromptKind::ContainerExec {
                        sandbox_id: sb.id.clone(),
                        container: ctr.name.clone(),
                    },
                    "",
                )));
                None
            }
            KeyCode::Char('l') => {
                let Some(sb) = self.current_sandbox() else {
                    self.push_log(LogTone::Warn, "No sandbox selected.");
                    return None;
                };
                let Some(ctr) = self.current_container() else {
                    self.push_log(
                        LogTone::Warn,
                        "No container selected. Press [c] to refresh containers.",
                    );
                    return None;
                };
                let sb_id = sb.id.clone();
                let ctr_id = ctr.id.clone();
                self.busy_label = Some(format!("Fetching logs for container {ctr_id}..."));
                Some(TuiCommand::ContainerLogs {
                    sandbox_id: sb_id,
                    container_id: ctr_id,
                })
            }
            KeyCode::Char('S') => {
                let Some(sb) = self.current_sandbox() else {
                    self.push_log(LogTone::Warn, "No sandbox selected.");
                    return None;
                };
                let Some(ctr) = self.current_container() else {
                    self.push_log(
                        LogTone::Warn,
                        "No container selected. Press [c] to refresh containers.",
                    );
                    return None;
                };
                let sb_id = sb.id.clone();
                let ctr_id = ctr.id.clone();
                let running = ctr.is_running();
                let verb = if running { "Stopping" } else { "Starting" };
                self.busy_label = Some(format!("{verb} container {ctr_id}..."));
                Some(TuiCommand::ToggleContainerState {
                    sandbox_id: sb_id,
                    container_id: ctr_id,
                    currently_running: running,
                })
            }
            KeyCode::Char('X') => self.open_remove_container_confirm(),
            KeyCode::Char('D') => self.open_destroy_sandbox_confirm(),
            KeyCode::Delete => match self.focus {
                FocusPane::Containers => self.open_remove_container_confirm(),
                FocusPane::Sandboxes | FocusPane::Output => self.open_destroy_sandbox_confirm(),
            },
            _ => None,
        }
    }

    fn open_destroy_sandbox_confirm(&mut self) -> Option<TuiCommand> {
        let Some(sb) = self.current_sandbox() else {
            self.push_log(LogTone::Warn, "No active sandbox selected to destroy.");
            return None;
        };
        self.modal = Some(Modal::Confirm(ConfirmAction::DestroySandbox {
            id: sb.id.clone(),
        }));
        None
    }

    fn open_remove_container_confirm(&mut self) -> Option<TuiCommand> {
        let Some(sb) = self.current_sandbox() else {
            self.push_log(LogTone::Warn, "No sandbox selected.");
            return None;
        };
        let Some(ctr) = self.current_container() else {
            self.push_log(
                LogTone::Warn,
                "No container selected to remove. Press [c] to refresh containers.",
            );
            return None;
        };
        self.modal = Some(Modal::Confirm(ConfirmAction::RemoveContainer {
            sandbox_id: sb.id.clone(),
            container_id: ctr.id.clone(),
            container_name: ctr.name.clone(),
        }));
        None
    }

    fn maybe_autoload_containers_on_focus(&mut self) -> Option<TuiCommand> {
        if self.focus != FocusPane::Containers {
            return None;
        }
        let sb = self.current_sandbox()?;
        if self.containers_by_sandbox.contains_key(&sb.id) {
            return None;
        }
        let id = sb.id.clone();
        self.busy_label = Some(format!("Inspecting containers in {id}..."));
        Some(TuiCommand::RefreshContainers { sandbox_id: id })
    }

    fn move_up(&mut self, step: usize) {
        match self.focus {
            FocusPane::Sandboxes => {
                self.selected_sandbox = self.selected_sandbox.saturating_sub(step);
                self.clamp_selections();
            }
            FocusPane::Containers => {
                self.selected_container = self.selected_container.saturating_sub(step);
                self.clamp_selections();
            }
            FocusPane::Output => self.scroll_output_up(step),
        }
    }

    fn move_down(&mut self, step: usize) {
        match self.focus {
            FocusPane::Sandboxes => {
                if !self.sandboxes.is_empty() {
                    self.selected_sandbox =
                        (self.selected_sandbox + step).min(self.sandboxes.len() - 1);
                }
                self.clamp_selections();
            }
            FocusPane::Containers => {
                let len = self.current_containers().map_or(0, <[ContainerRow]>::len);
                if len > 0 {
                    self.selected_container = (self.selected_container + step).min(len - 1);
                }
            }
            FocusPane::Output => self.scroll_output_down(step),
        }
    }

    fn scroll_output_up(&mut self, step: usize) {
        let max_scroll = self.output.len().saturating_sub(1);
        self.output_scroll_from_bottom =
            (self.output_scroll_from_bottom + step).min(max_scroll);
    }

    fn scroll_output_down(&mut self, step: usize) {
        self.output_scroll_from_bottom = self.output_scroll_from_bottom.saturating_sub(step);
    }

    fn handle_modal_key(&mut self, modal: Modal, key: KeyEvent) -> Option<TuiCommand> {
        match modal {
            Modal::Help => {
                if !matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char('?')
                ) {
                    self.modal = Some(Modal::Help);
                }
                None
            }
            Modal::Spawn { mut selected } => match key.code {
                KeyCode::Esc => None,
                KeyCode::Up | KeyCode::Char('k') => {
                    selected = selected.saturating_sub(1);
                    self.modal = Some(Modal::Spawn { selected });
                    None
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    selected = (selected + 1).min(SpawnPreset::ALL.len() - 1);
                    self.modal = Some(Modal::Spawn { selected });
                    None
                }
                KeyCode::Char('1') => self.trigger_spawn(SpawnPreset::WarmIsolated),
                KeyCode::Char('2') => self.trigger_spawn(SpawnPreset::ContainerIsolated),
                KeyCode::Char('3') => self.trigger_spawn(SpawnPreset::ContainerInternet),
                KeyCode::Enter => self.trigger_spawn(SpawnPreset::ALL[selected]),
                _ => {
                    self.modal = Some(Modal::Spawn { selected });
                    None
                }
            },
            Modal::DockerCompat {
                sandbox_id,
                mut selected,
            } => match key.code {
                KeyCode::Esc => None,
                KeyCode::Up | KeyCode::Down | KeyCode::Char('k') | KeyCode::Char('j') => {
                    selected = 1 - (selected & 1);
                    self.modal = Some(Modal::DockerCompat {
                        sandbox_id,
                        selected,
                    });
                    None
                }
                KeyCode::Char('1') => self.trigger_docker_compat(sandbox_id, false),
                KeyCode::Char('2') => self.trigger_docker_compat(sandbox_id, true),
                KeyCode::Enter => self.trigger_docker_compat(sandbox_id, selected == 1),
                _ => {
                    self.modal = Some(Modal::DockerCompat {
                        sandbox_id,
                        selected,
                    });
                    None
                }
            },
            Modal::Confirm(action) => match key.code {
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => None,
                KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => match action {
                    ConfirmAction::DestroySandbox { id } => {
                        self.busy_label = Some(format!("Destroying sandbox {id}..."));
                        Some(TuiCommand::DestroySandbox { sandbox_id: id })
                    }
                    ConfirmAction::RemoveContainer {
                        sandbox_id,
                        container_id,
                        ..
                    } => {
                        self.busy_label = Some(format!("Removing container {container_id}..."));
                        Some(TuiCommand::RemoveContainer {
                            sandbox_id,
                            container_id,
                        })
                    }
                },
                _ => {
                    self.modal = Some(Modal::Confirm(action));
                    None
                }
            },
            Modal::Prompt(mut prompt) => match key.code {
                KeyCode::Esc => None,
                KeyCode::Left => {
                    prompt.cursor_chars = prompt.cursor_chars.saturating_sub(1);
                    self.modal = Some(Modal::Prompt(prompt));
                    None
                }
                KeyCode::Right => {
                    let max = prompt.input.chars().count();
                    prompt.cursor_chars = (prompt.cursor_chars + 1).min(max);
                    self.modal = Some(Modal::Prompt(prompt));
                    None
                }
                KeyCode::Home => {
                    prompt.cursor_chars = 0;
                    self.modal = Some(Modal::Prompt(prompt));
                    None
                }
                KeyCode::End => {
                    prompt.cursor_chars = prompt.input.chars().count();
                    self.modal = Some(Modal::Prompt(prompt));
                    None
                }
                KeyCode::Backspace => {
                    prompt.backspace();
                    self.modal = Some(Modal::Prompt(prompt));
                    None
                }
                KeyCode::Delete => {
                    prompt.delete_forward();
                    self.modal = Some(Modal::Prompt(prompt));
                    None
                }
                KeyCode::Enter => {
                    let trimmed = prompt.input.trim().to_owned();
                    if trimmed.is_empty() {
                        self.push_log(LogTone::Warn, "Command/input was empty; cancelled.");
                        return None;
                    }
                    match prompt.kind {
                        PromptKind::GuestExec { sandbox_id } => {
                            self.busy_label =
                                Some(format!("Running guest command in {sandbox_id}..."));
                            Some(TuiCommand::GuestExec {
                                sandbox_id,
                                shell_cmd: trimmed,
                            })
                        }
                        PromptKind::ContainerExec {
                            sandbox_id,
                            container,
                        } => {
                            self.busy_label = Some(format!(
                                "Running command in container '{container}' ({sandbox_id})..."
                            ));
                            Some(TuiCommand::ContainerExec {
                                sandbox_id,
                                container,
                                shell_cmd: trimmed,
                            })
                        }
                        PromptKind::RunContainer { sandbox_id } => {
                            self.busy_label =
                                Some(format!("Starting container in {sandbox_id}..."));
                            Some(TuiCommand::RunContainer {
                                sandbox_id,
                                run_args: trimmed,
                            })
                        }
                        PromptKind::LoadImageTar { sandbox_id } => {
                            let unquoted = trimmed
                                .trim_matches('"')
                                .trim_matches('\'')
                                .trim()
                                .to_owned();
                            if unquoted.is_empty() {
                                self.push_log(LogTone::Warn, "Archive path was empty; cancelled.");
                                return None;
                            }
                            self.busy_label =
                                Some(format!("Streaming OCI image tar into {sandbox_id}..."));
                            Some(TuiCommand::LoadImageTar {
                                sandbox_id,
                                host_tar_path: PathBuf::from(unquoted),
                            })
                        }
                        PromptKind::BuildImage { sandbox_id } => {
                            let tokens = match split_shell_words(&trimmed) {
                                Ok(t) => t,
                                Err(err) => {
                                    self.push_log(LogTone::Error, format!("Invalid input: {err}"));
                                    return None;
                                }
                            };
                            if tokens.len() != 2 {
                                self.push_log(
                                    LogTone::Warn,
                                    "Expected `<context_dir> <image:tag>` (quote path if it contains spaces).",
                                );
                                return None;
                            }
                            self.busy_label = Some(format!(
                                "Building image '{}' in {sandbox_id}...",
                                tokens[1]
                            ));
                            Some(TuiCommand::BuildImage {
                                sandbox_id,
                                context_dir: PathBuf::from(&tokens[0]),
                                tag: tokens[1].clone(),
                            })
                        }
                        PromptKind::ComposeUp { sandbox_id } => {
                            let unquoted = trimmed
                                .trim_matches('"')
                                .trim_matches('\'')
                                .trim()
                                .to_owned();
                            if unquoted.is_empty() {
                                self.push_log(LogTone::Warn, "Compose path was empty; cancelled.");
                                return None;
                            }
                            let mut path = PathBuf::from(&unquoted);
                            if path.is_dir() {
                                for candidate in [
                                    "compose.yaml",
                                    "compose.yml",
                                    "docker-compose.yml",
                                    "docker-compose.yaml",
                                ] {
                                    if path.join(candidate).is_file() {
                                        path = path.join(candidate);
                                        break;
                                    }
                                }
                            }
                            self.busy_label =
                                Some(format!("Deploying Compose stack into {sandbox_id}..."));
                            Some(TuiCommand::ComposeUp {
                                sandbox_id,
                                compose_path: path,
                            })
                        }
                    }
                }
                KeyCode::Char(ch)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && !key.modifiers.contains(KeyModifiers::ALT) =>
                {
                    prompt.insert_char(ch);
                    self.modal = Some(Modal::Prompt(prompt));
                    None
                }
                _ => {
                    self.modal = Some(Modal::Prompt(prompt));
                    None
                }
            },
        }
    }

    fn trigger_spawn(&mut self, preset: SpawnPreset) -> Option<TuiCommand> {
        self.busy_label = Some(format!("Spawning sandbox ({:?})...", preset));
        Some(TuiCommand::Spawn { preset })
    }

    fn trigger_docker_compat(
        &mut self,
        sandbox_id: SandboxId,
        allow_reaper_socket: bool,
    ) -> Option<TuiCommand> {
        self.busy_label = Some(format!("Binding Docker API endpoint for {sandbox_id}..."));
        Some(TuiCommand::EnableDockerCompat {
            sandbox_id,
            allow_reaper_socket,
        })
    }

    /// Applies an asynchronous background worker result and returns any follow-up command.
    pub fn apply_bg_event(&mut self, ev: BgEvent) -> Option<TuiCommand> {
        match ev {
            BgEvent::Snapshot { status, sandboxes } => {
                self.poll_in_flight = false;
                let prev_selected_id = self.current_sandbox().map(|s| s.id.clone());

                match status {
                    Ok(info) => {
                        self.daemon_status = Some(info);
                        self.daemon_error = None;
                    }
                    Err(err) => {
                        self.daemon_error = Some(err);
                    }
                }

                if let Ok(list) = sandboxes {
                    let live_ids: std::collections::HashSet<SandboxId> =
                        list.iter().map(|s| s.id.clone()).collect();
                    self.containers_by_sandbox
                        .retain(|k, _| live_ids.contains(k));
                    self.container_errors.retain(|k, _| live_ids.contains(k));
                    self.sandboxes = list;
                    let preferred_id = self.pending_select_sandbox.take().or(prev_selected_id);
                    if let Some(target_id) = preferred_id {
                        if let Some(pos) = self.sandboxes.iter().position(|s| s.id == target_id) {
                            self.selected_sandbox = pos;
                        }
                    }
                    self.clamp_selections();
                }
                None
            }
            BgEvent::ContainersLoaded { sandbox_id, result } => {
                self.busy_label = None;
                match result {
                    Ok(rows) => {
                        self.container_errors.remove(&sandbox_id);
                        self.containers_by_sandbox.insert(sandbox_id, rows);
                        self.clamp_selections();
                    }
                    Err(err) => {
                        self.push_log(
                            LogTone::Error,
                            format!("[{sandbox_id}] Failed listing containers: {err}"),
                        );
                        self.container_errors.insert(sandbox_id, err);
                    }
                }
                None
            }
            BgEvent::ActionFinished {
                busy_done,
                headline,
                stdout,
                stderr,
                refresh_all,
                refresh_containers_for,
                select_sandbox,
            } => {
                if busy_done {
                    self.busy_label = None;
                }
                self.push_log(headline.tone, headline.text);
                if !stdout.trim().is_empty() {
                    self.push_log(LogTone::Stdout, stdout.trim_end_matches(['\r', '\n']));
                }
                if !stderr.trim().is_empty() {
                    self.push_log(LogTone::Stderr, stderr.trim_end_matches(['\r', '\n']));
                }
                if let Some(target_id) = select_sandbox {
                    if let Some(pos) = self.sandboxes.iter().position(|s| s.id == target_id) {
                        self.selected_sandbox = pos;
                    } else {
                        self.pending_select_sandbox = Some(target_id);
                    }
                }
                if refresh_all {
                    return Some(TuiCommand::RefreshAll {
                        also_containers_for: refresh_containers_for,
                    });
                }
                if let Some(sb_id) = refresh_containers_for {
                    return Some(TuiCommand::RefreshContainers { sandbox_id: sb_id });
                }
                None
            }
        }
    }
}

/// Parses tab-separated output from `podman ps -a --noheading --format "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}"`.
pub fn parse_podman_ps_tsv(raw: &str) -> Vec<ContainerRow> {
    let mut rows = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(6, '\t');
        let id = parts.next().unwrap_or("").trim().to_owned();
        if id.is_empty() {
            continue;
        }
        let name_raw = parts.next().unwrap_or("").trim();
        let name = if name_raw.is_empty() {
            id.clone()
        } else {
            name_raw.to_owned()
        };
        let image = parts.next().unwrap_or("-").trim().to_owned();
        let state = parts.next().unwrap_or("unknown").trim().to_owned();
        let status = parts.next().unwrap_or("").trim().to_owned();
        let ports_raw = parts.next().unwrap_or("").trim();
        let ports = if ports_raw.is_empty() {
            "-".to_owned()
        } else {
            ports_raw.to_owned()
        };
        rows.push(ContainerRow {
            id: sanitize_terminal_text(&id),
            name: sanitize_terminal_text(&name),
            image: sanitize_terminal_text(&image),
            state: sanitize_terminal_text(&state),
            status: sanitize_terminal_text(&status),
            ports: sanitize_terminal_text(&ports),
        });
    }
    rows
}

/// Strips ANSI CSI/OSC escape sequences and raw C0/C1 control characters from untrusted text.
pub fn sanitize_terminal_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    let _ = chars.next();
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    let _ = chars.next();
                    while let Some(c) = chars.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && chars.peek() == Some(&'\\') {
                            let _ = chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    let _ = chars.next();
                }
                None => {}
            }
            continue;
        }
        if ch == '\n' || ch == '\t' || !ch.is_control() {
            out.push(ch);
        }
    }
    out
}

/// Renders the complete TUI frame (used both by the live Crossterm loop and headless `TestBackend` tests).
pub fn draw_ui(f: &mut Frame<'_>, app: &TuiApp) {
    let root = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(9),
            Constraint::Length(10),
            Constraint::Length(2),
        ])
        .split(root);

    draw_header(f, app, chunks[0]);

    let mid_chunks = if root.width >= 100 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
            .split(chunks[1])
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[1])
    };

    draw_sandboxes_pane(f, app, mid_chunks[0]);
    draw_containers_pane(f, app, mid_chunks[1]);
    draw_output_pane(f, app, chunks[2]);
    draw_footer(f, app, chunks[3]);

    if let Some(ref modal) = app.modal {
        draw_modal(f, modal, root);
    }
}

fn draw_header(f: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let (conn_span, metrics_line) = match (&app.daemon_status, &app.daemon_error) {
        (_, Some(err)) => (
            Span::styled(
                format!(" DISCONNECTED ({err}) "),
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ),
            "Daemon unreachable — start `sandboxd serve` in another terminal or pass `--endpoint`."
                .to_owned(),
        ),
        (Some(st), None) => (
            Span::styled(
                format!(" CONNECTED v{} ", st.version),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            format!(
                "Active VMs: {}   |   Warm Pool Ready: {}   |   Effective Host RSS: {} MiB   |   Reserved Disk: {} MiB",
                st.active_sandboxes,
                st.warm_ready_vms,
                st.effective_host_rss_mb,
                st.reserved_host_storage_mb,
            ),
        ),
        (None, None) => (
            Span::styled(
                " CONNECTING... ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            "Querying sandboxd status...".to_owned(),
        ),
    };

    let activity_span = match &app.busy_label {
        Some(msg) => Span::styled(
            format!("  [BUSY: {msg}]"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        None => Span::styled("  [IDLE]", Style::default().fg(Color::DarkGray)),
    };

    let lines = vec![
        Line::from(vec![
            conn_span,
            Span::raw("  Endpoint: "),
            Span::styled(&app.endpoint_label, Style::default().fg(Color::Cyan)),
            activity_span,
        ]),
        Line::from(Span::raw(metrics_line)),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" mini-pod Container Sandbox Console ")
        .border_style(Style::default().fg(Color::Cyan));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_sandboxes_pane(f: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let focused = app.focus == FocusPane::Sandboxes;
    let border_color = if focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let title = format!(" [1] Sandboxes ({}) ", app.sandboxes.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(border_color));

    if app.sandboxes.is_empty() {
        let hint = Paragraph::new(
            "No active sandboxes.\n\nPress [s] to spawn a micro-VM sandbox (Warm-Pool Isolated or Container preset).",
        )
        .style(Style::default().fg(Color::DarkGray))
        .wrap(Wrap { trim: true })
        .block(block);
        f.render_widget(hint, area);
        return;
    }

    let header = Row::new(vec!["ID", "PID", "NET", "RSS(MiB)", "TTL", "DOCKER"])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    let rows: Vec<Row<'_>> = app
        .sandboxes
        .iter()
        .map(|sb| {
            let rss = match (sb.live_rss_bytes, sb.host_rss_budget_mb) {
                (Some(b), Some(cap)) => format!("{}/{}", b.div_ceil(1024 * 1024), cap),
                (Some(b), None) => format!("{}", b.div_ceil(1024 * 1024)),
                (None, Some(cap)) => format!("-/{cap}"),
                (None, None) => "-".to_owned(),
            };
            let ttl_secs = sb.remaining_ttl_ms / 1000;
            let ttl_style = if ttl_secs < 30 {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let docker_lbl = match (&sb.docker_endpoint, sb.allow_reaper_socket) {
                (Some(_), true) => "ready+ryuk",
                (Some(_), false) => "ready",
                (None, _) => "-",
            };
            Row::new(vec![
                Cell::from(sb.id.as_str().to_owned()),
                Cell::from(sb.pid.to_string()),
                Cell::from(format_network_short(&sb.network)),
                Cell::from(rss),
                Cell::from(format!("{ttl_secs}s")).style(ttl_style),
                Cell::from(docker_lbl),
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(14),
        Constraint::Length(7),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(7),
        Constraint::Length(11),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(
            Style::default()
                .bg(if focused {
                    Color::Blue
                } else {
                    Color::DarkGray
                })
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = TableState::default().with_selected(Some(app.selected_sandbox));
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_containers_pane(f: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let focused = app.focus == FocusPane::Containers;
    let border_color = if focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let sb_title = app
        .current_sandbox()
        .map_or_else(|| "none".to_owned(), |s| s.id.as_str().to_owned());
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" [2] Guest Containers ({sb_title}) "))
        .border_style(Style::default().fg(border_color));

    let Some(sb) = app.current_sandbox() else {
        f.render_widget(
            Paragraph::new("Select or spawn a sandbox to manage containers inside it.")
                .style(Style::default().fg(Color::DarkGray))
                .wrap(Wrap { trim: true })
                .block(block),
            area,
        );
        return;
    };

    if let Some(err) = app.container_errors.get(&sb.id) {
        f.render_widget(
            Paragraph::new(format!(
                "Failed querying Podman containers:\n{err}\n\nPress [c] to retry."
            ))
            .style(Style::default().fg(Color::Red))
            .wrap(Wrap { trim: true })
            .block(block),
            area,
        );
        return;
    }

    let Some(containers) = app.containers_by_sandbox.get(&sb.id) else {
        f.render_widget(
            Paragraph::new(
                "Container list not loaded yet.\n\n• Press [c] (or [Enter] on sandbox) to query `podman ps -a`\n• Press [i] to stream a host OCI `.tar` image into air-gapped VM\n• Press [n] to run a new detached container\n• Press [d] to bind a host DOCKER_HOST socket",
            )
            .style(Style::default().fg(Color::Gray))
            .wrap(Wrap { trim: true })
            .block(block),
            area,
        );
        return;
    };

    if containers.is_empty() {
        f.render_widget(
            Paragraph::new(
                "0 containers in this sandbox.\n\n• Press [i] to load a `.tar` OCI image (`podman load`)\n• Press [n] to start a container (`podman run -d ...`)\n• Press [d] to expose `DOCKER_HOST` on Host",
            )
            .style(Style::default().fg(Color::DarkGray))
            .wrap(Wrap { trim: true })
            .block(block),
            area,
        );
        return;
    }

    let header = Row::new(vec!["NAME", "ID", "IMAGE", "STATE", "PORTS"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row<'_>> = containers
        .iter()
        .map(|ctr| {
            let short_id: String = ctr.id.chars().take(12).collect();
            let state_style = if ctr.is_running() {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Gray)
            };
            Row::new(vec![
                Cell::from(ctr.name.clone()),
                Cell::from(short_id),
                Cell::from(ctr.image.clone()),
                Cell::from(ctr.state.clone()).style(state_style),
                Cell::from(ctr.ports.clone()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(12),
        Constraint::Length(13),
        Constraint::Min(16),
        Constraint::Length(9),
        Constraint::Min(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(
            Style::default()
                .bg(if focused {
                    Color::Blue
                } else {
                    Color::DarkGray
                })
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    let mut state = TableState::default().with_selected(Some(app.selected_container));
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_output_pane(f: &mut Frame<'_>, app: &TuiApp, area: Rect) {
    let focused = app.focus == FocusPane::Output;
    let border_color = if focused {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let visible_rows = usize::from(area.height.saturating_sub(2)).max(1);
    let total = app.output.len();
    let end = total.saturating_sub(app.output_scroll_from_bottom);
    let start = end.saturating_sub(visible_rows);

    let lines: Vec<Line<'_>> = app
        .output
        .iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .map(|entry| {
            let style = match entry.tone {
                LogTone::Info => Style::default().fg(Color::Cyan),
                LogTone::Success => Style::default().fg(Color::Green),
                LogTone::Warn => Style::default().fg(Color::Yellow),
                LogTone::Error => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                LogTone::Stdout => Style::default().fg(Color::White),
                LogTone::Stderr => Style::default().fg(Color::LightRed),
            };
            Line::from(Span::styled(entry.text.clone(), style))
        })
        .collect();

    let title = if app.output_scroll_from_bottom > 0 {
        format!(
            " [3] Output & Activity Log (scrolled -{} lines) ",
            app.output_scroll_from_bottom
        )
    } else {
        " [3] Output & Activity Log ".to_owned()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(border_color));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_footer(f: &mut Frame<'_>, _app: &TuiApp, area: Rect) {
    let line1 = Line::from(vec![
        hotkey_span("Tab"),
        Span::raw(" Pane  "),
        hotkey_span("s"),
        Span::raw(" Spawn VM  "),
        hotkey_span("r"),
        Span::raw(" +5m TTL  "),
        hotkey_span("d"),
        Span::raw(" Docker URI  "),
        hotkey_span("e"),
        Span::raw(" VM Exec  "),
        hotkey_span("D"),
        Span::raw(" Destroy VM  "),
        hotkey_span("R"),
        Span::raw(" Refresh  "),
        hotkey_span("?"),
        Span::raw(" Help  "),
        hotkey_span("q"),
        Span::raw(" Quit"),
    ]);
    let line2 = Line::from(vec![
        Span::styled("Containers: ", Style::default().fg(Color::DarkGray)),
        hotkey_span("c"),
        Span::raw(" List  "),
        hotkey_span("b"),
        Span::raw(" Build  "),
        hotkey_span("C"),
        Span::raw(" Compose  "),
        hotkey_span("i"),
        Span::raw(" Load .tar  "),
        hotkey_span("n"),
        Span::raw(" Run  "),
        hotkey_span("x"),
        Span::raw(" Exec  "),
        hotkey_span("l"),
        Span::raw(" Logs  "),
        hotkey_span("S"),
        Span::raw(" Start/Stop  "),
        hotkey_span("X"),
        Span::raw(" Rm"),
    ]);
    f.render_widget(Paragraph::new(vec![line1, line2]), area);
}

fn hotkey_span(key: &str) -> Span<'_> {
    Span::styled(
        format!("[{key}]"),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let popup_height = height.min(area.height.saturating_sub(2)).max(3);
    let top = area.y + area.height.saturating_sub(popup_height) / 2;
    let popup_width = (u32::from(area.width) * u32::from(percent_x) / 100) as u16;
    let width = popup_width.min(area.width.saturating_sub(2)).max(20);
    let left = area.x + area.width.saturating_sub(width) / 2;
    Rect::new(left, top, width, popup_height)
}

fn draw_modal(f: &mut Frame<'_>, modal: &Modal, root: Rect) {
    match modal {
        Modal::Spawn { selected } => {
            let area = centered_rect(76, 9, root);
            f.render_widget(Clear, area);
            let mut lines = vec![Line::from(Span::styled(
                "Select a sandbox profile ([1-3] or Enter, Esc to cancel):",
                Style::default().fg(Color::Gray),
            ))];
            lines.push(Line::from(""));
            for (idx, preset) in SpawnPreset::ALL.iter().enumerate() {
                let style = if idx == *selected {
                    Style::default()
                        .bg(Color::Blue)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                lines.push(Line::from(Span::styled(preset.label(), style)));
            }
            let block = Block::default()
                .borders(Borders::ALL)
                .title(" Spawn Micro-VM Sandbox ")
                .border_style(Style::default().fg(Color::Cyan));
            f.render_widget(Paragraph::new(lines).block(block), area);
        }
        Modal::DockerCompat {
            sandbox_id,
            selected,
        } => {
            let area = centered_rect(76, 8, root);
            f.render_widget(Clear, area);
            let opts = [
                "[1] Standard Docker API   (owner-only IPC, blocks all host bind mounts)",
                "[2] Testcontainers Mode   (--allow-reaper-socket, maps guest podman.sock)",
            ];
            let mut lines = vec![
                Line::from(Span::styled(
                    "Choose Docker Engine API compatibility policy (Enter, Esc to cancel):",
                    Style::default().fg(Color::Gray),
                )),
                Line::from(""),
            ];
            for (idx, lbl) in opts.iter().enumerate() {
                let style = if idx == *selected {
                    Style::default()
                        .bg(Color::Blue)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                lines.push(Line::from(Span::styled(*lbl, style)));
            }
            let block = Block::default()
                .borders(Borders::ALL)
                .title(format!(" Enable DOCKER_HOST for {sandbox_id} "))
                .border_style(Style::default().fg(Color::Cyan));
            f.render_widget(Paragraph::new(lines).block(block), area);
        }
        Modal::Confirm(action) => {
            let area = centered_rect(68, 7, root);
            f.render_widget(Clear, area);
            let block = Block::default()
                .borders(Borders::ALL)
                .title(" Confirm Destructive Action ")
                .border_style(Style::default().fg(Color::Red));
            f.render_widget(
                Paragraph::new(action.prompt_message())
                    .wrap(Wrap { trim: true })
                    .block(block),
                area,
            );
        }
        Modal::Prompt(prompt) => {
            let area = centered_rect(82, 7, root);
            f.render_widget(Clear, area);
            let block = Block::default()
                .borders(Borders::ALL)
                .title(prompt.kind.title())
                .border_style(Style::default().fg(Color::Yellow));
            let avail = usize::from(area.width.saturating_sub(5)).max(1);
            let scroll_chars = prompt.cursor_chars.saturating_sub(avail.saturating_sub(1));
            let visible_input: String = prompt
                .input
                .chars()
                .skip(scroll_chars)
                .take(avail)
                .collect();
            let cursor_offset = (prompt.cursor_chars - scroll_chars) as u16;
            let lines = vec![
                Line::from(Span::styled(
                    prompt.kind.hint(),
                    Style::default().fg(Color::Gray),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled("> ", Style::default().fg(Color::Yellow)),
                    Span::raw(visible_input),
                ]),
                Line::from(Span::styled(
                    "[Enter] Run   [Esc] Cancel",
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            f.render_widget(Paragraph::new(lines).block(block), area);

            let cx = (area.x + 3 + cursor_offset).min(area.x + area.width.saturating_sub(2));
            let cy = area.y + 3;
            if cy < area.y + area.height {
                f.set_cursor_position((cx, cy));
            }
        }
        Modal::Help => {
            let area = centered_rect(78, 21, root);
            f.render_widget(Clear, area);
            let help_text = "\
Navigation & Views:
  Tab / Shift+Tab / 1-3   Switch active pane (Sandboxes, Containers, Output)
  Up/Down or k/j          Move selection or scroll Output pane
  PgUp / PgDn             Scroll Output & Activity Log faster
  R                       Force refresh daemon status & sandboxes

Sandbox Lifecycle:
  s                       Spawn micro-VM sandbox (Warm-Pool or Container presets)
  r                       Renew selected sandbox lease (+300s)
  d                       Bind & print owner-only DOCKER_HOST URI
  e                       Execute shell command inside Guest VM
  D (or Del on VM pane)   Destroy selected sandbox (with confirmation)

Guest Podman Container Administration:
  c (or Enter on VM)      Refresh `podman ps -a` inside selected sandbox
  b                       Build image from host folder + Dockerfile (`podman build`)
  C (Shift+c)             Deploy Compose stack (`compose.yaml` / `docker-compose.yml`)
  i                       Stream host OCI `.tar` archive into guest (`podman load`)
  n                       Run new detached container (`podman run -d ...`)
  x                       Execute command inside selected container (`ExecTarget::Container`)
  l                       View tail logs of selected container (`podman logs --tail 100`)
  S                       Start or Stop selected container
  X (or Del on Ctr pane)  Force-remove selected container (with confirmation)";
            let block = Block::default()
                .borders(Borders::ALL)
                .title(" Keyboard Shortcuts (Esc / ? to close) ")
                .border_style(Style::default().fg(Color::Cyan));
            f.render_widget(Paragraph::new(help_text).block(block), area);
        }
    }
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self, SandboxError> {
        install_panic_restore_hook();
        enable_raw_mode().map_err(|err| {
            SandboxError::Transport(format!("failed to enable terminal raw mode: {err}"))
        })?;
        if let Err(err) = execute!(io::stdout(), EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(SandboxError::Transport(format!(
                "failed to enter alternate screen: {err}"
            )));
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
    }
}

fn install_panic_restore_hook() {
    static HOOK_ONCE: Once = Once::new();
    HOOK_ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
            prev(info);
        }));
    });
}

fn format_endpoint(ep: &sandbox_client::ControlEndpoint) -> String {
    match ep {
        sandbox_client::ControlEndpoint::UnixSocket(p) => format!("unix://{}", p.display()),
        sandbox_client::ControlEndpoint::NamedPipe(s) => s.clone(),
    }
}

/// Runs the interactive terminal dashboard until the user quits (`q` / `Ctrl+C`).
pub async fn run_tui(client: &SandboxClient, refresh_interval: Duration) -> Result<u8, SandboxError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(SandboxError::InvalidSpec(
            "tui requires an interactive terminal (TTY)".to_owned(),
        ));
    }

    let _guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|err| {
        SandboxError::Transport(format!("failed to initialize terminal backend: {err}"))
    })?;
    terminal.clear().map_err(|err| {
        SandboxError::Transport(format!("failed to clear terminal screen: {err}"))
    })?;

    let mut app = TuiApp::new(format_endpoint(client.endpoint()));
    let (bg_tx, mut bg_rx) = mpsc::unbounded_channel::<BgEvent>();
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<Event>();
    let stop_reader = Arc::new(AtomicBool::new(false));
    let stop_reader_bg = Arc::clone(&stop_reader);

    std::thread::spawn(move || {
        while !stop_reader_bg.load(Ordering::Relaxed) {
            match event::poll(Duration::from_millis(50)) {
                Ok(true) => match event::read() {
                    Ok(ev) => {
                        if ev_tx.send(ev).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                Ok(false) => {}
                Err(_) => break,
            }
        }
    });

    dispatch_tui_command(
        client,
        &bg_tx,
        &mut app,
        TuiCommand::RefreshAll {
            also_containers_for: None,
        },
    );

    let mut tick = tokio::time::interval(refresh_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await;

    loop {
        terminal
            .draw(|f| draw_ui(f, &app))
            .map_err(|err| SandboxError::Transport(format!("terminal draw failed: {err}")))?;

        if app.should_quit {
            break;
        }

        tokio::select! {
            biased;
            Some(ev) = ev_rx.recv() => {
                if let Some(cmd) = app.handle_event(ev) {
                    dispatch_tui_command(client, &bg_tx, &mut app, cmd);
                }
            }
            Some(bg) = bg_rx.recv() => {
                if let Some(follow_up) = app.apply_bg_event(bg) {
                    dispatch_tui_command(client, &bg_tx, &mut app, follow_up);
                }
            }
            _ = tick.tick() => {
                if !app.poll_in_flight {
                    dispatch_tui_command(
                        client,
                        &bg_tx,
                        &mut app,
                        TuiCommand::RefreshAll {
                            also_containers_for: None,
                        },
                    );
                }
            }
        }
    }

    stop_reader.store(true, Ordering::Relaxed);
    Ok(0)
}

fn dispatch_tui_command(
    client: &SandboxClient,
    bg_tx: &mpsc::UnboundedSender<BgEvent>,
    app: &mut TuiApp,
    cmd: TuiCommand,
) {
    let client = client.clone();
    let tx = bg_tx.clone();

    match cmd {
        TuiCommand::RefreshAll {
            also_containers_for,
        } => {
            app.poll_in_flight = true;
            tokio::spawn(async move {
                let (status_res, list_res) =
                    tokio::join!(client.status(), client.list_sandboxes());
                let _ = tx.send(BgEvent::Snapshot {
                    status: status_res.map_err(|e| e.to_string()),
                    sandboxes: list_res.map_err(|e| e.to_string()),
                });
                if let Some(sb_id) = also_containers_for {
                    let result = query_podman_containers(&client, &sb_id).await;
                    let _ = tx.send(BgEvent::ContainersLoaded {
                        sandbox_id: sb_id,
                        result,
                    });
                }
            });
        }
        TuiCommand::RefreshContainers { sandbox_id } => {
            tokio::spawn(async move {
                let result = query_podman_containers(&client, &sandbox_id).await;
                let _ = tx.send(BgEvent::ContainersLoaded { sandbox_id, result });
            });
        }
        TuiCommand::Spawn { preset } => {
            tokio::spawn(async move {
                match client.spawn(preset.to_spec()).await {
                    Ok(lease) => {
                        let id = lease.id.clone();
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Success,
                                text: format!(
                                    "[OK] Spawned sandbox {} (ttl={}s)",
                                    id,
                                    lease.ttl.as_secs()
                                ),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: true,
                            refresh_containers_for: None,
                            select_sandbox: Some(id),
                        });
                    }
                    Err(err) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Error,
                                text: format!("[ERR] Spawn failed: {err}"),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: false,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                }
            });
        }
        TuiCommand::RenewLease {
            sandbox_id,
            ttl_secs,
        } => {
            tokio::spawn(async move {
                match client
                    .renew_lease(&sandbox_id, Duration::from_secs(ttl_secs))
                    .await
                {
                    Ok(()) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Success,
                                text: format!(
                                    "[OK] Renewed lease for {sandbox_id} (+{ttl_secs}s)"
                                ),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: true,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                    Err(err) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Error,
                                text: format!("[ERR] Renew lease failed for {sandbox_id}: {err}"),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: false,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                }
            });
        }
        TuiCommand::EnableDockerCompat {
            sandbox_id,
            allow_reaper_socket,
        } => {
            tokio::spawn(async move {
                match client
                    .enable_docker_compat(&sandbox_id, allow_reaper_socket)
                    .await
                {
                    Ok(uri) => {
                        let env_hint = if cfg!(windows) {
                            format!("$env:DOCKER_HOST = \"{uri}\"")
                        } else {
                            format!("export DOCKER_HOST=\"{uri}\"")
                        };
                        let mode = if allow_reaper_socket {
                            "Testcontainers + reaper"
                        } else {
                            "standard"
                        };
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Success,
                                text: format!(
                                    "[OK] Docker endpoint bound for {sandbox_id} ({mode}):"
                                ),
                            },
                            stdout: env_hint,
                            stderr: String::new(),
                            refresh_all: true,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                    Err(err) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Error,
                                text: format!(
                                    "[ERR] Failed binding Docker endpoint for {sandbox_id}: {err}"
                                ),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: false,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                }
            });
        }
        TuiCommand::DestroySandbox { sandbox_id } => {
            tokio::spawn(async move {
                match client.destroy(&sandbox_id).await {
                    Ok(status) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Success,
                                text: format!("[OK] Destroyed {sandbox_id} ({status:?})"),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: true,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                    Err(err) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Error,
                                text: format!("[ERR] Destroy failed for {sandbox_id}: {err}"),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: true,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                }
            });
        }
        TuiCommand::GuestExec {
            sandbox_id,
            shell_cmd,
        } => {
            tokio::spawn(async move {
                let req = build_exec_req(
                    ExecTarget::Guest,
                    vec!["/bin/sh".to_owned(), "-c".to_owned(), shell_cmd.clone()],
                    60,
                );
                send_exec_outcome(
                    &tx,
                    format!("guest:{sandbox_id}$ {shell_cmd}"),
                    client.exec_collect(&sandbox_id, req).await,
                    None,
                );
            });
        }
        TuiCommand::ContainerExec {
            sandbox_id,
            container,
            shell_cmd,
        } => {
            tokio::spawn(async move {
                let req = build_exec_req(
                    ExecTarget::Container {
                        id_or_name: container.clone(),
                    },
                    vec!["/bin/sh".to_owned(), "-c".to_owned(), shell_cmd.clone()],
                    60,
                );
                send_exec_outcome(
                    &tx,
                    format!("ctr:{container}@{sandbox_id}$ {shell_cmd}"),
                    client.exec_collect(&sandbox_id, req).await,
                    None,
                );
            });
        }
        TuiCommand::RunContainer {
            sandbox_id,
            run_args,
        } => {
            tokio::spawn(async move {
                match run_container_via_docker_compat(&client, &sandbox_id, &run_args).await {
                    Ok((ctr_label, ports_summary)) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Success,
                                text: format!(
                                    "[OK] Started container {ctr_label} in {sandbox_id} ({ports_summary})"
                                ),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: true,
                            refresh_containers_for: Some(sandbox_id),
                            select_sandbox: None,
                        });
                    }
                    Err(err) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Error,
                                text: format!(
                                    "[ERR] Failed starting container in {sandbox_id}: {err}"
                                ),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: false,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                }
            });
        }
        TuiCommand::LoadImageTar {
            sandbox_id,
            host_tar_path,
        } => {
            tokio::spawn(async move {
                let res = stream_image_tar_into_podman(&client, &sandbox_id, &host_tar_path).await;
                match res {
                    Ok((stdout, stderr)) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Success,
                                text: format!(
                                    "[OK] Loaded OCI image '{}' into {sandbox_id}",
                                    host_tar_path.display()
                                ),
                            },
                            stdout,
                            stderr,
                            refresh_all: false,
                            refresh_containers_for: Some(sandbox_id),
                            select_sandbox: None,
                        });
                    }
                    Err(err) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Error,
                                text: format!(
                                    "[ERR] Failed loading '{}' into {sandbox_id}: {err}",
                                    host_tar_path.display()
                                ),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: false,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                }
            });
        }
        TuiCommand::BuildImage {
            sandbox_id,
            context_dir,
            tag,
        } => {
            tokio::spawn(async move {
                let spec = ImageBuildSpec {
                    context_dir: context_dir.clone(),
                    dockerfile: None,
                    tags: vec![tag.clone()],
                    build_args: Vec::new(),
                    target: None,
                    no_cache: false,
                    output_tar: None,
                    deadline: Duration::from_secs(300),
                };
                match build_image_in_sandbox(&client, &sandbox_id, spec, false).await {
                    Ok(res) if res.exit.code == Some(0) && !res.exit.timed_out => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Success,
                                text: format!(
                                    "[OK] Built image '{tag}' in {sandbox_id} from '{}'",
                                    context_dir.display()
                                ),
                            },
                            stdout: res.stdout,
                            stderr: res.stderr,
                            refresh_all: false,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                    Ok(res) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Error,
                                text: format!(
                                    "[ERR] Build failed for '{tag}' (exit={:?}, timed_out={})",
                                    res.exit.code, res.exit.timed_out
                                ),
                            },
                            stdout: res.stdout,
                            stderr: res.stderr,
                            refresh_all: false,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                    Err(err) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Error,
                                text: format!("[ERR] Build error for '{tag}': {err}"),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: false,
                            refresh_containers_for: None,
                            select_sandbox: None,
                        });
                    }
                }
            });
        }
        TuiCommand::ComposeUp {
            sandbox_id,
            compose_path,
        } => {
            tokio::spawn(async move {
                let res = async {
                    let spec = load_compose_spec_from_path(&compose_path, None)?;
                    let started = compose_up_in_sandbox(
                        &client,
                        &sandbox_id,
                        &spec,
                        true,
                        Duration::from_secs(300),
                        false,
                    )
                    .await?;
                    Ok::<_, SandboxError>((spec.project_name, started))
                }
                .await;

                match res {
                    Ok((proj, started)) => {
                        let summary_lines: Vec<String> = started
                            .iter()
                            .map(|s| {
                                let ports = if s.host_ports.is_empty() {
                                    "no host ports".to_owned()
                                } else {
                                    s.host_ports.join(", ")
                                };
                                format!("  {} ({}) -> {}", s.service, s.container_name, ports)
                            })
                            .collect();
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Success,
                                text: format!(
                                    "[OK] Compose stack '{proj}' up in {sandbox_id} ({} service(s)):",
                                    started.len()
                                ),
                            },
                            stdout: summary_lines.join("\n"),
                            stderr: String::new(),
                            refresh_all: true,
                            refresh_containers_for: Some(sandbox_id),
                            select_sandbox: None,
                        });
                    }
                    Err(err) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Error,
                                text: format!(
                                    "[ERR] Compose up failed for '{}': {err}",
                                    compose_path.display()
                                ),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: true,
                            refresh_containers_for: Some(sandbox_id),
                            select_sandbox: None,
                        });
                    }
                }
            });
        }
        TuiCommand::ToggleContainerState {
            sandbox_id,
            container_id,
            currently_running,
        } => {
            tokio::spawn(async move {
                let verb = if currently_running { "stop" } else { "start" };
                let res = async {
                    let uri = client.enable_docker_compat(&sandbox_id, false).await?;
                    let ep = ControlEndpoint::parse(&uri)?;
                    let enc = percent_encode_component(&container_id);
                    let path = if currently_running {
                        format!("/containers/{enc}/stop?t=3")
                    } else {
                        format!("/containers/{enc}/start")
                    };
                    let (st, body) = docker_json_request(&ep, "POST", &path, None).await?;
                    if (200..300).contains(&st) || st == 304 {
                        Ok::<(), SandboxError>(())
                    } else {
                        Err(docker_http_error(
                            &format!("{verb} container '{container_id}'"),
                            st,
                            &body,
                        ))
                    }
                }
                .await;
                match res {
                    Ok(()) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Success,
                                text: format!(
                                    "[OK] Container {container_id} {verb}ped in {sandbox_id}"
                                ),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: true,
                            refresh_containers_for: Some(sandbox_id),
                            select_sandbox: None,
                        });
                    }
                    Err(err) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Error,
                                text: format!(
                                    "[ERR] Failed to {verb} container {container_id} in {sandbox_id}: {err}"
                                ),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: false,
                            refresh_containers_for: Some(sandbox_id),
                            select_sandbox: None,
                        });
                    }
                }
            });
        }
        TuiCommand::ContainerLogs {
            sandbox_id,
            container_id,
        } => {
            tokio::spawn(async move {
                let argv = vec![
                    "/usr/bin/podman".to_owned(),
                    "logs".to_owned(),
                    "--tail".to_owned(),
                    "100".to_owned(),
                    "--".to_owned(),
                    container_id.clone(),
                ];
                let req = build_exec_req(ExecTarget::Guest, argv, 20);
                send_exec_outcome(
                    &tx,
                    format!("[{sandbox_id}] podman logs --tail 100 {container_id}"),
                    client.exec_collect(&sandbox_id, req).await,
                    None,
                );
            });
        }
        TuiCommand::RemoveContainer {
            sandbox_id,
            container_id,
        } => {
            tokio::spawn(async move {
                let res = async {
                    let uri = client.enable_docker_compat(&sandbox_id, false).await?;
                    let ep = ControlEndpoint::parse(&uri)?;
                    let enc = percent_encode_component(&container_id);
                    let path = format!("/containers/{enc}?force=true");
                    let (st, body) = docker_json_request(&ep, "DELETE", &path, None).await?;
                    if (200..300).contains(&st) || st == 404 {
                        Ok::<(), SandboxError>(())
                    } else {
                        Err(docker_http_error(
                            &format!("remove container '{container_id}'"),
                            st,
                            &body,
                        ))
                    }
                }
                .await;
                match res {
                    Ok(()) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Success,
                                text: format!(
                                    "[OK] Removed container {container_id} from {sandbox_id}"
                                ),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: true,
                            refresh_containers_for: Some(sandbox_id),
                            select_sandbox: None,
                        });
                    }
                    Err(err) => {
                        let _ = tx.send(BgEvent::ActionFinished {
                            busy_done: true,
                            headline: OutputLine {
                                tone: LogTone::Error,
                                text: format!(
                                    "[ERR] Failed removing container {container_id} from {sandbox_id}: {err}"
                                ),
                            },
                            stdout: String::new(),
                            stderr: String::new(),
                            refresh_all: false,
                            refresh_containers_for: Some(sandbox_id),
                            select_sandbox: None,
                        });
                    }
                }
            });
        }
    }
}

fn build_exec_req(target: ExecTarget, argv: Vec<String>, deadline_secs: u64) -> ExecRequest {
    ExecRequest {
        target,
        argv,
        env: BTreeMap::new(),
        cwd: None,
        user: None,
        deadline: Duration::from_secs(deadline_secs),
        stdout_budget_bytes: EXEC_BUDGET_BYTES,
        stderr_budget_bytes: EXEC_BUDGET_BYTES,
    }
}

async fn query_podman_containers(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
) -> Result<Vec<ContainerRow>, String> {
    // If Docker compatibility is already active on this sandbox, query `/containers/json?all=true`
    // so host-forwarded `127.0.0.1:<port>` bindings are reflected accurately.
    if let Ok(sandboxes) = client.list_sandboxes().await {
        if let Some(uri) = sandboxes
            .into_iter()
            .find(|s| &s.id == sandbox_id)
            .and_then(|s| s.docker_endpoint)
        {
            if let Ok(ep) = ControlEndpoint::parse(&uri) {
                if let Ok((200, body)) =
                    docker_json_request(&ep, "GET", "/containers/json?all=true", None).await
                {
                    if let Ok(rows) = parse_docker_containers_json(&body) {
                        return Ok(rows);
                    }
                }
            }
        }
    }

    let req = build_exec_req(
        ExecTarget::Guest,
        vec![
            "/usr/bin/podman".to_owned(),
            "ps".to_owned(),
            "-a".to_owned(),
            "--noheading".to_owned(),
            "--format".to_owned(),
            "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}".to_owned(),
        ],
        20,
    );
    let out = client
        .exec_collect(sandbox_id, req)
        .await
        .map_err(|e| e.to_string())?;
    if out.exit.code != Some(0) {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        return Err(if stderr.is_empty() {
            format!("podman ps exited with {:?}", out.exit.code)
        } else {
            stderr
        });
    }
    Ok(parse_podman_ps_tsv(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_docker_containers_json(body: &[u8]) -> Result<Vec<ContainerRow>, SandboxError> {
    let arr: Vec<Value> = serde_json::from_slice(body)
        .map_err(|err| SandboxError::Transport(format!("invalid /containers/json: {err}")))?;
    let mut rows = Vec::with_capacity(arr.len());
    for item in arr {
        let id = item["Id"].as_str().unwrap_or("").to_owned();
        if id.is_empty() {
            continue;
        }
        let name = item["Names"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .map(|n| n.trim_start_matches('/').to_owned())
            .unwrap_or_else(|| id.chars().take(12).collect());
        let image = item["Image"].as_str().unwrap_or("-").to_owned();
        let state = item["State"].as_str().unwrap_or("unknown").to_owned();
        let status = item["Status"].as_str().unwrap_or("").to_owned();
        let ports = format_container_list_ports(&item["Ports"]);
        rows.push(ContainerRow {
            id: sanitize_terminal_text(&id),
            name: sanitize_terminal_text(&name),
            image: sanitize_terminal_text(&image),
            state: sanitize_terminal_text(&state),
            status: sanitize_terminal_text(&status),
            ports: sanitize_terminal_text(&ports),
        });
    }
    Ok(rows)
}

/// Parses safe TUI `podman run` arguments into `(container_name, image, create_json_payload)`
/// without ever invoking a shell, enforcing policy and forwarding `-p` ports via `DockerCompat`.
// shortcut: parses core detached podman-run flags in TUI, use Compose or DOCKER_HOST for volumes/multi-network configs
pub fn parse_tui_run_container_spec(
    raw_args: &str,
) -> Result<(Option<String>, String, Value), SandboxError> {
    let tokens = split_shell_words(raw_args)?;
    if tokens.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "container run arguments must include an image name".to_owned(),
        ));
    }

    let mut name: Option<String> = None;
    let mut ports = Vec::new();
    let mut env = Vec::new();
    let mut workdir: Option<String> = None;
    let mut user: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut entrypoint: Option<String> = None;
    let mut network: Option<String> = None;
    let mut restart = None;
    let mut auto_remove = false;
    let mut idx = 0usize;

    let take_opt_val = |flag: &str, idx: &mut usize| -> Result<String, SandboxError> {
        *idx += 1;
        tokens.get(*idx).cloned().ok_or_else(|| {
            SandboxError::InvalidSpec(format!("missing value after '{flag}'"))
        })
    };

    while idx < tokens.len() {
        let tok = tokens[idx].as_str();
        if tok == "--" {
            idx += 1;
            break;
        }
        if !tok.starts_with('-') || tok == "-" {
            break;
        }

        if matches!(tok, "-d" | "--detach") {
            idx += 1;
            continue;
        }
        if tok == "--rm" {
            auto_remove = true;
            idx += 1;
            continue;
        }
        if tok == "--privileged"
            || tok.starts_with("--privileged=")
            || matches!(tok, "-v" | "--volume" | "--mount")
            || tok.starts_with("--volume=")
            || tok.starts_with("--mount=")
        {
            return Err(SandboxError::PolicyViolation(format!(
                "flag '{tok}' is forbidden in sandbox container run"
            )));
        }

        let (flag, inline_val) = match tok.split_once('=') {
            Some((f, v)) => (f, Some(v.to_owned())),
            None => (tok, None),
        };
        let next_val = |inline: Option<String>, idx: &mut usize| -> Result<String, SandboxError> {
            match inline {
                Some(v) => Ok(v),
                None => take_opt_val(flag, idx),
            }
        };

        match flag {
            "--name" => {
                let n = next_val(inline_val, &mut idx)?;
                validate_safe_identifier(&n, "container name")?;
                name = Some(n);
            }
            "-p" | "--publish" => {
                let p = next_val(inline_val, &mut idx)?;
                ports.push(parse_short_port(&p, "tui")?);
            }
            "-e" | "--env" => {
                let kv = next_val(inline_val, &mut idx)?;
                if kv.is_empty() || !kv.contains('=') || kv.contains('\0') {
                    return Err(SandboxError::InvalidSpec(format!(
                        "invalid -e/--env '{kv}' (expected KEY=VALUE)"
                    )));
                }
                env.push(kv);
            }
            "-w" | "--workdir" => {
                workdir = Some(next_val(inline_val, &mut idx)?);
            }
            "-u" | "--user" => {
                user = Some(next_val(inline_val, &mut idx)?);
            }
            "--hostname" => {
                hostname = Some(next_val(inline_val, &mut idx)?);
            }
            "--entrypoint" => {
                entrypoint = Some(next_val(inline_val, &mut idx)?);
            }
            "--network" | "--net" => {
                let net = next_val(inline_val, &mut idx)?;
                if net.trim().eq_ignore_ascii_case("host") {
                    return Err(SandboxError::PolicyViolation(
                        "network mode 'host' is forbidden inside sandbox isolation".to_owned(),
                    ));
                }
                network = Some(net);
            }
            "--restart" => {
                let pol = next_val(inline_val, &mut idx)?;
                restart = Some(parse_restart_policy_str(&pol, "tui")?);
            }
            other => {
                return Err(SandboxError::InvalidSpec(format!(
                    "unsupported container run flag '{other}' (supported: -d, --rm, --name, -p, -e, -w, -u, --hostname, --entrypoint, --network, --restart)"
                )));
            }
        }
        idx += 1;
    }

    let image = tokens.get(idx).cloned().ok_or_else(|| {
        SandboxError::InvalidSpec("missing container image in run arguments".to_owned())
    })?;
    validate_image_tag(&image)?;
    let cmd: Vec<String> = tokens[idx + 1..].to_vec();

    let mut root = Map::new();
    root.insert("Image".to_owned(), Value::String(image.clone()));
    if !cmd.is_empty() {
        root.insert("Cmd".to_owned(), json!(cmd));
    }
    if let Some(ep) = entrypoint {
        root.insert("Entrypoint".to_owned(), json!([ep]));
    }
    if !env.is_empty() {
        root.insert("Env".to_owned(), json!(env));
    }
    if let Some(wd) = workdir {
        root.insert("WorkingDir".to_owned(), Value::String(wd));
    }
    if let Some(u) = user {
        root.insert("User".to_owned(), Value::String(u));
    }
    if let Some(hn) = hostname {
        root.insert("Hostname".to_owned(), Value::String(hn));
    }

    let mut hc = Map::new();
    if auto_remove {
        hc.insert("AutoRemove".to_owned(), Value::Bool(true));
    }
    insert_port_bindings_json(&mut root, &mut hc, &ports, &[]);
    if let Some(net) = network {
        hc.insert("NetworkMode".to_owned(), Value::String(net));
    }
    if let Some(r) = restart {
        hc.insert(
            "RestartPolicy".to_owned(),
            json!({
                "Name": r.name,
                "MaximumRetryCount": r.maximum_retry_count,
            }),
        );
    }
    root.insert("HostConfig".to_owned(), Value::Object(hc));

    Ok((name, image, Value::Object(root)))
}

async fn run_container_via_docker_compat(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    raw_args: &str,
) -> Result<(String, String), SandboxError> {
    let (name_opt, _image, payload) = parse_tui_run_container_spec(raw_args)?;
    let docker_uri = client.enable_docker_compat(sandbox_id, false).await?;
    let docker_ep = ControlEndpoint::parse(&docker_uri)?;

    let create_path = match &name_opt {
        Some(n) => format!("/containers/create?name={}", percent_encode_component(n)),
        None => "/containers/create".to_owned(),
    };
    let (cst, cbody) = docker_json_request(&docker_ep, "POST", &create_path, Some(&payload)).await?;
    if cst != 201 {
        return Err(docker_http_error("create container", cst, &cbody));
    }
    let created: Value = serde_json::from_slice(&cbody)
        .map_err(|err| SandboxError::Transport(format!("invalid create container JSON: {err}")))?;
    let ctr_id = created["Id"]
        .as_str()
        .ok_or_else(|| SandboxError::Transport("create container missing 'Id'".to_owned()))?
        .to_owned();

    let enc_id = percent_encode_component(&ctr_id);
    let (sst, sbody) =
        docker_json_request(&docker_ep, "POST", &format!("/containers/{enc_id}/start"), None)
            .await?;
    if sst != 204 && sst != 304 {
        return Err(docker_http_error("start container", sst, &sbody));
    }

    let (ist, ibody) =
        docker_json_request(&docker_ep, "GET", &format!("/containers/{enc_id}/json"), None).await?;
    let host_ports = if ist == 200 {
        serde_json::from_slice::<Value>(&ibody)
            .ok()
            .map(|v| extract_inspected_host_ports(&v))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let label = name_opt.unwrap_or_else(|| ctr_id.chars().take(12).collect());
    let ports_summary = if host_ports.is_empty() {
        "detached".to_owned()
    } else {
        host_ports.join(", ")
    };
    Ok((label, ports_summary))
}

async fn stream_image_tar_into_podman(
    client: &SandboxClient,
    sandbox_id: &SandboxId,
    host_tar_path: &std::path::Path,
) -> Result<(String, String), String> {
    let path_owned = host_tar_path.to_path_buf();
    let std_file = tokio::task::spawn_blocking(move || -> Result<std::fs::File, String> {
        let meta = std::fs::symlink_metadata(&path_owned)
            .map_err(|e| format!("cannot inspect '{}': {e}", path_owned.display()))?;
        if is_symlink_or_reparse(&meta) || !meta.file_type().is_file() {
            return Err(format!(
                "'{}' must be a regular non-symlink .tar file",
                path_owned.display()
            ));
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        apply_open_no_follow(&mut opts);
        let f = opts
            .open(&path_owned)
            .map_err(|e| format!("cannot open '{}': {e}", path_owned.display()))?;
        let open_meta = f
            .metadata()
            .map_err(|e| format!("cannot stat '{}': {e}", path_owned.display()))?;
        if is_symlink_or_reparse(&open_meta) || !open_meta.file_type().is_file() {
            return Err(format!(
                "'{}' must be a regular non-symlink .tar file",
                path_owned.display()
            ));
        }
        Ok(f)
    })
    .await
    .map_err(|e| format!("file open task failed: {e}"))??;

    let mut file = tokio::fs::File::from_std(std_file);

    let req = build_exec_req(
        ExecTarget::Guest,
        vec!["/usr/bin/podman".to_owned(), "load".to_owned()],
        180,
    );
    let mut stream = client
        .exec_stream(sandbox_id, req)
        .await
        .map_err(|e| e.to_string())?;

    let mut buf = vec![0u8; IMAGE_STREAM_CHUNK_BYTES];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| format!("read error: {e}"))?;
        if n == 0 {
            break;
        }
        stream
            .write_stdin(buf[..n].to_vec())
            .await
            .map_err(|e| format!("stdin stream error: {e}"))?;
    }
    stream.close_stdin();

    let collected = stream.collect().await.map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&collected.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&collected.stderr).into_owned();
    if collected.exit.code != Some(0) {
        return Err(if stderr.trim().is_empty() {
            format!("podman load exited with {:?}", collected.exit.code)
        } else {
            stderr.trim().to_owned()
        });
    }
    Ok((stdout, stderr))
}

fn send_exec_outcome(
    tx: &mpsc::UnboundedSender<BgEvent>,
    label: String,
    res: Result<sandbox_client::ClientExecOutput, SandboxError>,
    refresh_containers_for: Option<SandboxId>,
) {
    match res {
        Ok(out) => {
            let ok = out.exit.code == Some(0) && !out.exit.timed_out;
            let status_tag = if out.exit.timed_out {
                "TIMED OUT".to_owned()
            } else {
                format!("exit={:?}", out.exit.code)
            };
            let _ = tx.send(BgEvent::ActionFinished {
                busy_done: true,
                headline: OutputLine {
                    tone: if ok { LogTone::Success } else { LogTone::Warn },
                    text: format!("{label}  [{status_tag}]"),
                },
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                refresh_all: false,
                refresh_containers_for,
                select_sandbox: None,
            });
        }
        Err(err) => {
            let _ = tx.send(BgEvent::ActionFinished {
                busy_done: true,
                headline: OutputLine {
                    tone: LogTone::Error,
                    text: format!("[ERR] {label}: {err}"),
                },
                stdout: String::new(),
                stderr: String::new(),
                refresh_all: false,
                refresh_containers_for: None,
                select_sandbox: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventState;
    use ratatui::backend::TestBackend;

    fn press(code: KeyCode) -> Event {
        Event::Key(KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        })
    }

    fn release(code: KeyCode) -> Event {
        Event::Key(KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Release,
            state: KeyEventState::NONE,
        })
    }

    fn sample_sandbox(id: &str) -> SandboxSummaryInfo {
        SandboxSummaryInfo {
            id: SandboxId::new(id),
            pid: 4200,
            alive: true,
            network: NetworkPolicy::Isolated,
            remaining_ttl_ms: 295_000,
            live_rss_bytes: Some(256 * 1024 * 1024),
            reserved_rss_mb: 320,
            host_rss_budget_mb: Some(512),
            host_storage_budget_mb: 1024,
            docker_endpoint: None,
            allow_reaper_socket: false,
        }
    }

    #[test]
    fn parses_podman_ps_tsv_and_detects_running_state() {
        let raw = "\
a1b2c3d4e5f6\tweb-api\tdocker.io/library/nginx:alpine\trunning\tUp 12 seconds\t0.0.0.0:8080->80/tcp
f6e5d4c3b2a1\tjob-1\talpine:3.20\texited\tExited (0) 3 minutes ago\t
";
        let rows = parse_podman_ps_tsv(raw);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "web-api");
        assert!(rows[0].is_running());
        assert_eq!(rows[0].ports, "0.0.0.0:8080->80/tcp");

        assert_eq!(rows[1].name, "job-1");
        assert!(!rows[1].is_running());
        assert_eq!(rows[1].ports, "-");
    }

    #[test]
    fn ignores_windows_key_release_and_enforces_confirmation_before_destroy() {
        let mut app = TuiApp::new(r"\\.\pipe\minipod-test".to_owned());
        app.apply_bg_event(BgEvent::Snapshot {
            status: Ok(DaemonStatusInfo {
                active_sandboxes: 1,
                warm_ready_vms: 1,
                effective_host_rss_mb: 256,
                reserved_host_storage_mb: 1024,
                version: "0.1.0".to_owned(),
            }),
            sandboxes: Ok(vec![sample_sandbox("sb-alpha")]),
        });

        // Windows KeyEventKind::Release must never trigger actions.
        assert_eq!(app.handle_event(release(KeyCode::Char('s'))), None);
        assert!(app.modal.is_none());

        // Spawn modal opens on 's' press and triggers WarmIsolated on '1'.
        assert_eq!(app.handle_event(press(KeyCode::Char('s'))), None);
        assert!(matches!(app.modal, Some(Modal::Spawn { selected: 0 })));
        assert_eq!(
            app.handle_event(press(KeyCode::Char('1'))),
            Some(TuiCommand::Spawn {
                preset: SpawnPreset::WarmIsolated,
            })
        );

        // Destructive 'D' opens confirmation modal first; 'n' cancels, 'y' confirms.
        assert_eq!(app.handle_event(press(KeyCode::Char('D'))), None);
        assert!(matches!(
            app.modal,
            Some(Modal::Confirm(ConfirmAction::DestroySandbox { .. }))
        ));
        assert_eq!(app.handle_event(press(KeyCode::Char('n'))), None);
        assert!(app.modal.is_none());

        assert_eq!(app.handle_event(press(KeyCode::Char('D'))), None);
        assert_eq!(
            app.handle_event(press(KeyCode::Char('y'))),
            Some(TuiCommand::DestroySandbox {
                sandbox_id: SandboxId::new("sb-alpha"),
            })
        );
    }

    #[test]
    fn container_prompt_handles_utf8_editing_and_headless_rendering_succeeds() {
        let mut app = TuiApp::new("unix:///tmp/minipod/ctl.sock".to_owned());
        app.apply_bg_event(BgEvent::Snapshot {
            status: Ok(DaemonStatusInfo {
                active_sandboxes: 1,
                warm_ready_vms: 0,
                effective_host_rss_mb: 512,
                reserved_host_storage_mb: 2048,
                version: "0.1.0".to_owned(),
            }),
            sandboxes: Ok(vec![sample_sandbox("sb-ctr-1")]),
        });
        app.apply_bg_event(BgEvent::ContainersLoaded {
            sandbox_id: SandboxId::new("sb-ctr-1"),
            result: Ok(vec![ContainerRow {
                id: "1234567890abcdef".to_owned(),
                name: "echo-srv".to_owned(),
                image: "echo-http:latest".to_owned(),
                state: "running".to_owned(),
                status: "Up 5 seconds".to_owned(),
                ports: "8080/tcp".to_owned(),
            }]),
        });

        // Open container exec prompt ('x') and edit multi-byte UTF-8 safely.
        assert_eq!(app.handle_event(press(KeyCode::Char('x'))), None);
        for ch in "echo xin chào".chars() {
            app.handle_event(press(KeyCode::Char(ch)));
        }
        app.handle_event(press(KeyCode::Left));
        app.handle_event(press(KeyCode::Backspace)); // deletes 'à' cleanly without UTF-8 boundary panic
        app.handle_event(press(KeyCode::Char('a')));

        // Render frame with prompt modal open on headless TestBackend.
        let backend = TestBackend::new(120, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| draw_ui(f, &app)).unwrap();

        let cmd = app.handle_event(press(KeyCode::Enter));
        assert_eq!(
            cmd,
            Some(TuiCommand::ContainerExec {
                sandbox_id: SandboxId::new("sb-ctr-1"),
                container: "echo-srv".to_owned(),
                shell_cmd: "echo xin chao".to_owned(),
            })
        );

        // Render main view and Help modal without panicking even on compact terminals.
        app.handle_event(press(KeyCode::Char('?')));
        let small_backend = TestBackend::new(72, 22);
        let mut small_term = Terminal::new(small_backend).unwrap();
        small_term.draw(|f| draw_ui(f, &app)).unwrap();
        app.handle_event(press(KeyCode::Esc));

        //Quoted path in LoadImageTar ('i') strips Explorer surrounding quotes cleanly.
        app.handle_event(press(KeyCode::Char('i')));
        for ch in "\"D:\\images\\echo.tar\"".chars() {
            app.handle_event(press(KeyCode::Char(ch)));
        }
        assert_eq!(
            app.handle_event(press(KeyCode::Enter)),
            Some(TuiCommand::LoadImageTar {
                sandbox_id: SandboxId::new("sb-ctr-1"),
                host_tar_path: PathBuf::from(r"D:\images\echo.tar"),
            })
        );

        // Newly spawned sandbox ID in ActionFinished is selected once the next Snapshot arrives.
        let follow_up = app.apply_bg_event(BgEvent::ActionFinished {
            busy_done: true,
            headline: OutputLine {
                tone: LogTone::Success,
                text: "spawned".to_owned(),
            },
            stdout: String::new(),
            stderr: String::new(),
            refresh_all: true,
            refresh_containers_for: None,
            select_sandbox: Some(SandboxId::new("sb-ctr-2")),
        });
        assert!(matches!(follow_up, Some(TuiCommand::RefreshAll { .. })));
        app.apply_bg_event(BgEvent::Snapshot {
            status: Ok(DaemonStatusInfo {
                active_sandboxes: 2,
                warm_ready_vms: 0,
                effective_host_rss_mb: 768,
                reserved_host_storage_mb: 3072,
                version: "0.1.0".to_owned(),
            }),
            sandboxes: Ok(vec![sample_sandbox("sb-ctr-1"), sample_sandbox("sb-ctr-2")]),
        });
        assert_eq!(app.selected_sandbox, 1);
    }

    #[test]
    fn parse_tui_run_container_spec_preserves_literal_argv_ports_and_rejects_unsafe_flags() {
        let (name, image, payload) = parse_tui_run_container_spec(
            "--name web-1 -p 8080:80 -e MODE=prod echo-http:latest --banner 'hi; touch /tmp/pwn'",
        )
        .unwrap();
        assert_eq!(name.as_deref(), Some("web-1"));
        assert_eq!(image, "echo-http:latest");
        assert_eq!(
            payload["Cmd"],
            json!(["--banner", "hi; touch /tmp/pwn"])
        );
        assert_eq!(
            payload["HostConfig"]["PortBindings"]["80/tcp"][0]["HostIp"],
            "127.0.0.1"
        );
        assert_eq!(
            payload["HostConfig"]["PortBindings"]["80/tcp"][0]["HostPort"],
            "8080"
        );
        assert_eq!(payload["Env"], json!(["MODE=prod"]));

        for forbidden in [
            "--privileged alpine:latest",
            "-v /etc:/host alpine:latest",
            "--network=host alpine:latest",
            "--unknown-flag alpine:latest",
        ] {
            assert!(
                parse_tui_run_container_spec(forbidden).is_err(),
                "expected '{forbidden}' to be rejected"
            );
        }

        let dirty = "ok\x1b[31mred\x1b[0m\x1b]52;c;cHdu\x07\x08xin chào";
        assert_eq!(sanitize_terminal_text(dirty), "okredxin chào");
    }
}
