//! # mtp-sdk
//!
//! Make any Clap-based CLI tool LLM-discoverable with `--mtp-describe`.
//!
//! This crate reads type information, help strings, defaults, and possible
//! values directly from Clap's `Command` and `Arg` metadata, so you get
//! `--mtp-describe` with zero extra annotation in most cases.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use clap::Parser;
//! use mtp_sdk::Describable;
//!
//! #[derive(Parser)]
//! #[command(name = "mytool", version = "1.0.0", about = "Does things")]
//! struct Cli {
//!     /// Input file
//!     input: String,
//! }
//!
//! fn main() {
//!     let cli = Cli::describable();
//! }
//! ```

use clap::{Command, CommandFactory, Parser, ValueHint};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process;

/// The MTP specification version this SDK implements.
pub const MTP_SPEC_VERSION: &str = "2026-02-07";

// ── Schema types ─────────────────────────────────────────────────────

/// Top-level tool schema returned by `--mtp-describe`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub commands: Vec<CommandDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthConfig>,
}

/// A single (leaf) command in the tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandDescriptor {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<ArgDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin: Option<IODescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<IODescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<Example>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<CommandAuth>,
}

/// Describes a single argument (positional or flag).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgDescriptor {
    pub name: String,
    #[serde(rename = "type")]
    pub arg_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

/// Describes stdin or stdout for a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IODescriptor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
}

/// An example invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Example {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

/// Tool-level auth configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    pub env_var: String,
    pub providers: Vec<AuthProvider>,
}

/// A supported authentication provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthProvider {
    pub id: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

/// Per-command auth overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAuth {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

// ── Annotations for the builder / describe options ───────────────────

/// Annotations for a single command (examples, IO, auth).
#[derive(Debug, Clone, Default)]
pub struct CommandAnnotation {
    pub stdin: Option<IODescriptor>,
    pub stdout: Option<IODescriptor>,
    pub examples: Vec<Example>,
    pub auth: Option<CommandAuth>,
}

/// Options passed to `describe()` for attaching metadata.
#[derive(Debug, Clone, Default)]
pub struct DescribeOptions {
    pub commands: HashMap<String, CommandAnnotation>,
    pub auth: Option<AuthConfig>,
}

// ── Clap type inference ──────────────────────────────────────────────

/// Infer the MTP arg type from a Clap `Arg`.
pub fn infer_arg_type(arg: &clap::Arg) -> String {
    // Boolean actions take priority (Clap derive sets possible_values
    // ["true","false"] for bool fields, so we must check action first)
    match arg.get_action() {
        clap::ArgAction::SetTrue | clap::ArgAction::SetFalse => {
            return "boolean".to_string();
        }
        clap::ArgAction::Count => {
            return "integer".to_string();
        }
        clap::ArgAction::Append => {
            return "array".to_string();
        }
        _ => {}
    }

    // Possible values -> enum
    if !arg.get_possible_values().is_empty() {
        return "enum".to_string();
    }

    // Value hint -> path
    match arg.get_value_hint() {
        ValueHint::FilePath | ValueHint::DirPath | ValueHint::AnyPath => {
            return "path".to_string();
        }
        _ => {}
    }

    // Multi-value detection via num_args
    if let Some(range) = arg.get_num_args() {
        if range.max_values() > 1 {
            return "array".to_string();
        }
    }

    // Value parser type ID checks for numeric types
    let type_id = arg.get_value_parser().type_id();
    if type_id == std::any::TypeId::of::<i32>()
        || type_id == std::any::TypeId::of::<i64>()
        || type_id == std::any::TypeId::of::<u32>()
        || type_id == std::any::TypeId::of::<u64>()
        || type_id == std::any::TypeId::of::<usize>()
    {
        return "integer".to_string();
    }
    if type_id == std::any::TypeId::of::<f32>()
        || type_id == std::any::TypeId::of::<f64>()
    {
        return "number".to_string();
    }

    "string".to_string()
}

// ── Arg extraction ───────────────────────────────────────────────────

/// Extract an `ArgDescriptor` from a Clap `Arg`. Returns `None` for
/// hidden args.
pub fn extract_arg(arg: &clap::Arg) -> Option<ArgDescriptor> {
    if arg.is_hide_set() {
        return None;
    }

    let is_positional = arg.get_long().is_none() && arg.get_short().is_none();

    let name = if is_positional {
        arg.get_id().to_string()
    } else if let Some(long) = arg.get_long() {
        format!("--{}", long)
    } else if let Some(short) = arg.get_short() {
        format!("-{}", short)
    } else {
        arg.get_id().to_string()
    };

    let arg_type = infer_arg_type(arg);

    let values = if arg_type == "enum" {
        Some(
            arg.get_possible_values()
                .iter()
                .filter_map(|v| {
                    if v.is_hide_set() {
                        None
                    } else {
                        v.get_name_and_aliases().next().map(|s| s.to_string())
                    }
                })
                .collect(),
        )
    } else {
        None
    };

    let default = arg.get_default_values().first().map(|v| {
        let s = v.to_string_lossy();
        match arg_type.as_str() {
            "boolean" => serde_json::Value::Bool(s == "true"),
            "integer" => s
                .parse::<i64>()
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::String(s.to_string())),
            "number" => s
                .parse::<f64>()
                .map(|f| serde_json::json!(f))
                .unwrap_or(serde_json::Value::String(s.to_string())),
            _ => serde_json::Value::String(s.to_string()),
        }
    });

    // Boolean flags with SetTrue action default to false
    let default = if arg_type == "boolean" && default.is_none() {
        Some(serde_json::Value::Bool(false))
    } else {
        default
    };

    let description = arg.get_help().map(|h| h.to_string());

    Some(ArgDescriptor {
        name,
        arg_type,
        description,
        required: arg.is_required_set(),
        default,
        values,
    })
}

// ── Command walking ──────────────────────────────────────────────────

fn is_filtered_subcommand(name: &str) -> bool {
    name == "help" || name == "mtp-describe"
}

/// Recursively walk a `Command` tree, returning leaf commands with
/// space-separated names (e.g. "auth login"). Commands with no visible
/// subcommands are leaves.
pub fn walk_commands(
    cmd: &Command,
    annotations: &HashMap<String, CommandAnnotation>,
    parent_path: Option<&str>,
) -> Vec<CommandDescriptor> {
    let visible_subs: Vec<&Command> = cmd
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set() && !is_filtered_subcommand(sub.get_name()))
        .collect();

    if visible_subs.is_empty() {
        // Leaf command
        let name = parent_path.unwrap_or("_root").to_string();
        vec![build_command_with_annotations(cmd, &name, annotations)]
    } else {
        let mut result = Vec::new();

        // If this command has its own args (beyond help/version), emit
        // a _root entry so they aren't silently dropped.
        let has_own_args = cmd.get_arguments().any(|a| {
            let id = a.get_id().as_str();
            id != "help" && id != "version" && id != "mtp-describe" && !a.is_hide_set()
        });
        if has_own_args && parent_path.is_none() {
            result.push(build_command_with_annotations(cmd, "_root", annotations));
        }

        // Recurse into subcommands
        for sub in visible_subs {
            let path = match parent_path {
                Some(p) => format!("{} {}", p, sub.get_name()),
                None => sub.get_name().to_string(),
            };
            result.extend(walk_commands(sub, annotations, Some(&path)));
        }
        result
    }
}

fn build_command_with_annotations(
    cmd: &Command,
    name: &str,
    annotations: &HashMap<String, CommandAnnotation>,
) -> CommandDescriptor {
    let mut desc = build_command(cmd, name);
    if let Some(ann) = annotations.get(name) {
        if let Some(ref stdin) = ann.stdin {
            desc.stdin = Some(stdin.clone());
        }
        if let Some(ref stdout) = ann.stdout {
            desc.stdout = Some(stdout.clone());
        }
        if !ann.examples.is_empty() {
            desc.examples = ann.examples.clone();
        }
        if let Some(ref auth) = ann.auth {
            desc.auth = Some(auth.clone());
        }
    }
    desc
}

fn build_command(cmd: &Command, name: &str) -> CommandDescriptor {
    let args: Vec<ArgDescriptor> = cmd
        .get_arguments()
        .filter(|a| {
            let id = a.get_id().as_str();
            id != "help" && id != "version" && id != "mtp-describe"
        })
        .filter_map(extract_arg)
        .collect();

    CommandDescriptor {
        name: name.to_string(),
        description: cmd
            .get_about()
            .map(|s| s.to_string())
            .unwrap_or_default(),
        args,
        stdin: None,
        stdout: None,
        examples: vec![],
        auth: None,
    }
}

// ── Schema generation ────────────────────────────────────────────────

/// Extract the full `ToolSchema` from a Clap `Command`.
///
/// This is a pure function with no side effects. Use it for
/// programmatic access or testing.
pub fn describe<T: CommandFactory>(options: Option<&DescribeOptions>) -> ToolSchema {
    let cmd = T::command();
    extract_schema(&cmd, options)
}

/// Extract the full `ToolSchema` from an already-built `Command`.
pub fn extract_schema(cmd: &Command, options: Option<&DescribeOptions>) -> ToolSchema {
    let annotations = options
        .map(|o| &o.commands)
        .cloned()
        .unwrap_or_default();

    let commands = walk_commands(cmd, &annotations, None);

    ToolSchema {
        spec_version: MTP_SPEC_VERSION.to_string(),
        name: cmd.get_name().to_string(),
        version: cmd
            .get_version()
            .map(|s| s.to_string())
            .unwrap_or_default(),
        description: cmd
            .get_about()
            .map(|s| s.to_string())
            .unwrap_or_default(),
        commands,
        auth: options.and_then(|o| o.auth.clone()),
    }
}

// ── Describable trait ────────────────────────────────────────────────

/// Trait for Clap-derived CLI structs to add `--mtp-describe` support.
///
/// Checks `std::env::args()` for `--mtp-describe` before parsing.
/// If found, prints the JSON schema and exits.
/// Otherwise, parses normally and returns the parsed value.
pub trait Describable: Parser {
    fn describable() -> Self {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--mtp-describe") {
            let schema = describe::<Self>(None);
            let json = serde_json::to_string_pretty(&schema).expect("failed to serialize schema");
            println!("{}", json);
            process::exit(0);
        }
        <Self as Parser>::parse()
    }

    /// Generate the schema without side effects.
    fn schema() -> ToolSchema {
        describe::<Self>(None)
    }
}

impl<T: Parser> Describable for T {}

// ── Builder ──────────────────────────────────────────────────────────

/// Builder for attaching examples, IO descriptors, and auth config
/// to commands before checking `--mtp-describe`.
pub struct DescribableBuilder {
    options: DescribeOptions,
}

impl DescribableBuilder {
    pub fn new() -> Self {
        Self {
            options: DescribeOptions::default(),
        }
    }

    fn annotation(&mut self, cmd: &str) -> &mut CommandAnnotation {
        self.options
            .commands
            .entry(cmd.to_string())
            .or_default()
    }

    pub fn example(
        mut self,
        command_name: &str,
        description: &str,
        invocation: &str,
        output: Option<&str>,
    ) -> Self {
        self.annotation(command_name).examples.push(Example {
            description: Some(description.to_string()),
            command: invocation.to_string(),
            output: output.map(|s| s.to_string()),
        });
        self
    }

    pub fn stdin(mut self, command_name: &str, content_type: &str, description: &str) -> Self {
        self.annotation(command_name).stdin = Some(IODescriptor {
            content_type: Some(content_type.to_string()),
            description: Some(description.to_string()),
            schema: None,
        });
        self
    }

    pub fn stdout(mut self, command_name: &str, content_type: &str, description: &str) -> Self {
        self.annotation(command_name).stdout = Some(IODescriptor {
            content_type: Some(content_type.to_string()),
            description: Some(description.to_string()),
            schema: None,
        });
        self
    }

    pub fn stdin_with_schema(
        mut self,
        command_name: &str,
        content_type: &str,
        description: &str,
        schema: serde_json::Value,
    ) -> Self {
        self.annotation(command_name).stdin = Some(IODescriptor {
            content_type: Some(content_type.to_string()),
            description: Some(description.to_string()),
            schema: Some(schema),
        });
        self
    }

    pub fn stdout_with_schema(
        mut self,
        command_name: &str,
        content_type: &str,
        description: &str,
        schema: serde_json::Value,
    ) -> Self {
        self.annotation(command_name).stdout = Some(IODescriptor {
            content_type: Some(content_type.to_string()),
            description: Some(description.to_string()),
            schema: Some(schema),
        });
        self
    }

    /// Set tool-level auth configuration.
    pub fn auth(mut self, config: AuthConfig) -> Self {
        self.options.auth = Some(config);
        self
    }

    /// Set per-command auth overrides.
    pub fn command_auth(mut self, command_name: &str, auth: CommandAuth) -> Self {
        self.annotation(command_name).auth = Some(auth);
        self
    }

    /// Check for `--mtp-describe` (printing schema + exiting if present),
    /// otherwise parse and return the CLI struct.
    pub fn parse<T: Parser>(self) -> T {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--mtp-describe") {
            let schema = describe::<T>(Some(&self.options));
            let json = serde_json::to_string_pretty(&schema).expect("failed to serialize schema");
            println!("{}", json);
            process::exit(0);
        }
        <T as Parser>::parse()
    }

    /// Generate schema without side effects. For testing.
    pub fn schema<T: CommandFactory>(&self) -> ToolSchema {
        describe::<T>(Some(&self.options))
    }
}

impl Default for DescribableBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, ArgAction, ValueHint};

    // ── infer_arg_type ───────────────────────────────────────────

    #[test]
    fn infer_type_boolean() {
        let arg = Arg::new("verbose").long("verbose").action(ArgAction::SetTrue);
        assert_eq!(infer_arg_type(&arg), "boolean");
    }

    #[test]
    fn infer_type_boolean_set_false() {
        let arg = Arg::new("no-color")
            .long("no-color")
            .action(ArgAction::SetFalse);
        assert_eq!(infer_arg_type(&arg), "boolean");
    }

    #[test]
    fn infer_type_enum() {
        let arg = Arg::new("format")
            .long("format")
            .value_parser(["json", "csv", "yaml"]);
        assert_eq!(infer_arg_type(&arg), "enum");
    }

    #[test]
    fn infer_type_path() {
        let arg = Arg::new("file")
            .long("file")
            .value_hint(ValueHint::FilePath);
        assert_eq!(infer_arg_type(&arg), "path");
    }

    #[test]
    fn infer_type_dir_path() {
        let arg = Arg::new("dir")
            .long("dir")
            .value_hint(ValueHint::DirPath);
        assert_eq!(infer_arg_type(&arg), "path");
    }

    #[test]
    fn infer_type_count_is_integer() {
        let arg = Arg::new("verbose").short('v').action(ArgAction::Count);
        assert_eq!(infer_arg_type(&arg), "integer");
    }

    #[test]
    fn infer_type_append_is_array() {
        let arg = Arg::new("file").long("file").action(ArgAction::Append);
        assert_eq!(infer_arg_type(&arg), "array");
    }

    #[test]
    fn infer_type_multi_value_is_array() {
        let arg = Arg::new("files")
            .long("files")
            .num_args(1..=10);
        assert_eq!(infer_arg_type(&arg), "array");
    }

    #[test]
    fn infer_type_integer_i64() {
        let arg = Arg::new("port")
            .long("port")
            .value_parser(clap::value_parser!(i64));
        assert_eq!(infer_arg_type(&arg), "integer");
    }

    #[test]
    fn infer_type_integer_u32() {
        let arg = Arg::new("count")
            .long("count")
            .value_parser(clap::value_parser!(u32));
        assert_eq!(infer_arg_type(&arg), "integer");
    }

    #[test]
    fn infer_type_number_f64() {
        let arg = Arg::new("threshold")
            .long("threshold")
            .value_parser(clap::value_parser!(f64));
        assert_eq!(infer_arg_type(&arg), "number");
    }

    #[test]
    fn infer_type_default_string() {
        let arg = Arg::new("name").long("name");
        assert_eq!(infer_arg_type(&arg), "string");
    }

    // ── extract_arg ──────────────────────────────────────────────

    #[test]
    fn extract_positional_arg() {
        let arg = Arg::new("input").required(true).help("Input file");
        let desc = extract_arg(&arg).unwrap();
        assert_eq!(desc.name, "input");
        assert!(desc.required);
        assert_eq!(desc.description.as_deref(), Some("Input file"));
    }

    #[test]
    fn extract_long_flag() {
        let arg = Arg::new("format")
            .long("format")
            .short('f')
            .help("Output format");
        let desc = extract_arg(&arg).unwrap();
        assert_eq!(desc.name, "--format"); // prefers long
    }

    #[test]
    fn extract_short_only_flag() {
        let arg = Arg::new("verbose").short('v').action(ArgAction::SetTrue);
        let desc = extract_arg(&arg).unwrap();
        assert_eq!(desc.name, "-v");
        assert_eq!(desc.arg_type, "boolean");
    }

    #[test]
    fn extract_default_value() {
        let arg = Arg::new("format")
            .long("format")
            .default_value("json")
            .value_parser(["json", "csv"]);
        let desc = extract_arg(&arg).unwrap();
        assert_eq!(desc.default, Some(serde_json::Value::String("json".to_string())));
        assert_eq!(desc.arg_type, "enum");
        assert_eq!(desc.values, Some(vec!["json".to_string(), "csv".to_string()]));
    }

    #[test]
    fn extract_boolean_default_false() {
        let arg = Arg::new("pretty").long("pretty").action(ArgAction::SetTrue);
        let desc = extract_arg(&arg).unwrap();
        assert_eq!(desc.default, Some(serde_json::Value::Bool(false)));
    }

    #[test]
    fn extract_hidden_arg_returns_none() {
        let arg = Arg::new("secret").long("secret").hide(true);
        assert!(extract_arg(&arg).is_none());
    }

    #[test]
    fn extract_required_flag() {
        let arg = Arg::new("token").long("token").required(true);
        let desc = extract_arg(&arg).unwrap();
        assert!(desc.required);
    }

    // ── walk_commands ────────────────────────────────────────────

    fn simple_cmd() -> Command {
        Command::new("mytool")
            .version("1.0.0")
            .about("A tool")
            .arg(Arg::new("input").required(true).help("Input file"))
    }

    fn multi_cmd() -> Command {
        Command::new("filetool")
            .version("1.2.0")
            .about("File operations")
            .subcommand(
                Command::new("convert")
                    .about("Convert files")
                    .arg(Arg::new("input").required(true))
                    .arg(
                        Arg::new("format")
                            .long("format")
                            .default_value("json")
                            .value_parser(["json", "csv"]),
                    ),
            )
            .subcommand(
                Command::new("validate")
                    .about("Validate files")
                    .arg(Arg::new("file").required(true)),
            )
    }

    #[test]
    fn walk_single_command_produces_root() {
        let cmd = simple_cmd();
        let result = walk_commands(&cmd, &HashMap::new(), None);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "_root");
        assert_eq!(result[0].args.len(), 1);
        assert_eq!(result[0].args[0].name, "input");
    }

    #[test]
    fn walk_multi_command_produces_subcommand_names() {
        let cmd = multi_cmd();
        let result = walk_commands(&cmd, &HashMap::new(), None);
        assert_eq!(result.len(), 2);
        let names: Vec<&str> = result.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"convert"));
        assert!(names.contains(&"validate"));
    }

    #[test]
    fn walk_nested_commands_space_separated() {
        let cmd = Command::new("tool")
            .subcommand(
                Command::new("auth")
                    .about("Auth commands")
                    .subcommand(Command::new("login").about("Log in"))
                    .subcommand(Command::new("logout").about("Log out")),
            );
        let result = walk_commands(&cmd, &HashMap::new(), None);
        assert_eq!(result.len(), 2);
        let names: Vec<&str> = result.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"auth login"));
        assert!(names.contains(&"auth logout"));
    }

    #[test]
    fn walk_deeply_nested_commands() {
        let cmd = Command::new("tool")
            .subcommand(
                Command::new("a")
                    .subcommand(
                        Command::new("b")
                            .subcommand(Command::new("c").about("Deep")),
                    ),
            );
        let result = walk_commands(&cmd, &HashMap::new(), None);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "a b c");
    }

    #[test]
    fn walk_filters_hidden_subcommands() {
        let cmd = Command::new("tool")
            .subcommand(Command::new("visible").about("Visible"))
            .subcommand(Command::new("hidden").about("Hidden").hide(true));
        let result = walk_commands(&cmd, &HashMap::new(), None);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "visible");
    }

    #[test]
    fn walk_merges_annotations() {
        let mut annotations = HashMap::new();
        annotations.insert(
            "convert".to_string(),
            CommandAnnotation {
                stdin: Some(IODescriptor {
                    content_type: Some("text/plain".to_string()),
                    description: Some("Raw input".to_string()),
                    schema: None,
                }),
                stdout: None,
                examples: vec![Example {
                    description: Some("Convert CSV".to_string()),
                    command: "filetool convert data.csv".to_string(),
                    output: None,
                }],
                auth: Some(CommandAuth {
                    required: Some(true),
                    scopes: Some(vec!["read".to_string()]),
                }),
            },
        );

        let cmd = multi_cmd();
        let result = walk_commands(&cmd, &annotations, None);
        let convert = result.iter().find(|c| c.name == "convert").unwrap();
        assert!(convert.stdin.is_some());
        assert_eq!(convert.examples.len(), 1);
        assert!(convert.auth.is_some());
        assert_eq!(convert.auth.as_ref().unwrap().required, Some(true));
    }

    #[test]
    fn walk_filters_hidden_args() {
        let cmd = Command::new("tool")
            .arg(Arg::new("visible").long("visible"))
            .arg(Arg::new("hidden").long("hidden").hide(true));
        let result = walk_commands(&cmd, &HashMap::new(), None);
        assert_eq!(result.len(), 1);
        let arg_names: Vec<&str> = result[0].args.iter().map(|a| a.name.as_str()).collect();
        assert!(arg_names.contains(&"--visible"));
        assert!(!arg_names.contains(&"--hidden"));
    }

    #[test]
    fn walk_root_args_with_subcommands() {
        let cmd = Command::new("tool")
            .arg(Arg::new("debug").long("debug").action(ArgAction::SetTrue))
            .subcommand(Command::new("run").about("Run it"))
            .subcommand(Command::new("build").about("Build it"));
        let result = walk_commands(&cmd, &HashMap::new(), None);
        assert_eq!(result.len(), 3);
        let names: Vec<&str> = result.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"_root"));
        assert!(names.contains(&"run"));
        assert!(names.contains(&"build"));
        let root = result.iter().find(|c| c.name == "_root").unwrap();
        assert_eq!(root.args.len(), 1);
        assert_eq!(root.args[0].name, "--debug");
    }

    #[test]
    fn walk_no_root_args_with_subcommands() {
        // No _root emitted when parent has no visible args
        let cmd = Command::new("tool")
            .subcommand(Command::new("run").about("Run it"));
        let result = walk_commands(&cmd, &HashMap::new(), None);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "run");
    }

    #[test]
    fn example_description_is_optional() {
        let ex = Example {
            description: None,
            command: "mytool run".to_string(),
            output: None,
        };
        let json = serde_json::to_value(&ex).unwrap();
        assert!(json.get("description").is_none());
        assert_eq!(json.get("command").unwrap(), "mytool run");
    }

    // ── extract_schema / describe ────────────────────────────────

    #[test]
    fn extract_schema_basic() {
        let cmd = multi_cmd();
        let schema = extract_schema(&cmd, None);
        assert_eq!(schema.spec_version, MTP_SPEC_VERSION);
        assert_eq!(schema.name, "filetool");
        assert_eq!(schema.version, "1.2.0");
        assert_eq!(schema.commands.len(), 2);
        assert!(schema.auth.is_none());
    }

    #[test]
    fn extract_schema_with_auth() {
        let cmd = simple_cmd();
        let opts = DescribeOptions {
            commands: HashMap::new(),
            auth: Some(AuthConfig {
                required: Some(true),
                env_var: "MY_TOKEN".to_string(),
                providers: vec![AuthProvider {
                    id: "api-key".to_string(),
                    provider_type: "api-key".to_string(),
                    display_name: None,
                    authorization_url: None,
                    token_url: None,
                    scopes: None,
                    client_id: None,
                    registration_url: Some("https://example.com/keys".to_string()),
                    instructions: Some("Get a key".to_string()),
                }],
            }),
        };
        let schema = extract_schema(&cmd, Some(&opts));
        assert!(schema.auth.is_some());
        let auth = schema.auth.unwrap();
        assert_eq!(auth.env_var, "MY_TOKEN");
        assert_eq!(auth.providers.len(), 1);
        assert_eq!(auth.providers[0].provider_type, "api-key");
    }

    #[test]
    fn extract_schema_no_version_defaults_empty() {
        let cmd = Command::new("bare").about("No version");
        let schema = extract_schema(&cmd, None);
        assert_eq!(schema.version, "");
    }

    // ── describe() pure function ─────────────────────────────────

    #[derive(Parser)]
    #[command(name = "testtool", version = "2.0.0", about = "Test tool")]
    struct TestCli {
        /// Input file
        input: String,
        /// Be verbose
        #[arg(long)]
        verbose: bool,
    }

    #[test]
    fn describe_pure_function() {
        let schema = describe::<TestCli>(None);
        assert_eq!(schema.spec_version, MTP_SPEC_VERSION);
        assert_eq!(schema.name, "testtool");
        assert_eq!(schema.version, "2.0.0");
        assert_eq!(schema.commands.len(), 1);
        assert_eq!(schema.commands[0].name, "_root");
        assert_eq!(schema.commands[0].args.len(), 2);
    }

    // ── DescribableBuilder ───────────────────────────────────────

    #[derive(Parser)]
    #[command(name = "buildertool", version = "1.0.0", about = "Builder test")]
    enum BuilderCli {
        /// Do stuff
        Doit {
            /// Input
            input: String,
        },
    }

    #[test]
    fn builder_attaches_examples() {
        let builder = DescribableBuilder::new().example(
            "doit",
            "Run it",
            "buildertool doit foo.txt",
            Some("done"),
        );
        let schema = builder.schema::<BuilderCli>();
        let cmd = &schema.commands[0];
        assert_eq!(cmd.examples.len(), 1);
        assert_eq!(cmd.examples[0].description, Some("Run it".to_string()));
        assert_eq!(cmd.examples[0].output, Some("done".to_string()));
    }

    #[test]
    fn builder_attaches_io() {
        let builder = DescribableBuilder::new()
            .stdin("doit", "text/plain", "Raw text")
            .stdout("doit", "application/json", "JSON output");
        let schema = builder.schema::<BuilderCli>();
        let cmd = &schema.commands[0];
        assert!(cmd.stdin.is_some());
        assert_eq!(
            cmd.stdin.as_ref().unwrap().content_type,
            Some("text/plain".to_string())
        );
        assert!(cmd.stdout.is_some());
    }

    #[test]
    fn builder_attaches_io_with_schema() {
        let json_schema = serde_json::json!({"type": "object"});
        let builder = DescribableBuilder::new().stdin_with_schema(
            "doit",
            "application/json",
            "JSON input",
            json_schema.clone(),
        );
        let schema = builder.schema::<BuilderCli>();
        let cmd = &schema.commands[0];
        assert_eq!(cmd.stdin.as_ref().unwrap().schema, Some(json_schema));
    }

    #[test]
    fn builder_attaches_auth() {
        let builder = DescribableBuilder::new()
            .auth(AuthConfig {
                required: Some(true),
                env_var: "TOKEN".to_string(),
                providers: vec![AuthProvider {
                    id: "gh".to_string(),
                    provider_type: "oauth2".to_string(),
                    display_name: Some("GitHub".to_string()),
                    authorization_url: Some("https://github.com/login/oauth/authorize".to_string()),
                    token_url: Some("https://github.com/login/oauth/access_token".to_string()),
                    scopes: Some(vec!["repo".to_string()]),
                    client_id: Some("abc123".to_string()),
                    registration_url: None,
                    instructions: None,
                }],
            })
            .command_auth(
                "doit",
                CommandAuth {
                    required: Some(true),
                    scopes: Some(vec!["write".to_string()]),
                },
            );
        let schema = builder.schema::<BuilderCli>();
        assert!(schema.auth.is_some());
        assert_eq!(schema.auth.as_ref().unwrap().env_var, "TOKEN");

        let cmd = &schema.commands[0];
        assert!(cmd.auth.is_some());
        assert_eq!(
            cmd.auth.as_ref().unwrap().scopes,
            Some(vec!["write".to_string()])
        );
    }

    // ── JSON serialization ───────────────────────────────────────

    #[test]
    fn io_descriptor_serializes_camel_case() {
        let io = IODescriptor {
            content_type: Some("application/json".to_string()),
            description: Some("JSON data".to_string()),
            schema: None,
        };
        let json = serde_json::to_value(&io).unwrap();
        assert!(json.get("contentType").is_some());
        assert!(json.get("content_type").is_none());
    }

    #[test]
    fn auth_config_serializes_camel_case() {
        let auth = AuthConfig {
            required: Some(true),
            env_var: "TOKEN".to_string(),
            providers: vec![],
        };
        let json = serde_json::to_value(&auth).unwrap();
        assert!(json.get("envVar").is_some());
        assert!(json.get("env_var").is_none());
    }

    #[test]
    fn auth_provider_serializes_camel_case() {
        let provider = AuthProvider {
            id: "gh".to_string(),
            provider_type: "oauth2".to_string(),
            display_name: Some("GitHub".to_string()),
            authorization_url: Some("https://example.com/auth".to_string()),
            token_url: Some("https://example.com/token".to_string()),
            scopes: None,
            client_id: None,
            registration_url: None,
            instructions: None,
        };
        let json = serde_json::to_value(&provider).unwrap();
        assert!(json.get("displayName").is_some());
        assert!(json.get("authorizationUrl").is_some());
        assert!(json.get("tokenUrl").is_some());
        assert!(json.get("type").is_some()); // renamed from provider_type
    }

    #[test]
    fn full_schema_json_roundtrip() {
        let schema = describe::<TestCli>(None);
        let json_str = serde_json::to_string(&schema).unwrap();
        let parsed: ToolSchema = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.spec_version, MTP_SPEC_VERSION);
        assert_eq!(parsed.name, "testtool");
        assert_eq!(parsed.commands.len(), 1);

        // Verify specVersion appears in serialized JSON (camelCase)
        let json_val: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(json_val.get("specVersion").is_some());
        assert!(json_val.get("spec_version").is_none());
    }
}
