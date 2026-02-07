//! Example CLI tool demonstrating mtp-sdk with auth support.
//!
//! Run:
//!   cargo run --example filetool -- --describe
//!   cargo run --example filetool -- convert data.csv --format json

use clap::Parser;
use mtp_sdk::{AuthConfig, AuthProvider, CommandAuth, DescribableBuilder};

#[derive(Parser)]
#[command(
    name = "filetool",
    version = "1.2.0",
    about = "Convert and validate files between formats"
)]
enum Cli {
    /// Convert a file from one format to another
    Convert {
        /// Input file path
        input_file: String,

        /// Output format
        #[arg(short, long, default_value = "json", value_parser = ["json", "csv", "yaml"])]
        format: String,

        /// Pretty-print output
        #[arg(long)]
        pretty: bool,
    },

    /// Check if a file is well-formed and valid
    Validate {
        /// File to validate
        input_file: String,

        /// Enable strict validation mode
        #[arg(long)]
        strict: bool,
    },

    /// Process structured JSON input from stdin
    Process {
        /// Enable verbose output
        #[arg(long)]
        verbose: bool,
    },
}

fn main() {
    let cli: Cli = DescribableBuilder::new()
        .example(
            "convert",
            "Convert a CSV file to JSON",
            "filetool convert data.csv --format json --pretty",
            Some("[{\n  \"name\": \"Alice\",\n  \"age\": 30\n}]"),
        )
        .example(
            "convert",
            "Pipe from stdin",
            "cat data.csv | filetool convert - --format yaml",
            None,
        )
        .stdin(
            "convert",
            "text/plain",
            "Raw input data (alternative to file path)",
        )
        .stdout("convert", "application/json", "Converted output")
        .example(
            "validate",
            "Validate a JSON file",
            "filetool validate config.json",
            Some("{\"valid\": true, \"errors\": []}"),
        )
        .example(
            "process",
            "Process a JSON object from stdin",
            "echo '{\"name\":\"foo\",\"count\":3}' | filetool process",
            Some("{\"status\": \"ok\", \"processed\": \"foo\"}"),
        )
        .stdin_with_schema(
            "process",
            "application/json",
            "JSON object to process",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Item name"},
                    "count": {"type": "integer", "description": "Number of items"}
                },
                "required": ["name"]
            }),
        )
        .stdout("process", "application/json", "Processing result")
        .auth(AuthConfig {
            required: Some(false),
            env_var: "FILETOOL_TOKEN".to_string(),
            providers: vec![
                AuthProvider {
                    id: "github".to_string(),
                    provider_type: "oauth2".to_string(),
                    display_name: Some("GitHub".to_string()),
                    authorization_url: Some(
                        "https://github.com/login/oauth/authorize".to_string(),
                    ),
                    token_url: Some(
                        "https://github.com/login/oauth/access_token".to_string(),
                    ),
                    scopes: Some(vec!["repo".to_string(), "read:user".to_string()]),
                    client_id: Some("Ov23lixyz".to_string()),
                    registration_url: None,
                    instructions: None,
                },
                AuthProvider {
                    id: "api-key".to_string(),
                    provider_type: "api-key".to_string(),
                    display_name: Some("API Key".to_string()),
                    authorization_url: None,
                    token_url: None,
                    scopes: None,
                    client_id: None,
                    registration_url: Some("https://example.com/settings/keys".to_string()),
                    instructions: Some(
                        "Create a key at https://example.com/settings/keys".to_string(),
                    ),
                },
            ],
        })
        .command_auth(
            "process",
            CommandAuth {
                required: Some(true),
                scopes: Some(vec!["write".to_string()]),
            },
        )
        .parse();

    match cli {
        Cli::Convert {
            input_file,
            format,
            pretty,
        } => {
            println!(
                "Converting {} to {}{}",
                input_file,
                format,
                if pretty { " (pretty)" } else { "" }
            );
        }
        Cli::Validate {
            input_file,
            strict,
        } => {
            println!(
                "Validating {}{}",
                input_file,
                if strict { " (strict)" } else { "" }
            );
        }
        Cli::Process { verbose } => {
            println!("Processing (verbose={})", verbose);
        }
    }
}
