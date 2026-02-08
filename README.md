# mtp-sdk

Rust SDK for the [Model Tools Protocol](https://github.com/modeltoolsprotocol/modeltoolsprotocol). Makes any Clap-based CLI tool LLM-discoverable with `--mtp-describe`.

## Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
mtp-sdk = "0.1"
clap = { version = "4", features = ["derive"] }
```

Use the `Describable` trait for zero-config `--mtp-describe` support:

```rust
use clap::Parser;
use mtp_sdk::Describable;

#[derive(Parser)]
#[command(name = "mytool", version = "1.0.0", about = "Does things")]
struct Cli {
    /// Input file
    input: String,
    /// Be verbose
    #[arg(long)]
    verbose: bool,
}

fn main() {
    // Checks for --mtp-describe, prints schema + exits if present.
    // Otherwise parses normally.
    let cli = Cli::describable();
}
```

Running `mytool --mtp-describe` outputs:

```json
{
  "name": "mytool",
  "version": "1.0.0",
  "specVersion": "2026-02-07",
  "description": "Does things",
  "commands": [
    {
      "name": "_root",
      "description": "Does things",
      "args": [
        { "name": "input", "type": "string", "description": "Input file", "required": true },
        { "name": "--verbose", "type": "boolean", "description": "Be verbose", "required": false, "default": false }
      ]
    }
  ]
}
```

## Adding examples and IO descriptors

Use `DescribableBuilder` for richer metadata:

```rust
use clap::Parser;
use mtp_sdk::DescribableBuilder;

#[derive(Parser)]
#[command(name = "filetool", version = "1.0.0", about = "File operations")]
enum Cli {
    /// Convert a file
    Convert {
        /// Input file path
        input: String,
        #[arg(short, long, default_value = "json", value_parser = ["json", "csv"])]
        format: String,
    },
}

fn main() {
    let cli: Cli = DescribableBuilder::new()
        .example("convert", "Convert CSV to JSON", "filetool convert data.csv --format json", None)
        .stdin("convert", "text/plain", "Raw input data")
        .stdout("convert", "application/json", "Converted output")
        .parse();
}
```

## Authentication

Declare auth requirements so LLM orchestrators know how to authenticate:

```rust
use mtp_sdk::{AuthConfig, AuthProvider, CommandAuth, DescribableBuilder};

let cli: Cli = DescribableBuilder::new()
    .auth(AuthConfig {
        required: Some(true),
        env_var: "MY_TOKEN".to_string(),
        providers: vec![
            AuthProvider {
                id: "github".to_string(),
                provider_type: "oauth2".to_string(),
                display_name: Some("GitHub".to_string()),
                authorization_url: Some("https://github.com/login/oauth/authorize".to_string()),
                token_url: Some("https://github.com/login/oauth/access_token".to_string()),
                scopes: Some(vec!["repo".to_string()]),
                client_id: Some("your-client-id".to_string()),
                registration_url: None,
                instructions: None,
            },
        ],
    })
    .command_auth("admin", CommandAuth {
        required: Some(true),
        scopes: Some(vec!["admin".to_string()]),
    })
    .parse();
```

## Programmatic access

Use `describe()` for testing or programmatic schema generation without side effects:

```rust
use mtp_sdk::describe;

let schema = describe::<Cli>(None);
assert_eq!(schema.name, "mytool");
```

Or with options:

```rust
use mtp_sdk::{describe, DescribeOptions};

let opts = DescribeOptions { ..Default::default() };
let schema = describe::<Cli>(Some(&opts));
```

## Type inference

Arg types describe flags and positional arguments, which are always scalar on the command line:

| Clap construct | MTP type |
|---|---|
| `ArgAction::SetTrue` / `SetFalse` | `boolean` |
| `ArgAction::Count` | `integer` |
| `ArgAction::Append` / multi-value | `array` |
| `value_parser(["a", "b"])` | `enum` |
| `ValueHint::FilePath` / `DirPath` | `path` |
| `value_parser!(i32)`, `u64`, etc. | `integer` |
| `value_parser!(f64)`, `f32` | `number` |
| Everything else | `string` |

For structured data flowing through stdin/stdout, IO descriptors support full JSON Schema (draft 2020-12): nested objects, arrays, unions, pattern validation, conditional fields.

## Structured IO

When a command accepts or produces JSON, describe the shape with a schema:

```rust
let cli: Cli = DescribableBuilder::new()
    .stdin_with_schema("process", "application/json", "Configuration to process",
        serde_json::json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "settings": {
                    "type": "object",
                    "properties": {
                        "retries": { "type": "integer" },
                        "endpoints": {
                            "type": "array",
                            "items": { "type": "string", "format": "uri" }
                        }
                    }
                }
            },
            "required": ["name"]
        })
    )
    .stdout_with_schema("process", "application/json", "Processing results",
        serde_json::json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["ok", "error"] },
                "results": { "type": "array", "items": { "type": "object" } }
            }
        })
    )
    .parse();
```

## License

Apache-2.0
