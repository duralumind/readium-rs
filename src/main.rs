use clap::{Parser, Subcommand};
use lcp_rs::{DecryptionInput, decrypt_epub, encrypt_epub, license::EncryptionProfile};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "lcp-rs")]
#[command(about = "LCP DRM encryption/decryption for EPUB files")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt an EPUB file using LCP DRM
    Encrypt {
        /// Path to the input EPUB file
        input: PathBuf,

        /// User password for encryption
        #[arg(long)]
        password: String,

        /// User password hint
        #[arg(long)]
        password_hint: String,

        /// Encryption profile to use
        #[arg(long)]
        profile: EncryptionProfile,

        /// Output path (optional, defaults to <input>.encrypted.epub)
        #[arg(long)]
        output: Option<PathBuf>,
    },

    /// Decrypt an LCP-protected EPUB file
    Decrypt {
        /// Path to the encrypted EPUB (with embedded .lcpl)
        #[arg(long, conflicts_with = "lcpl")]
        input: Option<PathBuf>,

        /// Path to the lcpl file which contains the link to the publication
        #[arg(long, conflicts_with = "input")]
        lcpl: Option<PathBuf>,

        /// User password for decryption
        #[arg(long)]
        password: String,

        /// Encryption profile used
        #[arg(long)]
        profile: EncryptionProfile,

        /// Output path (optional, defaults to <input>.decrypted.epub)
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            input,
            password,
            password_hint,
            profile,
            output,
        } => encrypt_epub(input, password, password_hint, profile, output).unwrap(),
        Commands::Decrypt {
            input,
            lcpl,
            password,
            profile,
            output,
        } => {
            let decryption_input = match (input, lcpl) {
                (Some(path), None) => DecryptionInput::EmbeddedEpub(path),
                (None, Some(path)) => DecryptionInput::Lcpl(path),
                (None, None) => {
                    eprintln!("Error: Either --input or --lcpl must be provided");
                    std::process::exit(1);
                }
                (Some(_), Some(_)) => unreachable!("clap conflicts_with prevents this"),
            };
            decrypt_epub(decryption_input, password, profile, output).unwrap()
        }
    }
}
