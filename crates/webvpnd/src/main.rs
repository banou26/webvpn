use std::io::IsTerminal;

use anyhow::{Context, Result};
use tokio::signal::unix::{signal, SignalKind};
use tracing::warn;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use webvpnd::{Daemon, Settings};

#[tokio::main]
async fn main() -> Result<()> {
    // Before anything else: the relay may be process 1 of its container, which the kernel hands a SIGTERM only
    // through a handler, and a tokio `Signal` made later does not see one that came before it (tokio's
    // `signal/registry.rs`, a watch `subscribe`).
    let mut terminate = signal(SignalKind::terminate()).context("the SIGTERM handler could not be installed")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("the SIGINT handler could not be installed")?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy())
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    let settings = Settings::from_env()?;
    raise_open_files(settings.policy.max_sockets);
    let stop = async {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    };
    Daemon::start(settings).await?.run(stop).await;
    Ok(())
}

/// Every socket a client holds is an open file, so the limit is raised as far as the system lets it.
fn raise_open_files(max_sockets: usize) {
    match rlimit::increase_nofile_limit(rlimit::INFINITY) {
        Ok(limit) if limit < max_sockets as u64 => {
            warn!("the open-files limit is {limit}, under WEBVPN_MAX_SOCKETS ({max_sockets}): sockets will fail first")
        }
        Ok(_) => {}
        Err(error) => warn!("the open-files limit could not be raised: {error}"),
    }
}
