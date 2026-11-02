//! Reports panics, and gets the report out before the process dies.
//!
//! The release profile sets `panic = "abort"`: once the panic hook returns the
//! process aborts, and an event still sitting in the client's queue is lost.
//! The hook therefore flushes the client before it returns.
//!
//! The hook is installed once for the life of the process and does nothing
//! while no client is bound, so restarting the client never stacks hooks.

use std::panic::{self, PanicHookInfo};
use std::sync::Once;

use sentry_panic::PanicIntegration;

use super::client::{hub, FLUSH_TIMEOUT};

static INSTALL: Once = Once::new();

/// Chains the reporting hook in front of the current one. Safe to call again.
pub fn install() {
    INSTALL.call_once(|| {
        let next = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            report(info);
            next(info);
        }));
    });
}

/// Captures the panic and waits for the queue to be sent.
fn report(info: &PanicHookInfo<'_>) {
    let hub = hub();
    let Some(client) = hub.client() else { return };
    hub.capture_event(PanicIntegration::new().event_from_panic_info(info));
    client.flush(Some(FLUSH_TIMEOUT));
}
