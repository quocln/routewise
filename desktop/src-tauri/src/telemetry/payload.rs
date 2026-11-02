//! Applies the scrubber to every Sentry payload that carries text, and strips
//! the fields that identify the machine or the user. Each function edits the
//! value it is given and returns it, the shape the client's `before_*` hooks
//! want.

use std::collections::BTreeMap;

use sentry::protocol::{Breadcrumb, Context, Event, Frame, Log, LogAttribute, Stacktrace, Value};

use super::scrubber::PrivacyScrubber;

/// An error event: message, exceptions and their frames, threads, tags, extra,
/// contexts, breadcrumbs, transaction name. The user, request and server name
/// are dropped, and so is the device name (the machine's hostname, often the
/// owner's name).
pub fn scrub_event(s: &PrivacyScrubber, mut event: Event<'static>) -> Event<'static> {
    event.user = None;
    event.request = None;
    event.server_name = None;
    event.culprit = None;
    event.modules.clear();

    event.message = event.message.map(|m| s.scrub(&m));
    if let Some(entry) = event.logentry.as_mut() {
        entry.message = s.scrub(&entry.message);
        entry.params = std::mem::take(&mut entry.params).into_iter().map(|p| s.scrub_value(p)).collect();
    }
    event.transaction = event.transaction.map(|t| s.scrub(&t));
    event.logger = event.logger.map(|l| s.scrub(&l));
    event.fingerprint = event.fingerprint.iter().map(|f| s.scrub(f).into()).collect::<Vec<_>>().into();

    for exception in event.exception.values.iter_mut() {
        exception.ty = s.scrub(&exception.ty);
        exception.value = exception.value.take().map(|v| s.scrub(&v));
        exception.module = exception.module.take().map(|m| s.scrub(&m));
        scrub_stacktrace(s, exception.stacktrace.as_mut());
        scrub_stacktrace(s, exception.raw_stacktrace.as_mut());
    }
    for thread in event.threads.values.iter_mut() {
        thread.name = thread.name.take().map(|n| s.scrub(&n));
        scrub_stacktrace(s, thread.stacktrace.as_mut());
        scrub_stacktrace(s, thread.raw_stacktrace.as_mut());
    }
    scrub_stacktrace(s, event.stacktrace.as_mut());

    event.tags = std::mem::take(&mut event.tags).into_iter().map(|(k, v)| (s.scrub(&k), s.scrub(&v))).collect();
    event.extra = scrub_entries(s, std::mem::take(&mut event.extra));
    event.contexts = std::mem::take(&mut event.contexts)
        .into_iter()
        .filter_map(|(name, ctx)| scrub_context(s, ctx).map(|ctx| (s.scrub(&name), ctx)))
        .collect();
    event.breadcrumbs.values = std::mem::take(&mut event.breadcrumbs.values)
        .into_iter()
        .map(|crumb| scrub_breadcrumb(s, crumb))
        .collect();
    event
}

pub fn scrub_breadcrumb(s: &PrivacyScrubber, mut crumb: Breadcrumb) -> Breadcrumb {
    crumb.message = crumb.message.map(|m| s.scrub(&m));
    crumb.category = crumb.category.map(|c| s.scrub(&c));
    crumb.data = scrub_entries(s, std::mem::take(&mut crumb.data));
    crumb
}

/// A log record: the body and every attribute. Attributes of other types hold
/// numbers and flags, which pass through `scrub_value` unchanged. The server
/// address attribute the client adds on its own is dropped.
pub fn scrub_log(s: &PrivacyScrubber, mut log: Log) -> Log {
    log.body = s.scrub(&log.body);
    log.attributes = std::mem::take(&mut log.attributes)
        .into_iter()
        .filter(|(key, _)| key != "sentry.server.address")
        .map(|(key, LogAttribute(value))| (s.scrub(&key), LogAttribute(s.scrub_value(value))))
        .collect();
    log
}

/// A JSON map with its keys and every string inside scrubbed.
fn scrub_entries(s: &PrivacyScrubber, map: BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    map.into_iter().map(|(k, v)| (s.scrub(&k), s.scrub_value(v))).collect()
}

fn scrub_stacktrace(s: &PrivacyScrubber, trace: Option<&mut Stacktrace>) {
    let Some(trace) = trace else { return };
    for frame in trace.frames.iter_mut() {
        scrub_frame(s, frame);
    }
}

fn scrub_frame(s: &PrivacyScrubber, frame: &mut Frame) {
    for field in [
        &mut frame.function,
        &mut frame.symbol,
        &mut frame.module,
        &mut frame.package,
        &mut frame.filename,
        &mut frame.abs_path,
        &mut frame.context_line,
    ] {
        *field = field.take().map(|v| s.scrub(&v));
    }
    for line in frame.pre_context.iter_mut().chain(frame.post_context.iter_mut()) {
        *line = s.scrub(line);
    }
    frame.vars = scrub_entries(s, std::mem::take(&mut frame.vars));
}

/// A context with its text scrubbed, or None when it cannot be handled: a
/// context that is not understood is dropped rather than sent as it is.
fn scrub_context(s: &PrivacyScrubber, mut ctx: Context) -> Option<Context> {
    match &mut ctx {
        Context::Device(device) => device.name = None,
        Context::Other(map) => {
            *map = scrub_entries(s, std::mem::take(map));
            return Some(ctx);
        }
        // Trace ids are hex and carry no names.
        Context::Trace(_) => return Some(ctx),
        _ => {}
    }
    let scrubbed = s.scrub_value(serde_json::to_value(&ctx).ok()?);
    serde_json::from_value::<Context>(scrubbed).ok()
}
