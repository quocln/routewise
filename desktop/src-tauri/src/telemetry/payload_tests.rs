use sentry::protocol::{
    Breadcrumb, Context, DeviceContext, Event, Exception, Frame, Log, LogAttribute, LogEntry, LogLevel,
    Request, Stacktrace, User, Value,
};

use super::payload::{scrub_breadcrumb, scrub_event, scrub_log};
use super::scrubber::{PrivacyScrubber, PLACEHOLDER as R};

fn scrubber() -> PrivacyScrubber {
    PrivacyScrubber::new(&["Acme".to_string()])
}

fn crumb() -> Breadcrumb {
    let mut crumb = Breadcrumb { category: Some("net".into()), message: Some("to example.com".into()), ..Default::default() };
    crumb.data.insert("host".into(), "example.com".into());
    crumb.data.insert("port".into(), 443.into());
    crumb
}

fn sensitive_event() -> Event<'static> {
    let mut event = Event { level: sentry::Level::Error, ..Default::default() };
    event.message = Some("failed for Acme at 10.0.0.1".into());
    event.logentry = Some(LogEntry { message: "dial example.com".into(), params: vec!["a.example.org".into()] });
    event.user = Some(User { id: Some("u".into()), ..Default::default() });
    event.request = Some(Request::default());
    event.server_name = Some("kevins-mac.local".into());
    event.transaction = Some("GET example.com".into());
    event.tags.insert("host".into(), "a.example.com".into());
    event.extra.insert("ip".into(), "10.2.3.4".into());
    event.extra.insert("n".into(), 1.into());
    event.contexts.insert(
        "device".into(),
        Context::Device(Box::new(DeviceContext {
            name: Some("Kevin's Mac".into()),
            model: Some("Mac14,2".into()),
            ..Default::default()
        })),
    );
    event.contexts.insert("app".into(), Context::Other([("note".to_string(), Value::from("Acme"))].into()));
    event.exception = vec![Exception {
        ty: "ClientError".into(),
        value: Some("dns example.com failed".into()),
        stacktrace: Some(Stacktrace {
            frames: vec![Frame {
                function: Some("routewise_desktop_lib::rpc::client::call".into()),
                filename: Some("client.rs".into()),
                abs_path: Some("/Users/kevin/dev/routewise/src/rpc/client.rs".into()),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }]
    .into();
    event.breadcrumbs.values.push(crumb());
    event
}

#[test]
fn scrubs_event_fields_and_drops_identity() {
    let event = scrub_event(&scrubber(), sensitive_event());

    assert_eq!(event.message.as_deref(), Some(format!("failed for {R} at {R}").as_str()));
    assert!(event.user.is_none());
    assert!(event.request.is_none());
    assert!(event.server_name.is_none());
    assert_eq!(event.transaction.as_deref(), Some(format!("GET {R}").as_str()));
    let entry = event.logentry.unwrap();
    assert_eq!(entry.message, format!("dial {R}"));
    assert_eq!(entry.params[0], R);
    assert_eq!(event.tags["host"], R);
    assert_eq!(event.extra["ip"], R);
    assert_eq!(event.extra["n"], 1);
    match &event.contexts["device"] {
        Context::Device(device) => {
            assert!(device.name.is_none());
            assert_eq!(device.model.as_deref(), Some("Mac14,2"));
        }
        other => panic!("device context became {other:?}"),
    }
    match &event.contexts["app"] {
        Context::Other(map) => assert_eq!(map["note"], R),
        other => panic!("app context became {other:?}"),
    }
    let exception = &event.exception.values[0];
    assert_eq!(exception.value.as_deref(), Some(format!("dns {R} failed").as_str()));
    assert_eq!(exception.ty, "ClientError");
    let frame = &exception.stacktrace.as_ref().unwrap().frames[0];
    assert_eq!(frame.abs_path.as_deref(), Some(format!("/Users/{R}/dev/routewise/src/rpc/client.rs").as_str()));
    assert_eq!(frame.filename.as_deref(), Some("client.rs"));
    assert_eq!(event.breadcrumbs.values[0].message.as_deref(), Some(format!("to {R}").as_str()));
}

#[test]
fn scrubs_breadcrumb() {
    let crumb = scrub_breadcrumb(&PrivacyScrubber::default(), crumb());
    assert_eq!(crumb.message.as_deref(), Some(format!("to {R}").as_str()));
    assert_eq!(crumb.data["host"], R);
    assert_eq!(crumb.data["port"], 443);
}

#[test]
fn scrubs_log_body_and_attributes_and_drops_the_server_address() {
    let mut log = Log {
        level: LogLevel::Warn,
        body: "cannot reach 10.0.0.9".into(),
        trace_id: None,
        timestamp: std::time::SystemTime::now(),
        severity_number: None,
        attributes: Default::default(),
    };
    log.attributes.insert("category".into(), LogAttribute("vpn.example.com".into()));
    log.attributes.insert("count".into(), LogAttribute(2.into()));
    log.attributes.insert("sentry.server.address".into(), LogAttribute("kevins-mac".into()));

    let log = scrub_log(&PrivacyScrubber::default(), log);
    assert_eq!(log.body, format!("cannot reach {R}"));
    assert_eq!(log.attributes["category"].0, R);
    assert_eq!(log.attributes["count"].0, 2);
    assert!(!log.attributes.contains_key("sentry.server.address"));
}
