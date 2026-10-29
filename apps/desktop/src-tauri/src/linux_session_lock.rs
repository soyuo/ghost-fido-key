use gio::prelude::*;
use gio::{BusType, DBusCallFlags, DBusConnection, DBusSignalFlags, SignalSubscriptionId};
use std::sync::Arc;

use super::DesktopVerificationProvider;

const LOGIND_NAME: &str = "org.freedesktop.login1";
const LOGIND_MANAGER_PATH: &str = "/org/freedesktop/login1";
const LOGIND_MANAGER_INTERFACE: &str = "org.freedesktop.login1.Manager";
const LOGIND_SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
const DBUS_PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const LOCKED_HINT: &str = "LockedHint";

#[derive(Clone)]
pub(super) struct LinuxSessionContext {
    connection: DBusConnection,
    session_path: String,
}

impl LinuxSessionContext {
    pub(super) fn locked_hint(&self) -> Result<bool, String> {
        let reply = self
            .connection
            .call_sync(
                Some(LOGIND_NAME),
                &self.session_path,
                DBUS_PROPERTIES_INTERFACE,
                "Get",
                Some(&(LOGIND_SESSION_INTERFACE, LOCKED_HINT).to_variant()),
                None,
                DBusCallFlags::NONE,
                2_000,
                None::<&gio::Cancellable>,
            )
            .map_err(|error| format!("Unable to read the logind session lock state: {error}"))?;

        reply
            .child_value(0)
            .get::<gio::glib::Variant>()
            .and_then(|value| value.get::<bool>())
            .ok_or_else(|| "logind returned an invalid LockedHint value.".to_owned())
    }
}

pub(super) struct LinuxSessionLockMonitor {
    connection: DBusConnection,
    subscriptions: Vec<SignalSubscriptionId>,
}

impl LinuxSessionLockMonitor {
    pub(super) fn install(
        verification: Arc<DesktopVerificationProvider>,
    ) -> Result<(Self, LinuxSessionContext), String> {
        let connection = gio::bus_get_sync(BusType::System, None::<&gio::Cancellable>)
            .map_err(|error| format!("Unable to connect to the system bus: {error}"))?;
        let session_reply = connection
            .call_sync(
                Some(LOGIND_NAME),
                LOGIND_MANAGER_PATH,
                LOGIND_MANAGER_INTERFACE,
                "GetSessionByPID",
                Some(&(std::process::id(),).to_variant()),
                None,
                DBusCallFlags::NONE,
                2_000,
                None::<&gio::Cancellable>,
            )
            .map_err(|error| format!("Unable to find the current logind session: {error}"))?;
        let session_path: String = session_reply
            .child_value(0)
            .get()
            .ok_or_else(|| "logind returned an invalid session path.".to_owned())?;
        let context = LinuxSessionContext {
            connection: connection.clone(),
            session_path: session_path.clone(),
        };

        let mut subscriptions = Vec::new();
        let lock_verification = Arc::downgrade(&verification);
        subscriptions.push(connection.signal_subscribe(
            Some(LOGIND_NAME),
            Some(LOGIND_SESSION_INTERFACE),
            Some("Lock"),
            Some(&session_path),
            None,
            DBusSignalFlags::NONE,
            move |_, _, _, _, _, _| {
                if let Some(verification) = lock_verification.upgrade() {
                    verification.set_session_lock_requested();
                }
            },
        ));

        let property_verification = Arc::downgrade(&verification);
        let changed_path = session_path.clone();
        subscriptions.push(connection.signal_subscribe(
            Some(LOGIND_NAME),
            Some(DBUS_PROPERTIES_INTERFACE),
            Some("PropertiesChanged"),
            Some(&session_path),
            None,
            DBusSignalFlags::NONE,
            move |_, _, _, _, _, parameters| {
                let Some(property_verification) = property_verification.upgrade() else {
                    return;
                };
                let changed_interface: Option<String> = parameters.child_value(0).get();
                if changed_interface.as_deref() != Some(LOGIND_SESSION_INTERFACE) {
                    return;
                }
                let changed_properties = parameters.child_value(1);
                let Some(value) = changed_properties.lookup_value(LOCKED_HINT, None) else {
                    return;
                };
                if let Some(locked) = value.get::<bool>() {
                    property_verification.apply_session_lock_hint(locked);
                } else {
                    log::error!(
                        "logind sent an invalid LockedHint for session {changed_path}; blocking authentication"
                    );
                    property_verification.set_session_monitor_available(false);
                }
            },
        ));

        let disconnected_verification = Arc::downgrade(&verification);
        connection.connect_closed(move |_, _, error| {
            log::error!(
                "system bus connection closed while monitoring Linux session lock: {}; blocking authentication",
                error.map_or_else(|| "connection closed".to_owned(), |error| error.to_string())
            );
            if let Some(verification) = disconnected_verification.upgrade() {
                verification.set_session_monitor_available(false);
            }
        });

        let initial_locked = match context.locked_hint() {
            Ok(locked) => locked,
            Err(error) => {
                for subscription in subscriptions {
                    connection.signal_unsubscribe(subscription);
                }
                return Err(error);
            }
        };

        verification.set_session_locked(initial_locked);

        Ok((
            Self {
                connection,
                subscriptions,
            },
            context,
        ))
    }

    pub(super) fn uninstall(self) {
        let Self {
            connection,
            subscriptions,
        } = self;
        for subscription in subscriptions {
            connection.signal_unsubscribe(subscription);
        }
    }
}
