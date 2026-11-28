// SPDX-License-Identifier: GPL-3.0-or-later

//! The Prime's local time zone, as the status bar uses it.
//!
//! Release history stores plain UTC seconds. The offset to local time is looked
//! up here at display time, per entry, so a date in winter and a date in
//! summer each get the offset that applied then.

use std::sync::{Arc, Mutex, OnceLock, RwLock};

use crate::state::AppState;

slint_keyos_platform::settings::use_api!(
    slint_keyos_platform::settings,
    slint_keyos_platform::server
);

fn zone() -> &'static RwLock<jiff::tz::TimeZone> {
    static ZONE: OnceLock<RwLock<jiff::tz::TimeZone>> = OnceLock::new();
    ZONE.get_or_init(|| {
        RwLock::new(settings_permissions::settings::global::TimeZone::default().timezone())
    })
}

fn set_zone(tz: &settings_permissions::settings::global::TimeZone) {
    *zone().write().unwrap() = tz.timezone();
}

/// Seconds to add to a UTC timestamp to get the Prime's local wall clock.
pub fn utc_offset_seconds(unix_secs: u64) -> i32 {
    let Ok(secs) = i64::try_from(unix_secs) else { return 0 };
    let Ok(ts) = jiff::Timestamp::from_second(secs) else { return 0 };
    zone().read().unwrap().to_offset_info(ts).offset().seconds()
}

/// Read the current zone and keep it current. `state` is refreshed whenever the
/// user changes the zone in Settings so open lists redraw with the new dates.
pub fn init(state: Arc<Mutex<AppState>>) {
    set_zone(&SettingsApi::default().get_time_zone());
    let updates = slint_keyos_platform::subscribe::<settings_permissions::SettingsPermissions, _>(
        settings_permissions::settings::messages::SubscribeTimeZone,
    );
    slint_keyos_platform::spawn_local(async move {
        let mut updates = updates.await;
        while let Some(tz) = updates.next().await {
            set_zone(&tz);
            state.lock().unwrap().refresh_credentials();
        }
    })
    .detach();
}
