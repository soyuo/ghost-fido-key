#[derive(Default)]
pub(super) struct SessionLockTransition {
    generation: u64,
    // Stable across repeated snapshots; changes for lock events and state transitions.
    approval_epoch: u64,
    pending: bool,
}

impl SessionLockTransition {
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn approval_epoch(&self) -> u64 {
        self.approval_epoch
    }

    pub(super) fn record_change(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.approval_epoch = self.approval_epoch.wrapping_add(1);
    }

    #[cfg(any(target_os = "linux", target_os = "windows", test))]
    pub(super) fn request_state(&mut self, locked: bool) {
        self.record_change();
        self.pending = locked;
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn request_lock(&mut self) {
        self.request_state(true);
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn request_unlock(&mut self) {
        self.record_change();
        self.pending = false;
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn apply_linux_snapshot(
        &mut self,
        locked: bool,
        expected_generation: Option<u64>,
        current_locked: bool,
    ) -> Option<(bool, bool)> {
        if expected_generation.is_some_and(|generation| generation != self.generation) {
            return None;
        }

        self.generation = self.generation.wrapping_add(1);
        let next_locked = if locked {
            self.pending = false;
            true
        } else if self.pending {
            // A Lock signal can arrive before the desktop environment reports
            // LockedHint=true. Do not let that stale false value reopen approvals.
            true
        } else {
            false
        };
        let changed = current_locked != next_locked;
        if changed {
            self.approval_epoch = self.approval_epoch.wrapping_add(1);
        }
        Some((next_locked, changed))
    }

    #[cfg(any(target_os = "windows", test))]
    pub(super) fn apply_windows_snapshot(
        &mut self,
        locked: bool,
        expected_generation: u64,
        current_locked: bool,
    ) -> Option<(bool, bool)> {
        if self.generation != expected_generation {
            return None;
        }

        self.generation = self.generation.wrapping_add(1);
        let next_locked = if locked {
            self.pending = false;
            true
        } else {
            self.pending
        };
        let changed = current_locked != next_locked;
        if changed {
            self.approval_epoch = self.approval_epoch.wrapping_add(1);
        }
        Some((next_locked, changed))
    }
}

#[cfg(test)]
mod tests {
    use super::SessionLockTransition;

    #[test]
    fn linux_rejects_stale_snapshot_and_keeps_pending_lock_closed() {
        let mut transition = SessionLockTransition::default();
        let stale_generation = transition.generation();

        transition.request_lock();
        assert_eq!(
            transition.apply_linux_snapshot(false, Some(stale_generation), false),
            None
        );
        assert_eq!(
            transition.apply_linux_snapshot(false, None, true),
            Some((true, false))
        );

        transition.request_unlock();
        assert_eq!(
            transition.apply_linux_snapshot(false, None, true),
            Some((false, true))
        );
    }

    #[test]
    fn linux_epoch_changes_on_events_and_state_changes_only() {
        let mut transition = SessionLockTransition::default();
        assert_eq!(transition.approval_epoch(), 0);

        transition.request_lock();
        assert_eq!(transition.approval_epoch(), 1);
        assert_eq!(
            transition.apply_linux_snapshot(true, None, true),
            Some((true, false))
        );
        assert_eq!(transition.approval_epoch(), 1);

        transition.request_unlock();
        assert_eq!(transition.approval_epoch(), 2);
        assert_eq!(
            transition.apply_linux_snapshot(false, None, true),
            Some((false, true))
        );
        assert_eq!(transition.approval_epoch(), 3);
        assert_eq!(
            transition.apply_linux_snapshot(false, None, false),
            Some((false, false))
        );
        assert_eq!(transition.approval_epoch(), 3);
    }

    #[test]
    fn windows_rejects_stale_snapshot_and_keeps_pending_lock_closed() {
        let mut transition = SessionLockTransition::default();
        let stale_generation = transition.generation();

        transition.request_state(true);
        assert_eq!(
            transition.apply_windows_snapshot(false, stale_generation, false),
            None
        );
        let current_generation = transition.generation();
        assert_eq!(
            transition.apply_windows_snapshot(false, current_generation, true),
            Some((true, false))
        );

        transition.request_state(false);
        let current_generation = transition.generation();
        assert_eq!(
            transition.apply_windows_snapshot(false, current_generation, true),
            Some((false, true))
        );
    }

    #[test]
    fn windows_epoch_changes_on_events_and_state_changes_only() {
        let mut transition = SessionLockTransition::default();
        assert_eq!(transition.approval_epoch(), 0);

        transition.request_state(true);
        assert_eq!(transition.approval_epoch(), 1);
        let current_generation = transition.generation();
        assert_eq!(
            transition.apply_windows_snapshot(true, current_generation, true),
            Some((true, false))
        );
        assert_eq!(transition.approval_epoch(), 1);

        transition.request_state(false);
        assert_eq!(transition.approval_epoch(), 2);
        let current_generation = transition.generation();
        assert_eq!(
            transition.apply_windows_snapshot(false, current_generation, true),
            Some((false, true))
        );
        assert_eq!(transition.approval_epoch(), 3);
        let current_generation = transition.generation();
        assert_eq!(
            transition.apply_windows_snapshot(false, current_generation, false),
            Some((false, false))
        );
        assert_eq!(transition.approval_epoch(), 3);
    }
}
