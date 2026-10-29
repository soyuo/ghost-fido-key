use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tauri::{Runtime, WebviewWindow};
use windows::Win32::{
    Foundation::{HANDLE, HWND, LPARAM, LRESULT, WPARAM},
    System::{
        RemoteDesktop::{
            NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification,
            WTSUnRegisterSessionNotification,
        },
        StationsAndDesktops::{
            CloseDesktop, DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS,
            GetUserObjectInformationW, OpenInputDesktop, UOI_NAME,
        },
    },
    UI::{
        Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass},
        WindowsAndMessaging::{
            WM_NCDESTROY, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK, WTS_SESSION_UNLOCK,
        },
    },
};

use crate::DesktopVerificationProvider;

const SUBCLASS_ID: usize = 0x47464944;

struct SessionLockContext {
    verification: Arc<DesktopVerificationProvider>,
    destroyed: Arc<AtomicBool>,
}

pub(crate) struct SessionLockHook {
    hwnd: HWND,
    context: usize,
    destroyed: Arc<AtomicBool>,
}

impl SessionLockHook {
    pub(crate) fn uninstall(self) {
        if self.destroyed.load(Ordering::Acquire) {
            return;
        }
        unsafe {
            if self.context != 0 {
                let context = &*(self.context as *const SessionLockContext);
                context.verification.set_session_monitor_available(false);
                let _ = WTSUnRegisterSessionNotification(self.hwnd);
            }
            if RemoveWindowSubclass(self.hwnd, Some(session_subclass_proc), SUBCLASS_ID).as_bool() {
                let context = Box::from_raw(self.context as *mut SessionLockContext);
                drop(context);
            }
        }
    }
}

pub(crate) fn install<R: Runtime>(
    window: &WebviewWindow<R>,
    verification: Arc<DesktopVerificationProvider>,
) -> Result<SessionLockHook, String> {
    let hwnd = window.hwnd().map_err(|error| {
        format!("Could not access the main window for session monitoring: {error}")
    })?;

    let destroyed = Arc::new(AtomicBool::new(false));
    let context = unsafe {
        WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION).map_err(|error| {
            format!("Could not register Windows session notifications: {error}")
        })?;

        let context = Box::into_raw(Box::new(SessionLockContext {
            verification: Arc::clone(&verification),
            destroyed: Arc::clone(&destroyed),
        }));
        if !SetWindowSubclass(
            hwnd,
            Some(session_subclass_proc),
            SUBCLASS_ID,
            context as usize,
        )
        .as_bool()
        {
            let _ = WTSUnRegisterSessionNotification(hwnd);
            drop(Box::from_raw(context));
            return Err("Could not attach the Windows session notification handler.".into());
        }
        context
    };

    let hook = SessionLockHook {
        hwnd,
        context: context as usize,
        destroyed,
    };
    let locked = match active_desktop_is_locked() {
        Ok(locked) => locked,
        Err(error) => {
            hook.uninstall();
            return Err(error);
        }
    };
    verification.set_session_locked(locked);
    verification.set_session_monitor_available(true);

    Ok(hook)
}

pub(crate) fn active_desktop_is_locked() -> Result<bool, String> {
    let desktop = unsafe {
        OpenInputDesktop(
            DESKTOP_CONTROL_FLAGS(0),
            false,
            DESKTOP_ACCESS_FLAGS(DESKTOP_READOBJECTS.0),
        )
    }
    .map_err(|error| format!("Could not determine the active Windows desktop: {error}"))?;

    let mut required_bytes = 0;
    let _ = unsafe {
        GetUserObjectInformationW(
            HANDLE(desktop.0),
            UOI_NAME,
            None,
            0,
            Some(&mut required_bytes),
        )
    };
    if required_bytes == 0 || required_bytes > 4096 {
        let _ = unsafe { CloseDesktop(desktop) };
        return Err("Could not read the active Windows desktop name.".into());
    }

    let mut name = vec![0u16; required_bytes.div_ceil(2) as usize];
    let read_result = unsafe {
        GetUserObjectInformationW(
            HANDLE(desktop.0),
            UOI_NAME,
            Some(name.as_mut_ptr().cast()),
            required_bytes,
            Some(&mut required_bytes),
        )
    };
    let close_result = unsafe { CloseDesktop(desktop) };
    read_result
        .map_err(|error| format!("Could not read the active Windows desktop name: {error}"))?;
    close_result
        .map_err(|error| format!("Could not release the active Windows desktop handle: {error}"))?;

    let length = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    let name = String::from_utf16(&name[..length])
        .map_err(|_| "The active Windows desktop name is invalid.".to_owned())?;
    Ok(!name.eq_ignore_ascii_case("Default"))
}

unsafe extern "system" fn session_subclass_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    subclass_id: usize,
    reference_data: usize,
) -> LRESULT {
    if reference_data != 0 {
        let context = unsafe { &*(reference_data as *const SessionLockContext) };
        if message == WM_WTSSESSION_CHANGE {
            match wparam.0 as u32 {
                WTS_SESSION_LOCK => context.verification.set_session_locked(true),
                WTS_SESSION_UNLOCK => context.verification.set_session_locked(false),
                _ => {}
            }
        }
    }

    if message == WM_NCDESTROY {
        let _ = unsafe { WTSUnRegisterSessionNotification(hwnd) };
        let _ = unsafe { RemoveWindowSubclass(hwnd, Some(session_subclass_proc), subclass_id) };
        if reference_data != 0 {
            let context = unsafe { Box::from_raw(reference_data as *mut SessionLockContext) };
            context.destroyed.store(true, Ordering::Release);
            context.verification.set_session_monitor_available(false);
            context.verification.set_session_locked(true);
        }
    }

    unsafe { DefSubclassProc(hwnd, message, wparam, lparam) }
}
