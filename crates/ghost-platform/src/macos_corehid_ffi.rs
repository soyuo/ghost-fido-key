//! Narrow C ABI wrapper for the macOS CoreHID Swift package.

#![allow(unsafe_code)]

use std::{
    ffi::c_void,
    ptr::{self, NonNull},
    time::Duration,
};

const SUCCESS: i32 = 0;
const INVALID_ARGUMENT: i32 = 1;
const NOT_PERMITTED: i32 = 2;
const TIMED_OUT: i32 = 3;
const NOT_READY: i32 = 4;
const NO_RESOURCES: i32 = 5;

unsafe extern "C" {
    fn ghost_fido_corehid_check_readiness(vendor_id: u32, product_id: u32) -> i32;
    fn ghost_fido_corehid_create(
        vendor_id: u32,
        product_id: u32,
        output_handle: *mut *mut c_void,
    ) -> i32;
    fn ghost_fido_corehid_send_input_report(
        handle: *mut c_void,
        report: *const u8,
        report_length: isize,
    ) -> i32;
    fn ghost_fido_corehid_receive_output_report(
        handle: *mut c_void,
        timeout_milliseconds: u64,
        report: *mut u8,
        report_capacity: isize,
        output_length: *mut isize,
    ) -> i32;
    fn ghost_fido_corehid_destroy(handle: *mut c_void) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BridgeError {
    InvalidArgument,
    NotPermitted,
    TimedOut,
    NotReady,
    NoResources,
    Io,
}

pub(super) fn check_readiness(vendor_id: u16, product_id: u16) -> Result<(), BridgeError> {
    // SAFETY: the C ABI accepts two integer identifiers and retains no pointers.
    status(unsafe {
        ghost_fido_corehid_check_readiness(u32::from(vendor_id), u32::from(product_id))
    })
}

pub(super) struct CoreHIDHandle(Option<NonNull<c_void>>);

// The handle is used by one backend owner at a time and the Swift wrapper
// serializes access to its actor through the C ABI.
unsafe impl Send for CoreHIDHandle {}

impl CoreHIDHandle {
    pub(super) fn create(vendor_id: u16, product_id: u16) -> Result<Self, BridgeError> {
        let mut raw_handle = ptr::null_mut();
        // SAFETY: raw_handle is valid for the duration of the call, and the
        // Swift function initializes it to null before attempting activation.
        status(unsafe {
            ghost_fido_corehid_create(u32::from(vendor_id), u32::from(product_id), &mut raw_handle)
        })?;
        NonNull::new(raw_handle)
            .map(|handle| Self(Some(handle)))
            .ok_or(BridgeError::Io)
    }

    pub(super) fn send_input_report(&self, report: &[u8]) -> Result<(), BridgeError> {
        let handle = self.0.ok_or(BridgeError::NotReady)?;
        // SAFETY: the handle is retained until destroy; the report slice is
        // valid and immutable for the duration of the synchronous call.
        status(unsafe {
            ghost_fido_corehid_send_input_report(
                handle.as_ptr(),
                report.as_ptr(),
                report.len() as isize,
            )
        })
    }

    pub(super) fn receive_output_report(&self, timeout: Duration) -> Result<Vec<u8>, BridgeError> {
        let handle = self.0.ok_or(BridgeError::NotReady)?;
        let timeout_milliseconds = timeout.as_millis().min(u128::from(u64::MAX)) as u64;
        let mut report = [0; 64];
        let mut output_length = 0_isize;
        // SAFETY: the handle remains retained, report has capacity 64, and
        // output_length points to a writable integer for the call duration.
        status(unsafe {
            ghost_fido_corehid_receive_output_report(
                handle.as_ptr(),
                timeout_milliseconds,
                report.as_mut_ptr(),
                report.len() as isize,
                &mut output_length,
            )
        })?;
        if output_length != 64 {
            return Err(BridgeError::Io);
        }
        Ok(report.to_vec())
    }

    pub(super) fn destroy(&mut self) -> Result<(), BridgeError> {
        let Some(handle) = self.0.take() else {
            return Ok(());
        };
        // SAFETY: the retained handle is consumed exactly once by destroy.
        status(unsafe { ghost_fido_corehid_destroy(handle.as_ptr()) })
    }
}

impl Drop for CoreHIDHandle {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

fn status(value: i32) -> Result<(), BridgeError> {
    match value {
        SUCCESS => Ok(()),
        INVALID_ARGUMENT => Err(BridgeError::InvalidArgument),
        NOT_PERMITTED => Err(BridgeError::NotPermitted),
        TIMED_OUT => Err(BridgeError::TimedOut),
        NOT_READY => Err(BridgeError::NotReady),
        NO_RESOURCES => Err(BridgeError::NoResources),
        _ => Err(BridgeError::Io),
    }
}
