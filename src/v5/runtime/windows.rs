//! Runtime Windows process/native machine observations, including WOW64.
use std::io::{Error, ErrorKind, Result};
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Machines {
    pub process: &'static str,
    pub native: &'static str,
}
fn architecture(machine: u16) -> Result<&'static str> {
    match machine {
        0x014c => Ok("x86"),
        0x8664 => Ok("x86_64"),
        0x01c0 | 0x01c4 => Ok("arm"),
        0xaa64 => Ok("aarch64"),
        _ => Err(Error::new(
            ErrorKind::Unsupported,
            format!("unsupported Windows machine code: {machine:#06x}"),
        )),
    }
}
fn machines(process: u16, native: u16) -> Result<Machines> {
    let native = architecture(native)?;
    Ok(Machines {
        process: if process == 0 {
            native
        } else {
            architecture(process)?
        },
        native,
    })
}
#[cfg(windows)]
pub(super) fn observe() -> Result<Machines> {
    use std::ffi::{c_char, c_void};
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn GetModuleHandleA(name: *const c_char) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    }
    type Query = unsafe extern "system" fn(*mut c_void, *mut u16, *mut u16) -> i32;
    // Resolve by name so older Windows can fail this evidence request without
    // making the API a mandatory import for every command in the executable.
    let module = unsafe { GetModuleHandleA(c"kernel32.dll".as_ptr()) };
    if module.is_null() {
        return Err(Error::last_os_error());
    }
    let symbol = unsafe { GetProcAddress(module, c"IsWow64Process2".as_ptr()) };
    if symbol.is_null() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "IsWow64Process2 is unavailable; native machine identity cannot be established",
        ));
    }
    // GetProcAddress's named export has the documented IsWow64Process2 ABI.
    let query = unsafe { std::mem::transmute::<*mut c_void, Query>(symbol) };
    let mut process = 0u16;
    let mut native = 0u16;
    if unsafe { query(GetCurrentProcess(), &mut process, &mut native) } == 0 {
        return Err(Error::last_os_error());
    }
    machines(process, native)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wow64_process_and_native_machine_codes_remain_distinct() {
        assert_eq!(
            machines(0, 0xaa64).unwrap(),
            Machines {
                process: "aarch64",
                native: "aarch64"
            }
        );
        assert_eq!(
            machines(0x8664, 0xaa64).unwrap(),
            Machines {
                process: "x86_64",
                native: "aarch64"
            }
        );
        assert_eq!(
            machines(0x014c, 0x8664).unwrap(),
            Machines {
                process: "x86",
                native: "x86_64"
            }
        );
        assert_eq!(
            machines(0, 0x8664).unwrap(),
            Machines {
                process: "x86_64",
                native: "x86_64"
            }
        );
        assert!(machines(0, 0).is_err());
        assert!(machines(0xffff, 0xaa64).is_err());
        assert!(machines(0, 0xffff).is_err());
    }
}
