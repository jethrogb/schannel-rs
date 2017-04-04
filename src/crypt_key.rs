use advapi32;
use winapi;
use std::io;
use std::ptr;

/// A handle to a key.
pub struct CryptKey(winapi::HCRYPTKEY);

impl Drop for CryptKey {
    fn drop(&mut self) {
        unsafe {
            advapi32::CryptDestroyKey(self.0);
        }
    }
}

inner!(CryptKey, winapi::HCRYPTKEY);
