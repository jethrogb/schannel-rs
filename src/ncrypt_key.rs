use winapi;

use Inner;

// FIXME https://github.com/retep998/winapi-rs/pull/319
extern "system" {
    fn NCryptFreeObject(handle: winapi::NCRYPT_HANDLE) -> winapi::SECURITY_STATUS;
}

/// A CNG handle to a key.
pub struct NcryptKey(winapi::NCRYPT_KEY_HANDLE);

impl Drop for NcryptKey {
    fn drop(&mut self) {
        unsafe {
            NCryptFreeObject(self.0);
        }
    }
}

impl Inner<winapi::NCRYPT_KEY_HANDLE> for NcryptKey {
    unsafe fn from_inner(t: winapi::NCRYPT_KEY_HANDLE) -> Self {
        NcryptKey(t)
    }

    fn as_inner(&self) -> winapi::NCRYPT_KEY_HANDLE {
        self.0
    }

    fn get_mut(&mut self) -> &mut winapi::NCRYPT_KEY_HANDLE {
        &mut self.0
    }
}
