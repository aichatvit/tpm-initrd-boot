#![no_std]
#![no_main]
extern crate alloc;

use alloc::{boxed::Box, vec, vec::Vec};
use boot_core::{
    format::{CLOSED_PHASE, Container, MEASUREMENT_DOMAIN, Manifest},
    hash,
    tpm::{Tpm, Transport},
};
use core::{ffi::c_void, ptr};
use uefi::{
    boot::{self, LoadImageSource, ScopedProtocol},
    prelude::*,
    proto::{
        loaded_image::LoadedImage,
        media::file::{File, FileAttribute, FileInfo, FileMode},
        tcg::{
            EventType, PcrIndex,
            v2::{HashLogExtendEventFlags, PcrEventInputs, Tcg},
        },
    },
};
use uefi_raw::{
    Boolean,
    protocol::{device_path::DevicePathProtocol, media::LoadFile2Protocol},
};
use zeroize::{Zeroize, Zeroizing};

const KEY: &[u8; 32] = include_bytes!(concat!(env!("OUT_DIR"), "/public-key.bin"));
const DIRECTORY: &str = "\\EFI\\TPMBOOT\\";

struct FirmwareTpm(ScopedProtocol<Tcg>);
impl Transport for FirmwareTpm {
    fn transact(&mut self, command: &[u8]) -> boot_core::Result<Vec<u8>> {
        let caps = self.0.get_capability().map_err(|e| {
            uefi::println!("TPMBOOT: GetCapability: {:?}", e.status());
            boot_core::Error::Transport
        })?;
        let capacity = usize::from(caps.max_response_size).min(8192);
        if command.len() < 10 || command.len() > usize::from(caps.max_command_size) || capacity < 10
        {
            return Err(boot_core::Error::Transport);
        }
        let code = u32::from_be_bytes(command[6..10].try_into().unwrap());
        let mut b = Zeroizing::new(vec![0; capacity]);
        self.0.submit_command(command, &mut b).map_err(|e| {
            uefi::println!("TPMBOOT: SubmitCommand {:#010x}: {:?}", code, e.status());
            boot_core::Error::Transport
        })?;
        let n = u32::from_be_bytes(b[2..6].try_into().unwrap()) as usize;
        if !(10..=capacity).contains(&n) {
            return Err(boot_core::Error::InvalidFormat);
        }
        b.truncate(n);
        Ok(core::mem::take(&mut *b))
    }
}
fn protocol<T: uefi::proto::ProtocolPointer + ?Sized>() -> uefi::Result<ScopedProtocol<T>> {
    let h = boot::get_handle_for_protocol::<T>()?;
    boot::open_protocol_exclusive::<T>(h)
}
fn bounded_read(name: &str, max: usize) -> core::result::Result<Vec<u8>, Status> {
    let mut fs = boot::get_image_file_system(boot::image_handle()).map_err(|e| e.status())?;
    let mut root = fs.open_volume().map_err(|e| e.status())?;
    let path = uefi::CString16::try_from(alloc::format!("{DIRECTORY}{name}").as_str())
        .map_err(|_| Status::INVALID_PARAMETER)?;
    let mut file = root
        .open(&path, FileMode::Read, FileAttribute::empty())
        .map_err(|e| e.status())?
        .into_regular_file()
        .ok_or(Status::INVALID_PARAMETER)?;
    let info = file.get_boxed_info::<FileInfo>().map_err(|e| e.status())?;
    let len = usize::try_from(info.file_size()).map_err(|_| Status::BAD_BUFFER_SIZE)?;
    if len > max {
        return Err(Status::BAD_BUFFER_SIZE);
    }
    let mut b = vec![0; len];
    let mut offset = 0;
    while offset < len {
        let n = file.read(&mut b[offset..]).map_err(|e| e.status())?;
        if n == 0 {
            return Err(Status::END_OF_FILE);
        }
        offset += n;
    }
    let mut extra = [0];
    if file.read(&mut extra).map_err(|e| e.status())? != 0 {
        return Err(Status::BAD_BUFFER_SIZE);
    }
    Ok(b)
}
fn checked<T>(r: boot_core::Result<T>) -> core::result::Result<T, Status> {
    r.map_err(|e| {
        uefi::println!("TPMBOOT: {:?}", e);
        Status::SECURITY_VIOLATION
    })
}
fn measure(tcg: &mut Tcg, data: &[u8], description: &[u8]) -> core::result::Result<(), Status> {
    let event = PcrEventInputs::new_in_box(PcrIndex(11), EventType::IPL, description)
        .map_err(|e| e.status())?;
    tcg.hash_log_extend_event(HashLogExtendEventFlags::empty(), data, &event)
        .map_err(|e| e.status())
}

fn verify_firmware_measurement(tpm: &mut Tpm<FirmwareTpm>) -> core::result::Result<(), Status> {
    let loader = bounded_read("tpmboot.efi", 16 * 1024 * 1024)?;
    let expected = checked(boot_core::pe::unsigned_efi_digest(&loader))?;
    let mut replay = [0u8; 32];
    let mut last_application = None;
    {
        let log = tpm.transport.0.get_event_log_v2().map_err(|e| e.status())?;
        if log.is_truncated() {
            return Err(Status::SECURITY_VIOLATION);
        }
        for event in log.iter() {
            if event.pcr_index() != PcrIndex(4) || event.event_type() == EventType::NO_ACTION {
                continue;
            }
            let digest = event
                .digests()
                .into_iter()
                .find(|(alg, _)| alg.0 == 0x0b)
                .map(|(_, d)| d)
                .ok_or(Status::SECURITY_VIOLATION)?;
            if digest.len() != 32 {
                return Err(Status::SECURITY_VIOLATION);
            }
            let mut extended = [0; 64];
            extended[..32].copy_from_slice(&replay);
            extended[32..].copy_from_slice(digest);
            replay = hash(&extended);
            if event.event_type() == EventType::EFI_BOOT_SERVICES_APPLICATION {
                let mut d = [0; 32];
                d.copy_from_slice(digest);
                last_application = Some(d);
            }
        }
    }
    let actual = checked(tpm.read_pcrs([0; 32]))?;
    if last_application != Some(expected) || replay != actual.values[2] {
        return Err(Status::SECURITY_VIOLATION);
    }
    Ok(())
}

#[repr(C)]
struct InitrdProvider {
    protocol: LoadFile2Protocol,
    data: Zeroizing<Vec<u8>>,
    consumed: bool,
}
unsafe extern "efiapi" fn load_initrd(
    this: *mut LoadFile2Protocol,
    path: *const DevicePathProtocol,
    boot_policy: Boolean,
    size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if this.is_null() || size.is_null() || path.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if bool::from(boot_policy) {
        return Status::UNSUPPORTED;
    }
    // SAFETY: firmware invokes this function only for the boxed protocol installed below.
    let provider = unsafe { &mut *this.cast::<InitrdProvider>() };
    // The remaining path must be End Entire; reject attempts to use this provider as a filesystem.
    let path_header = unsafe { core::slice::from_raw_parts(path.cast::<u8>(), 4) };
    if path_header != [0x7f, 0xff, 4, 0] {
        return Status::NOT_FOUND;
    }
    if provider.consumed {
        return Status::ACCESS_DENIED;
    }
    let needed = provider.data.len();
    if buffer.is_null() || unsafe { *size } < needed {
        unsafe { *size = needed };
        return Status::BUFFER_TOO_SMALL;
    }
    unsafe {
        ptr::copy_nonoverlapping(provider.data.as_ptr(), buffer.cast::<u8>(), needed);
        *size = needed;
    }
    provider.data.as_mut_slice().zeroize();
    provider.consumed = true;
    Status::SUCCESS
}

// Vendor Media node LINUX_EFI_INITRD_MEDIA_GUID, then End Entire.
#[repr(C, align(8))]
struct AlignedPath([u8; 24]);
const INITRD_PATH: AlignedPath = AlignedPath([
    4, 3, 20, 0, 0x27, 0xe4, 0x68, 0x55, 0xfc, 0x68, 0x3d, 0x4f, 0xac, 0x74, 0xca, 0x55, 0x52,
    0x31, 0xcc, 0x68, 0x7f, 0xff, 4, 0,
]);
const DEVICE_PATH_GUID: uefi::Guid = uefi::guid!("09576e91-6d3f-11d2-8e39-00a0c969723b");

fn run() -> core::result::Result<(), Status> {
    boot::set_watchdog_timer(0, 0x10000, None).map_err(|e| e.status())?;
    let signed = bounded_read("manifest.bin", 4096)?;
    let manifest = checked(Manifest::verify(&signed, KEY))?;
    let kernel = bounded_read("vmlinuz.efi", 128 * 1024 * 1024)?;
    let mut initrd = Zeroizing::new(bounded_read("initramfs.img", 512 * 1024 * 1024)?);
    checked(manifest.verify_images(&kernel, &initrd))?;
    let container = match bounded_read("sealed.bin", 4096) {
        Ok(b) => Some(checked(Container::decode(&b))?),
        Err(Status::NOT_FOUND) => None,
        Err(e) => return Err(e),
    };
    let enroll = match bounded_read("enroll.request", 64) {
        Ok(b) => {
            if b != b"TPMBOOT-ENROLL-v1\n" {
                return Err(Status::SECURITY_VIOLATION);
            }
            true
        }
        Err(Status::NOT_FOUND) => false,
        Err(e) => return Err(e),
    };
    if container.is_none() && !enroll {
        return Err(Status::NOT_FOUND);
    }
    if container.is_some() && enroll {
        return Err(Status::ACCESS_DENIED);
    }
    let mut tpm = Tpm::new(FirmwareTpm(protocol::<Tcg>().map_err(|e| e.status())?));
    verify_firmware_measurement(&mut tpm)?;
    let mut measured = Vec::from(MEASUREMENT_DOMAIN);
    measured.extend_from_slice(&hash(&signed));
    measure(
        &mut tpm.transport.0,
        &measured,
        b"TPMBOOT verified manifest v1",
    )?;
    let snapshot = checked(tpm.read_pcrs(hash(&signed)))?;
    let secret = if let Some(c) = container.as_ref() {
        Some(checked(tpm.unseal(c, &snapshot))?)
    } else {
        None
    };
    // Close the early-boot policy window before handing control to any next-stage code.
    measure(
        &mut tpm.transport.0,
        CLOSED_PHASE,
        b"TPMBOOT unseal phase closed v1",
    )?;
    drop(tpm);
    let record = if enroll {
        Some(snapshot.encode())
    } else {
        None
    };
    checked(boot_core::cpio::append_handoff(
        &mut initrd,
        record.as_deref(),
        secret.as_deref(),
    ))?;
    drop(secret);
    // Load exactly the verified kernel bytes. Unseal occurred before LoadImage extends PCR 4.
    let image = boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromBuffer {
            buffer: &kernel,
            file_path: None,
        },
    )
    .map_err(|e| e.status())?;
    let options = uefi::CString16::try_from(manifest.cmdline.as_str())
        .map_err(|_| Status::INVALID_PARAMETER)?;
    {
        let mut loaded =
            boot::open_protocol_exclusive::<LoadedImage>(image).map_err(|e| e.status())?;
        let bytes = options.as_slice_with_nul();
        unsafe {
            loaded.set_load_options(bytes.as_ptr().cast(), (bytes.len() * 2) as u32);
        }
    }
    uefi::println!("TPMBOOT: installing initrd provider");
    match boot::find_handles::<uefi::proto::media::load_file::LoadFile2>() {
        Ok(handles) if !handles.is_empty() => return Err(Status::ALREADY_STARTED),
        Ok(_) => {}
        Err(e) if e.status() == Status::NOT_FOUND => {}
        Err(e) => return Err(e.status()),
    }
    let mut provider = Box::new(InitrdProvider {
        protocol: LoadFile2Protocol {
            load_file: load_initrd,
        },
        data: initrd,
        consumed: false,
    });
    let path = Box::new(INITRD_PATH);
    let handle = unsafe {
        boot::install_protocol_interface(
            None,
            &LoadFile2Protocol::GUID,
            ptr::from_mut(&mut provider.protocol).cast(),
        )
    }
    .map_err(|e| e.status())?;
    if let Err(e) = unsafe {
        boot::install_protocol_interface(Some(handle), &DEVICE_PATH_GUID, path.0.as_ptr().cast())
    } {
        let removed = unsafe {
            boot::uninstall_protocol_interface(
                handle,
                &LoadFile2Protocol::GUID,
                ptr::from_mut(&mut provider.protocol).cast(),
            )
        };
        if removed.is_err() {
            provider.data.as_mut_slice().zeroize();
            core::mem::forget(provider);
        }
        let _ = boot::unload_image(image);
        return Err(e.status());
    }
    let result = boot::start_image(image);
    // Both protocol objects must stay alive until uninstalled, even if StartImage returns.
    let remove_path = unsafe {
        boot::uninstall_protocol_interface(handle, &DEVICE_PATH_GUID, path.0.as_ptr().cast())
    };
    let remove_provider = unsafe {
        boot::uninstall_protocol_interface(
            handle,
            &LoadFile2Protocol::GUID,
            ptr::from_mut(&mut provider.protocol).cast(),
        )
    };
    if remove_path.is_err() {
        core::mem::forget(path);
    }
    if remove_provider.is_err() {
        provider.data.as_mut_slice().zeroize();
        core::mem::forget(provider);
    }
    let _ = boot::unload_image(image);
    result.map_err(|e| e.status())?;
    Err(Status::ABORTED) // A booted Linux kernel should never return.
}

#[entry]
fn main() -> Status {
    if let Err(e) = uefi::helpers::init() {
        return e.status();
    }
    uefi::println!("TPMBOOT demo 0.2.0: EFI loader started");
    match run() {
        Ok(()) => Status::SUCCESS,
        Err(s) => {
            uefi::println!("TPMBOOT stopped: {:?}", s);
            uefi::println!("Returning to firmware in 60 seconds...");
            boot::stall(core::time::Duration::from_secs(60));
            s
        }
    }
}
