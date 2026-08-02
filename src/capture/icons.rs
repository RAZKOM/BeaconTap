//! Small shell icons for executables, as RGBA so the UI can upload them as textures.

use super::winutil::to_wide;
use windows::core::PCWSTR;
use windows::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO, BITMAPINFOHEADER,
    BI_RGB, DIB_RGB_COLORS, HBITMAP, HGDIOBJ,
};
use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;
use windows::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_SMALLICON};
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};

#[derive(Clone, Debug)]
pub struct IconRgba {
    pub width: usize,
    pub height: usize,
    pub rgba: Vec<u8>,
}

/// The small (16 px) shell icon of a file, or None if the shell has none or GDI fails.
pub fn icon_for_path(path: &str) -> Option<IconRgba> {
    let wide = to_wide(path);
    let mut info = SHFILEINFOW::default();
    // Safety: `wide` is NUL terminated; `info` is a valid out struct of the stated size.
    let res = unsafe {
        SHGetFileInfoW(
            PCWSTR(wide.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(0),
            Some(&mut info),
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_SMALLICON,
        )
    };
    if res == 0 || info.hIcon.is_invalid() {
        return None;
    }
    let result = hicon_to_rgba(info.hIcon);
    // Safety: the icon was returned to us by SHGetFileInfo and is ours to destroy.
    unsafe {
        let _ = DestroyIcon(info.hIcon);
    }
    result
}

fn hicon_to_rgba(hicon: windows::Win32::UI::WindowsAndMessaging::HICON) -> Option<IconRgba> {
    let mut ii = ICONINFO::default();
    // Safety: out struct; bitmaps it returns are deleted below.
    unsafe { GetIconInfo(hicon, &mut ii) }.ok()?;
    let color = ii.hbmColor;
    let mask = ii.hbmMask;
    let out = (|| {
        let mut bm = BITMAP::default();
        // Safety: BITMAP out struct sized correctly.
        let got = unsafe {
            GetObjectW(
                HGDIOBJ(color.0),
                std::mem::size_of::<BITMAP>() as i32,
                Some(&mut bm as *mut _ as *mut _),
            )
        };
        if got == 0 || bm.bmWidth <= 0 || bm.bmHeight <= 0 || bm.bmWidth > 256 || bm.bmHeight > 256
        {
            return None;
        }
        let w = bm.bmWidth as usize;
        let h = bm.bmHeight as usize;
        let mut rgba = read_bgra(color, w, h)?;
        let has_alpha = rgba.as_chunks::<4>().0.iter().any(|p| p[3] != 0);
        if !has_alpha {
            // 24-bit icon: alpha comes from the mask (1 = transparent).
            if let Some(m) = read_bgra(mask, w, h) {
                for (px, mp) in rgba
                    .as_chunks_mut::<4>()
                    .0
                    .iter_mut()
                    .zip(m.as_chunks::<4>().0.iter())
                {
                    px[3] = if mp[0] == 0 { 255 } else { 0 };
                }
            } else {
                for px in rgba.as_chunks_mut::<4>().0.iter_mut() {
                    px[3] = 255;
                }
            }
        }
        for px in rgba.as_chunks_mut::<4>().0.iter_mut() {
            px.swap(0, 2); // BGRA -> RGBA
        }
        Some(IconRgba {
            width: w,
            height: h,
            rgba,
        })
    })();
    // Safety: both bitmaps were created for us by GetIconInfo.
    unsafe {
        if !color.is_invalid() {
            let _ = DeleteObject(HGDIOBJ(color.0));
        }
        if !mask.is_invalid() {
            let _ = DeleteObject(HGDIOBJ(mask.0));
        }
    }
    out
}

fn read_bgra(bmp: HBITMAP, w: usize, h: usize) -> Option<Vec<u8>> {
    if bmp.is_invalid() {
        return None;
    }
    let mut bi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w as i32,
            biHeight: -(h as i32), // top-down
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut buf = vec![0u8; w * h * 4];
    // Safety: screen DC released below; buffer sized for 32bpp w*h; header requests that layout.
    unsafe {
        let hdc = GetDC(None);
        if hdc.is_invalid() {
            return None;
        }
        let lines = GetDIBits(
            hdc,
            bmp,
            0,
            h as u32,
            Some(buf.as_mut_ptr() as *mut _),
            &mut bi,
            DIB_RGB_COLORS,
        );
        ReleaseDC(None, hdc);
        if lines as usize != h {
            return None;
        }
    }
    Some(buf)
}
