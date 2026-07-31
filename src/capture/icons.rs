//! Small shell icons for executables, as RGBA so the UI can upload them as textures.

use windows::Win32::Graphics::Gdi::{
    GetDC, GetDIBits, ReleaseDC, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
    HBITMAP,
};

#[derive(Clone, Debug)]
pub struct IconRgba {
    pub width: usize,
    pub height: usize,
    pub rgba: Vec<u8>,
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
