# App Icons

Place your application icons in this directory. The following files are required for building:

- `32x32.png` - 32x32 pixel PNG icon
- `128x128.png` - 128x128 pixel PNG icon  
- `128x128@2x.png` - 256x256 pixel PNG icon (for Retina displays)
- `icon.icns` - macOS icon file
- `icon.ico` - Windows icon file

## Generating Icons

You can use online tools or command-line utilities to generate these icons from a single source image:

- [Tauri Icon Generator](https://github.com/tauri-apps/tauri-icon-gen)
- Online tools like [CloudConvert](https://cloudconvert.com/) or [IconKitchen](https://icon.kitchen/)

For development, you can temporarily comment out the icon references in `tauri.conf.json` if needed.


