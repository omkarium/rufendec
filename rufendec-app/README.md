# Tauri App

A modern desktop application built with Tauri, Rust, and web technologies.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Rust**: Install from [rustup.rs](https://rustup.rs/)
- **Node.js**: Install from [nodejs.org](https://nodejs.org/) (optional, for package management)
- **System Dependencies**:
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`)
  - **Linux**: `libwebkit2gtk-4.0-dev`, `build-essential`, `curl`, `wget`, `libssl-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`
  - **Windows**: Microsoft Visual Studio C++ Build Tools and Windows SDK

## Getting Started

### 1. Install Tauri CLI

```bash
cargo install tauri-cli
```

Or use npm:

```bash
npm install -g @tauri-apps/cli
```

### 2. Navigate to the project directory

```bash
cd tauri-app
```

### 3. Run the development server

```bash
cargo tauri dev
```

Or if using npm:

```bash
npm run tauri dev
```

This will:
- Build the Rust backend
- Launch the development window
- Watch for changes and rebuild automatically

### 4. Build for production

```bash
cargo tauri build
```

Or:

```bash
npm run tauri build
```

This creates an installer in `src-tauri/target/release/bundle/`.

## Project Structure

```
tauri-app/
├── src/                 # Frontend files (HTML, CSS, JS)
│   ├── index.html
│   ├── styles.css
│   └── main.js
├── src-tauri/           # Rust backend
│   ├── src/
│   │   └── main.rs      # Main Rust entry point
│   ├── Cargo.toml       # Rust dependencies
│   ├── build.rs         # Build script
│   └── tauri.conf.json  # Tauri configuration
├── Cargo.toml           # Root Cargo.toml
└── README.md
```

## Features

- **Modern UI**: Clean, responsive design with gradient backgrounds
- **Rust Backend**: Fast and secure backend powered by Rust
- **Cross-platform**: Runs on Windows, macOS, and Linux
- **Small Bundle Size**: Much smaller than Electron apps

## Development

### Adding New Commands

1. Add a new command function in `src-tauri/src/main.rs`:

```rust
#[tauri::command]
fn my_command(param: String) -> String {
    format!("Received: {}", param)
}
```

2. Register it in the `invoke_handler`:

```rust
.invoke_handler(tauri::generate_handler![greet, my_command])
```

3. Call it from JavaScript:

```javascript
const result = await invoke("my_command", { param: "value" });
```

## Resources

- [Tauri Documentation](https://tauri.app/v1/guides/)
- [Rust Documentation](https://doc.rust-lang.org/)
- [Tauri API Reference](https://tauri.app/v1/api/js/)

## License

This project is open source and available under your chosen license.


