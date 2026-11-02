# Install, update and remove

## macOS

### Download the app

For macOS 13 or later, on Apple Silicon or Intel.

1. Download `RouteWise-<version>-macos-universal.zip` from the
   [latest release](https://github.com/quocln/routewise/releases/latest).
2. Unzip it and move `RouteWise.app` to `/Applications`.
3. Open it. The app is not notarized, so macOS blocks the first launch. Go to
   **System Settings > Privacy & Security** and choose **Open Anyway**.
4. In **Settings > Helper Daemon**, choose **Install Helper** and enter your password.

To update, replace the app with the newer one, open it and choose **Reinstall Helper**. That
restarts the helper, so built-in VPNs disconnect.

### Build from source

You need Go, Rust with the `aarch64-apple-darwin` and `x86_64-apple-darwin` targets, Node, and
administrator rights. The installer fetches the pnpm version the app pins.

**Install or update:**

```bash
sudo make install
```

This builds as your user, not as root, then installs the helper and its launchd service, and
`RouteWise.app`. It keeps your configuration. A build that fails leaves the running helper alone.

Updating restarts the helper. Built-in VPNs disconnect and need connecting again, unless they
are set to connect automatically.

**Put the command line tool on your `PATH`.** The installer does not, and the commands in these docs assume it:

```bash
sudo mkdir -p /usr/local/bin
sudo ln -sf /Library/PrivilegedHelperTools/com.routewise.helper /usr/local/bin/routewise
```

Do not use the binary inside `RouteWise.app` for this: that one starts the app.

**Stop the helper.** launchd restarts it after `routewise stop`, so to stop it for good:

```bash
sudo launchctl bootout system/com.routewise.helper
```

Bring it back with `sudo launchctl bootstrap system /Library/LaunchDaemons/com.routewise.helper.plist`.

**Remove:**

```bash
sudo make uninstall
```

## Linux

The app needs systemd and systemd-resolved. Packages built by CI need the glibc of Ubuntu 22.04
and `libwebkit2gtk-4.1`, so Ubuntu 22.04+ or Debian 12+. To target an older distribution, build
on it.

Build on a Linux host:

```bash
sudo apt install build-essential libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev patchelf
make desktop-linux
```

This produces a `.deb` and an AppImage in `desktop/src-tauri/target/release/bundle/`.

- The `.deb` installs the helper as `routewise.service`, and removes it on uninstall. Your
  configuration, data and logs stay.
- The AppImage asks for administrator approval on first launch and installs the helper then.
  **Settings** can reinstall or remove it.

## Windows

Build on Windows with Go, Rust and Node:

```bash
make desktop-windows WIN_ARCH=amd64
```

The installer is in `desktop/src-tauri/target/<triple>/release/bundle/nsis/`. It is per machine,
asks for administrator approval, and registers the helper as the `RouteWise` service. Uninstalling
removes the service and leaves your data in `%ProgramData%\RouteWise`.

CI builds the same installers. See [what has been tested where](../reference/platforms.md).
