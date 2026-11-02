# Smart VPN Routing Daemon Makefile

BINARY_NAME=routewise
BUILD_DIR=build
GO=go

# Version info (can be overridden)
VERSION?=$(shell sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' desktop/package.json | head -n 1)
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# The installer builds the helper as root, and git refuses a repository owned by
# another user, so Go's automatic VCS stamping fails there. The commit is passed
# in through COMMIT instead, which makes the stamping redundant.
BUILDVCS=-buildvcs=false

# Architecture detection
ARCH?=$(shell uname -m)
ifeq ($(ARCH),arm64)
	GOARCH=arm64
else
	GOARCH=amd64
endif

.PHONY: all build clean install uninstall test lint fmt help app clean-app build-helper-universal stage-desktop-helper desktop-universal stage-desktop-helper-linux desktop-linux stage-desktop-helper-windows desktop-windows

all: build

## build: Build the binary (native architecture)
build:
	@echo "Building $(BINARY_NAME) for $(ARCH)..."
	@mkdir -p $(BUILD_DIR)
	GOARCH=$(GOARCH) $(GO) build $(LDFLAGS) $(BUILDVCS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/routewise

## build-release: Build optimized release binary
build-release:
	@echo "Building release $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(LDFLAGS) $(BUILDVCS) -trimpath -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/routewise

## install: Build and install the helper, its service and RouteWise.app (requires sudo)
install: build
	sudo bash ./scripts/install.sh

## uninstall: Remove the helper, its service and RouteWise.app (requires sudo)
uninstall:
	sudo bash ./scripts/uninstall.sh

## test: Run tests
test:
	$(GO) test -v -race ./...

## test-coverage: Run tests with coverage
test-coverage:
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

## lint: Run linter
lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

## fmt: Format code
fmt:
	$(GO) fmt ./...
	goimports -w .

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

## tidy: Tidy go modules
tidy:
	$(GO) mod tidy

## help: Show this help
help:
	@echo "Available targets:"
	@grep -E '^## ' Makefile | sed 's/## /  /'

# macOS App targets
APP_BUNDLE := build/RouteWise.app
HELPER_BINARY := build/com.routewise.helper

## app: Build the GUI app with helper as a universal binary (Intel + Apple Silicon)
app: desktop-universal

## build-helper-universal: Build the Go helper daemon for Intel and Apple Silicon in one binary
build-helper-universal:
	@echo "Building universal helper daemon (x86_64 + arm64)..."
	@mkdir -p $(BUILD_DIR)
	GOARCH=amd64 GOOS=darwin CGO_ENABLED=0 $(GO) build $(LDFLAGS) $(BUILDVCS) -o $(HELPER_BINARY)-amd64 ./cmd/routewise
	GOARCH=arm64 GOOS=darwin CGO_ENABLED=0 $(GO) build $(LDFLAGS) $(BUILDVCS) -o $(HELPER_BINARY)-arm64 ./cmd/routewise
	lipo -create -output $(HELPER_BINARY) $(HELPER_BINARY)-amd64 $(HELPER_BINARY)-arm64
	@rm -f $(HELPER_BINARY)-amd64 $(HELPER_BINARY)-arm64
	codesign -f -s - $(HELPER_BINARY)
	@lipo -info $(HELPER_BINARY)

# The Tauri app ships the helper, its launchd plist, and the starter config as
# bundle resources, so it can install the helper itself.
DESKTOP_DIR := desktop
# Run the pnpm this app pins, whichever pnpm comes first on PATH. Another version
# tries to switch itself to the pin, and for a standalone pnpm that fails: it
# asks for a @pnpm/macos-x64 version that package never published. npx also puts
# the pinned pnpm first on PATH for the `pnpm build` that `tauri build` runs.
PNPM = npx --yes $(shell node -p "require('./$(DESKTOP_DIR)/package.json').packageManager")
DESKTOP_HELPER_RESOURCES := $(DESKTOP_DIR)/src-tauri/resources/helper
DESKTOP_UNIVERSAL_BUNDLE := $(DESKTOP_DIR)/src-tauri/target/universal-apple-darwin/release/bundle/macos/RouteWise.app

## stage-desktop-helper: Put the universal helper and the starter config where the Tauri bundle picks them up
## (the app writes the launchd plist itself)
stage-desktop-helper: build-helper-universal
	@rm -rf $(DESKTOP_HELPER_RESOURCES)
	@mkdir -p $(DESKTOP_HELPER_RESOURCES)
	cp $(HELPER_BINARY) $(DESKTOP_HELPER_RESOURCES)/
	cp config/starter-config.yaml $(DESKTOP_HELPER_RESOURCES)/config.yaml

## desktop-universal: Build the Tauri app with the helper for Intel and Apple Silicon (needs the aarch64 and x86_64 macOS Rust targets)
desktop-universal: stage-desktop-helper
	@# Targets belong to a toolchain, so add them to whichever one this shell uses; a no-op once present.
	rustup target add aarch64-apple-darwin x86_64-apple-darwin
	cd $(DESKTOP_DIR) && $(PNPM) install --frozen-lockfile && $(PNPM) tauri build --target universal-apple-darwin --bundles app
	@rm -rf $(APP_BUNDLE)
	@mkdir -p $(BUILD_DIR)
	cp -R $(DESKTOP_UNIVERSAL_BUNDLE) $(APP_BUNDLE)
	codesign -f -s - $(APP_BUNDLE)
	@lipo -info $(APP_BUNDLE)/Contents/MacOS/routewise-desktop $(APP_BUNDLE)/Contents/Resources/helper/com.routewise.helper
	@echo "Universal Tauri app bundle created at $(APP_BUNDLE)"

# Linux: the helper installs itself (`routewise service install`, which seeds
# its own config), so the bundle carries only the binary. It is built static
# (no cgo) so it runs on any distro whatever the build host's glibc. Build on a
# Linux host with the Tauri system libraries (see README), ideally the oldest
# distro the packages should run on, or cross-build the helper alone.
DESKTOP_LINUX_GOARCH ?= $(if $(filter arm64 aarch64,$(ARCH)),arm64,amd64)

## stage-desktop-helper-linux: Build the static Linux helper where the Tauri bundle picks it up
stage-desktop-helper-linux:
	@rm -rf $(DESKTOP_HELPER_RESOURCES)
	@mkdir -p $(DESKTOP_HELPER_RESOURCES)
	GOOS=linux GOARCH=$(DESKTOP_LINUX_GOARCH) CGO_ENABLED=0 $(GO) build $(LDFLAGS) $(BUILDVCS) -trimpath -o $(DESKTOP_HELPER_RESOURCES)/$(BINARY_NAME) ./cmd/routewise

## desktop-linux: Build the Tauri app and its .deb and AppImage with the Linux helper (run on Linux)
desktop-linux: stage-desktop-helper-linux
	cd $(DESKTOP_DIR) && $(PNPM) install --frozen-lockfile && $(PNPM) tauri build --bundles deb,appimage

# Windows: the helper installs itself (`routewise.exe service install`, run by
# the installer), so the bundle carries routewise.exe and the wintun.dll that
# must sit beside it. These run on a Windows host (Git Bash), where the Tauri
# NSIS bundler is available.
WIN_ARCH ?= amd64
WIN_RUST_TRIPLE = $(if $(filter arm64,$(WIN_ARCH)),aarch64,x86_64)-pc-windows-msvc

## stage-desktop-helper-windows: Build routewise.exe and fetch wintun.dll (WIN_ARCH=amd64|arm64) where the Tauri bundle picks them up
stage-desktop-helper-windows:
	VERSION=$(VERSION) COMMIT=$(COMMIT) bash scripts/stage-windows-desktop-helper.sh $(WIN_ARCH)

## desktop-windows: Build the Tauri app and its NSIS installer with the Windows helper (run on Windows; WIN_ARCH=amd64|arm64)
desktop-windows: stage-desktop-helper-windows
	rustup target add $(WIN_RUST_TRIPLE)
	cd $(DESKTOP_DIR) && $(PNPM) install --frozen-lockfile && $(PNPM) tauri build --bundles nsis --target $(WIN_RUST_TRIPLE)

## clean-app: Remove app build artifacts
clean-app:
	@rm -rf $(APP_BUNDLE)
	@rm -f $(HELPER_BINARY)
