# ssh-key-control for macOS
#
#   make            build build/bin/ssh-key-control and build/libexec/ssh-key-control-ui
#   make test       run the Go and Swift tests
#   make install    copy both files under $(PREFIX); registers nothing
#   make uninstall  remove those files
#
# Defaults to a user-only install; override with make install PREFIX=/path/to/prefix.
# After `make install`, register the agent for your user (no sudo):
#   ssh-key-control install

PREFIX     ?= $(HOME)/.local
DESTDIR    ?=
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO         ?= go
SWIFT      ?= swift
SWIFTFLAGS ?=
SIGN_IDENTITY ?= -
SIGN_FLAGS = --options runtime $(if $(filter -,$(SIGN_IDENTITY)),,--timestamp)

BUILD   = build
BIN     = $(BUILD)/bin/ssh-key-control
HELPER  = $(BUILD)/libexec/ssh-key-control-ui
UI_RESOURCES = ssh-key-control-ui_SSHKeyControlUI.bundle
APP     = $(BUILD)/SSH Key Control.app
DMG     = $(BUILD)/SSH-Key-Control-$(shell uname -m).dmg
APPDIR  ?= $(HOME)/Applications
# Keep symbols: govulncheck otherwise falls back to module-wide guesses on Mach-O.
LDFLAGS = -X main.version=$(VERSION)

.PHONY: all build test test-go test-ui check install uninstall clean app dmg install-app FORCE

all: build

build: $(BIN) $(HELPER) app

$(BIN): FORCE
	@mkdir -p $(dir $@)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/ssh-key-control

$(HELPER): FORCE
	@mkdir -p $(dir $@)
	$(SWIFT) build -c release --package-path ui $(SWIFTFLAGS)
	cp ui/.build/release/ssh-key-control-ui $@
	ditto "ui/.build/release/$(UI_RESOURCES)" "$(BUILD)/libexec/$(UI_RESOURCES)"
	codesign --force --sign "$(SIGN_IDENTITY)" $(SIGN_FLAGS) $@

app: $(BIN) $(HELPER)
	mkdir -p "$(APP)/Contents/MacOS" "$(APP)/Contents/Resources"
	cp ui/App/Info.plist "$(APP)/Contents/Info.plist"
	ditto "ui/.build/release/$(UI_RESOURCES)" "$(APP)/Contents/Resources/$(UI_RESOURCES)"
	cp ui/.build/release/ssh-key-control-menubar "$(APP)/Contents/MacOS/"
	cp $(BIN) "$(APP)/Contents/MacOS/"
	cp $(HELPER) "$(APP)/Contents/MacOS/"
	ui/.build/release/ssh-key-control-menubar --render-assets "$(BUILD)/artwork"
	iconutil -c icns "$(BUILD)/artwork/AppIcon.iconset" -o "$(APP)/Contents/Resources/AppIcon.icns"
	codesign --force --sign "$(SIGN_IDENTITY)" $(SIGN_FLAGS) "$(APP)/Contents/MacOS/ssh-key-control"
	codesign --force --sign "$(SIGN_IDENTITY)" $(SIGN_FLAGS) "$(APP)/Contents/MacOS/ssh-key-control-ui"
	codesign --force --sign "$(SIGN_IDENTITY)" $(SIGN_FLAGS) "$(APP)"

dmg: app
	bash scripts/build-dmg.sh "$(APP)" "$(DMG)" "$(SIGN_IDENTITY)"

install-app: app
	mkdir -p "$(DESTDIR)$(APPDIR)"
	ditto "$(APP)" "$(DESTDIR)$(APPDIR)/SSH Key Control.app"

test: test-go test-ui

test-go:
	$(GO) test -race ./...

test-ui:
	$(SWIFT) test --package-path ui $(SWIFTFLAGS)

# What CI runs before the tests.
check:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; echo "gofmt: files above need formatting"; exit 1; }
	$(GO) vet ./...

install: build
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/libexec
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/ssh-key-control
	install -m 0755 $(HELPER) $(DESTDIR)$(PREFIX)/libexec/ssh-key-control-ui
	ditto "$(BUILD)/libexec/$(UI_RESOURCES)" "$(DESTDIR)$(PREFIX)/libexec/$(UI_RESOURCES)"
	@echo
	mkdir -p "$(DESTDIR)$(APPDIR)"
	ditto "$(APP)" "$(DESTDIR)$(APPDIR)/SSH Key Control.app"
	@echo "Installed under $(PREFIX). Register the agent for your user (no sudo):"
	@echo "    $(PREFIX)/bin/ssh-key-control install"

uninstall:
	@echo "Note: run 'ssh-key-control uninstall' first if the agent is still registered."
	rm -f $(DESTDIR)$(PREFIX)/bin/ssh-key-control $(DESTDIR)$(PREFIX)/libexec/ssh-key-control-ui
	rm -rf "$(DESTDIR)$(APPDIR)/SSH Key Control.app" "$(DESTDIR)$(PREFIX)/libexec/$(UI_RESOURCES)"

clean:
	rm -rf $(BUILD) ui/.build

FORCE:
