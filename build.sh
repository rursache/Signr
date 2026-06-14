#!/usr/bin/env bash
# One-command build: Rust core -> xcframework -> Signr.app
set -euo pipefail
cd "$(dirname "$0")"

echo "==> [1/2] Building Rust core into an xcframework"
./rust/build-xcframework.sh

echo ""
echo "==> [2/2] Generating + building Signr.app"
xcodegen generate
xcodebuild -project Signr.xcodeproj -scheme Signr -configuration Debug \
  -derivedDataPath .build/DerivedData \
  -destination 'platform=macOS,arch=arm64' \
  build | tail -1

APP=".build/DerivedData/Build/Products/Debug/Signr.app"
# Keep a convenience symlink to the freshly built app at the repo root.
ln -sfn "${APP}" Signr.app
echo ""
echo "Built: $(pwd)/${APP}"
echo "Run:   open Signr.app"
