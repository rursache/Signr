#!/usr/bin/env bash
# Build signr_core into an xcframework + Swift bindings consumed by the SwiftUI app.
# arm64-only (every Apple Silicon Mac on macOS 26). Add x86_64 later if Intel is needed.
set -euo pipefail
cd "$(dirname "$0")" # rust/

CRATE=signr_core
LIB=lib${CRATE}.a
PROFILE=release
BUILD=target/${PROFILE}
GEN=generated
HEADERS=${GEN}/headers
OUT=build
XCF=${OUT}/${CRATE}FFI.xcframework

echo "==> cargo build --${PROFILE}"
cargo build --${PROFILE} -p ${CRATE}

echo "==> generate Swift bindings"
rm -rf "${GEN}"
mkdir -p "${GEN}"
cargo run --${PROFILE} -p ${CRATE} --bin uniffi-bindgen -- generate \
    --library "${BUILD}/${LIB}" \
    --language swift \
    --out-dir "${GEN}"

# Swift 6 strict concurrency: the generated callback-interface vtable pointers are
# process-lifetime singletons; mark them nonisolated(unsafe) (UniFFI #2448 workaround).
sed -i '' 's/^    static let vtablePtr:/    nonisolated(unsafe) static let vtablePtr:/' "${GEN}/${CRATE}.swift"

echo "==> assemble headers + modulemap"
mkdir -p "${HEADERS}"
cp "${GEN}/${CRATE}FFI.h" "${HEADERS}/"
cp "${GEN}/${CRATE}FFI.modulemap" "${HEADERS}/module.modulemap"

echo "==> create xcframework"
rm -rf "${XCF}"
mkdir -p "${OUT}"
xcodebuild -create-xcframework \
    -library "${BUILD}/${LIB}" \
    -headers "${HEADERS}" \
    -output "${XCF}"

echo "==> copy generated Swift source into the app"
cp "${GEN}/${CRATE}.swift" "${OUT}/${CRATE}.swift"

echo ""
echo "Built ${XCF}"
echo "Bindings ${OUT}/${CRATE}.swift"
