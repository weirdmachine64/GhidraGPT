#!/bin/bash

# GhidraGPT Plugin Build and Install Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if GHIDRA_INSTALL_DIR is set
if [ -z "$GHIDRA_INSTALL_DIR" ]; then
    print_error "GHIDRA_INSTALL_DIR environment variable is not set"
    echo "Please set it to your Ghidra installation directory:"
    echo "export GHIDRA_INSTALL_DIR=/path/to/ghidra"
    exit 1
fi

# Verify Ghidra installation
if [ ! -d "$GHIDRA_INSTALL_DIR" ]; then
    print_error "Ghidra installation directory not found: $GHIDRA_INSTALL_DIR"
    exit 1
fi

if [ ! -d "$GHIDRA_INSTALL_DIR/Ghidra/Framework" ]; then
    print_error "Invalid Ghidra installation: Framework directory not found"
    exit 1
fi

print_status "Found Ghidra installation at: $GHIDRA_INSTALL_DIR"

# Check Java version
JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | awk -F'.' '{print $1}')
if [ "$JAVA_VERSION" -lt 11 ]; then
    print_error "Java 11 or later is required. Current version: $JAVA_VERSION"
    exit 1
fi

print_status "Java version check passed"

# Check if gradle is available
if ! command -v gradle &> /dev/null; then
    print_error "Gradle is not installed or not in PATH"
    print_status "Please install Gradle: https://gradle.org/install/"
    exit 1
fi

# Build the plugin
print_status "Building GhidraGPT plugin..."

# Remove existing build dir
rm -rf build

# Use gradlew if available, otherwise use system gradle
if [ -f "./gradlew" ]; then
    BUILD_CMD="./gradlew"
else
    BUILD_CMD="gradle"
fi

if $BUILD_CMD clean build -DGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"; then
    print_status "Build completed successfully"
else
    print_error "Build failed"
    exit 1
fi

# Check if build artifact exists
BUILD_DIRS="build/libs build/distributions"
PLUGIN_FILE=""

for dir in $BUILD_DIRS; do
    if [ -d "$dir" ]; then
        PLUGIN_FILE=$(find "$dir" -name "*.zip" | head -1)
        if [ -n "$PLUGIN_FILE" ]; then
            break
        fi
    fi
done

if [ -z "$PLUGIN_FILE" ]; then
    # If no zip found, look for JAR file
    for dir in $BUILD_DIRS; do
        if [ -d "$dir" ]; then
            PLUGIN_FILE=$(find "$dir" -name "*.jar" | head -1)
            if [ -n "$PLUGIN_FILE" ]; then
                break
            fi
        fi
    done
fi

if [ -z "$PLUGIN_FILE" ]; then
    print_error "No plugin file found in build directories"
    exit 1
fi

print_status "Built plugin: $PLUGIN_FILE"

print_status "Done!"
