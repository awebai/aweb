"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");

const NativeBinary = Object.freeze({ AW: "aw", A2A_GATEWAY: "aweb-a2a-gw" });
const PACKAGES = Object.freeze({
  "linux x64": "@awebai/aw-linux-x64",
  "linux arm64": "@awebai/aw-linux-arm64",
  "darwin x64": "@awebai/aw-darwin-x64",
  "darwin arm64": "@awebai/aw-darwin-arm64",
  "win32 x64": "@awebai/aw-windows-x64",
  "win32 arm64": "@awebai/aw-windows-arm64",
});

function hostPlatform() {
  const key = `${process.platform} ${os.arch()}`;
  const pkg = PACKAGES[key];
  if (!pkg) throw new Error(`Unsupported platform ${key}. Visit https://github.com/awebai/aw for installation alternatives.`);
  return { key, pkg };
}

function binaryRelativePath(binary) {
  return `bin/${binary}${process.platform === "win32" ? ".exe" : ""}`;
}

function fallbackBinaryPath({ platform, binary }) {
  return path.join(__dirname, "npm-install", "node_modules", platform.pkg, binaryRelativePath(binary));
}

function resolveNativeBinary({ platform, binary }) {
  try {
    return require.resolve(`${platform.pkg}/${binaryRelativePath(binary)}`);
  } catch (error) {
    if (error.code !== "MODULE_NOT_FOUND") throw error;
    const fallback = fallbackBinaryPath({ platform, binary });
    fs.accessSync(fallback);
    return fallback;
  }
}

module.exports = { NativeBinary, hostPlatform, fallbackBinaryPath, resolveNativeBinary };
