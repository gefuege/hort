#!/usr/bin/env node
"use strict";

const { createWriteStream, mkdirSync, chmodSync, existsSync, unlinkSync } = require("fs");
const { execSync } = require("child_process");
const path = require("path");
const https = require("https");
const os = require("os");

const VERSION = require("./package.json").version;
const REPO = "gefuege/hort";

const PLATFORM_MAP = { darwin: "darwin", linux: "linux", win32: "windows" };
const ARCH_MAP = { x64: "amd64", arm64: "arm64" };

function getBinaryName() {
  return process.platform === "win32" ? "hort.exe" : "hort";
}

function getArchiveUrl() {
  const platform = PLATFORM_MAP[process.platform];
  const arch = ARCH_MAP[process.arch];

  if (!platform || !arch) {
    throw new Error(`Unsupported platform: ${process.platform}/${process.arch}`);
  }

  const ext = process.platform === "win32" ? "zip" : "tar.gz";
  return `https://github.com/${REPO}/releases/download/v${VERSION}/hort_${VERSION}_${platform}_${arch}.${ext}`;
}

function download(url) {
  return new Promise((resolve, reject) => {
    const follow = (url, redirects) => {
      if (redirects > 5) return reject(new Error("Too many redirects"));

      https.get(url, { headers: { "User-Agent": "hort-npm" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return follow(res.headers.location, redirects + 1);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`Download failed: HTTP ${res.statusCode} from ${url}`));
        }
        resolve(res);
      }).on("error", reject);
    };
    follow(url, 0);
  });
}

async function extractTarGz(stream, destDir) {
  // All paths are script-controlled constants, no user input
  const tmpFile = path.join(os.tmpdir(), `hort-${Date.now()}.tar.gz`);
  await new Promise((resolve, reject) => {
    const out = createWriteStream(tmpFile);
    stream.pipe(out);
    out.on("finish", resolve);
    out.on("error", reject);
  });

  execSync(`tar -xzf "${tmpFile}" -C "${destDir}" ${getBinaryName()}`, { stdio: "ignore" });
  unlinkSync(tmpFile);
}

async function extractZip(stream, destDir) {
  // All paths are script-controlled constants, no user input
  const tmpFile = path.join(os.tmpdir(), `hort-${Date.now()}.zip`);
  await new Promise((resolve, reject) => {
    const out = createWriteStream(tmpFile);
    stream.pipe(out);
    out.on("finish", resolve);
    out.on("error", reject);
  });

  if (process.platform === "win32") {
    execSync(
      `powershell -Command "Expand-Archive -Path '${tmpFile}' -DestinationPath '${destDir}' -Force"`,
      { stdio: "ignore" }
    );
  } else {
    execSync(`unzip -o "${tmpFile}" ${getBinaryName()} -d "${destDir}"`, { stdio: "ignore" });
  }
  unlinkSync(tmpFile);
}

async function main() {
  const binDir = path.join(__dirname, "bin");
  const binaryPath = path.join(binDir, getBinaryName());

  if (existsSync(binaryPath)) {
    return; // Already installed
  }

  const url = getArchiveUrl();
  console.log(`Downloading hort v${VERSION}...`);

  mkdirSync(binDir, { recursive: true });

  const stream = await download(url);

  if (process.platform === "win32") {
    await extractZip(stream, binDir);
  } else {
    await extractTarGz(stream, binDir);
    chmodSync(binaryPath, 0o755);
  }

  console.log("hort installed successfully.");
}

main().catch((err) => {
  console.error(`Failed to install hort: ${err.message}`);
  process.exit(1);
});
