import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { readRegularFile } from "./release.mjs";

const withFiles = (run) => {
  const root = fs.mkdtempSync(path.join(process.cwd(), "release-read-test-"));
  try {
    return run(root);
  } finally {
    const workspace = path.resolve(process.cwd()) + path.sep;
    if (!path.resolve(root).startsWith(workspace)) {
      throw new Error("Refusing to remove a test directory outside this checkout.");
    }
    fs.rmSync(root, { recursive: true, force: true });
  }
};

test("reads an unchanged regular release artifact", () =>
  withFiles((root) => {
    const file = path.join(root, "artifact.zip");
    fs.writeFileSync(file, "verified package bytes");
    assert.equal(readRegularFile(file).toString(), "verified package bytes");
  }));

test("refuses a directory in place of a release artifact", () =>
  withFiles((root) => {
    const directory = path.join(root, "artifact.zip");
    fs.mkdirSync(directory);
    assert.throws(() => readRegularFile(directory));
  }));

test("refuses an oversized release artifact before allocating for it", () =>
  withFiles((root) => {
    const file = path.join(root, "artifact.zip");
    fs.writeFileSync(file, "");
    fs.truncateSync(file, 64 * 1024 * 1024 + 1);
    assert.throws(() => readRegularFile(file), /size limit/);
  }));

test("refuses a different file substituted after opening the artifact", () =>
  withFiles((root) => {
    const file = path.join(root, "artifact.zip");
    const replacement = path.join(root, "replacement.zip");
    fs.writeFileSync(file, "verified package bytes");
    fs.writeFileSync(replacement, "substituted package bytes");
    const actualLstat = fs.lstatSync;
    fs.lstatSync = (...args) => {
      fs.renameSync(file, path.join(root, "original.zip"));
      fs.renameSync(replacement, file);
      return actualLstat(...args);
    };
    try {
      assert.throws(() => readRegularFile(file), /changed or is not a regular file/);
    } finally {
      fs.lstatSync = actualLstat;
    }
    assert.equal(fs.readFileSync(file, "utf8"), "substituted package bytes");
  }));

test("refuses an artifact changed while its handle is open", () =>
  withFiles((root) => {
    const file = path.join(root, "artifact.zip");
    fs.writeFileSync(file, "original");
    const actualLstat = fs.lstatSync;
    fs.lstatSync = (...args) => {
      fs.writeFileSync(file, "changed while being read");
      return actualLstat(...args);
    };
    try {
      assert.throws(() => readRegularFile(file), /changed while being read/);
    } finally {
      fs.lstatSync = actualLstat;
    }
  }));
