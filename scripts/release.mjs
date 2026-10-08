import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const publish = async ({ github, context, core }) => {
  if (
    context.eventName !== "push" ||
    context.ref !== "refs/heads/main" ||
    !/^[0-9a-f]{40}$/.test(context.sha)
  ) {
    throw new Error(
      "Publishing requires a main push with an exact commit SHA.",
    );
  }
  const version = /^version = "(\d+\.\d+\.\d+)"$/m.exec(fs.readFileSync("Cargo.toml", "utf8"))?.[1];
  if (!version || context.repo.repo !== "zero") throw Error("Expected versioned Zero source.");
  const tag = "v" + version;
  const { owner, repo } = context.repo;
  const releases = await github.paginate(github.rest.repos.listReleases, {
    owner,
    repo,
    per_page: 100,
  });
  const matching = releases.filter((release) => release.tag_name === tag);
  if (matching.length > 1) throw new Error("Multiple releases use " + tag);
  let release = matching[0];
  if (release && !release.draft) {
    core.info(
      "Release " + tag + " is already published; leaving it unchanged.",
    );
    return;
  }
  if (
    release &&
    (release.target_commitish !== context.sha || release.prerelease)
  ) {
    throw new Error(
      "Existing draft does not belong to this exact release commit.",
    );
  }
  const requireCurrentHead = async () => {
    const branch = (
      await github.rest.repos.getBranch({ owner, repo, branch: "main" })
    ).data;
    if (branch.commit.sha !== context.sha)
      throw new Error("Main advanced beyond the checked release commit.");
  };
  await requireCurrentHead();

  const tagCommit = async () => {
    let object;
    try {
      object = (
        await github.rest.git.getRef({ owner, repo, ref: "tags/" + tag })
      ).data.object;
    } catch (error) {
      if (error.status === 404) return null;
      throw error;
    }
    for (let depth = 0; depth < 10; depth++) {
      if (object.type === "commit") return object.sha;
      if (object.type !== "tag")
        throw new Error("Release tag does not point to a commit.");
      object = (
        await github.rest.git.getTag({
          owner,
          repo,
          tag_sha: object.sha,
        })
      ).data.object;
    }
    throw new Error("Release tag has too many annotated tag layers.");
  };
  const requireCorrectTag = async () => {
    const commit = await tagCommit();
    if (commit !== null && commit !== context.sha) {
      throw new Error("Existing release tag points to a different commit.");
    }
    return commit;
  };
  await requireCorrectTag();

  const directory = "release-artifacts";
  const filenames = fs.readdirSync(directory).sort();
  const archives = [`Zero-${version}-Source.zip`, `Zero-${version}-Windows.zip`, "Zero.exe"];
  const expectedInputs = [
    ...archives.flatMap((filename) => [filename, filename + ".sha256"]),
    "SHA256SUMS",
  ].sort();
  if (JSON.stringify(filenames) !== JSON.stringify(expectedInputs)) {
    throw new Error(
      "Downloaded artifacts contain unexpected or missing files.",
    );
  }
  const payloads = [];
  const checksumLines = [];
  const readFile = (filename) => {
    const location = path.join(directory, filename);
    if (!fs.lstatSync(location).isFile())
      throw new Error("Artifact is not a regular file.");
    return fs.readFileSync(location);
  };
  const digest = (data) =>
    "sha256:" + crypto.createHash("sha256").update(data).digest("hex");
  for (const filename of archives) {
    const data = readFile(filename);
    const checksum = readFile(filename + ".sha256");
    const expected = digest(data).slice(7) + "  " + filename + "\n";
    if (checksum.toString("utf8") !== expected) {
      throw new Error("Artifact checksum mismatch: " + filename);
    }
    checksumLines.push(expected);
    payloads.push(
      { name: filename, data },
      { name: filename + ".sha256", data: checksum },
    );
  }
  const combined = Buffer.from(checksumLines.join(""), "utf8");
  if (!readFile("SHA256SUMS").equals(combined))
    throw new Error("Combined checksums do not match the package set.");
  payloads.push({ name: "SHA256SUMS", data: combined });
  for (const payload of payloads) payload.digest = digest(payload.data);

  const changelog = fs
    .readFileSync("CHANGELOG.md", "utf8")
    .replaceAll("\r\n", "\n");
  const heading = "## " + version + "\n";
  if (!changelog.includes(heading))
    throw new Error("Changelog has no release section.");
  const notes = changelog.split(heading)[1].split("\n## ")[0].trim();
  const body = notes + "\n\nDownload the Windows ZIP, compare SHA256SUMS, extract the complete folder and read README.md before selecting disposable copies. Zero processes explicitly selected files immediately and cannot undo it. No installer, account or API key is required. The matching source ZIP includes the Rust code, build instructions and release manifest. Logical cleanup does not establish physical-media erasure or remove backups and snapshots.\n\n[Use, build, upgrade and recovery](https://github.com/" + owner + "/" + repo + "/blob/" + tag + "/README.md).";
  await requireCurrentHead();
  if (!release) {
    release = (
      await github.rest.repos.createRelease({
        owner,
        repo,
        tag_name: tag,
        target_commitish: context.sha,
        name: "Zero " + version,
        body,
        draft: true,
        prerelease: false,
      })
    ).data;
  } else {
    release = (
      await github.rest.repos.updateRelease({
        owner,
        repo,
        release_id: release.id,
        name: "Zero " + version,
        body,
        draft: true,
        prerelease: false,
      })
    ).data;
  }
  const existing = await github.paginate(github.rest.repos.listReleaseAssets, {
    owner,
    repo,
    release_id: release.id,
    per_page: 100,
  });
  const wanted = new Map(payloads.map((payload) => [payload.name, payload]));
  const existingNames = new Set();
  for (const asset of existing) {
    if (!wanted.has(asset.name) || existingNames.has(asset.name)) {
      throw new Error("Draft contains an unexpected or duplicate asset.");
    }
    existingNames.add(asset.name);
  }
  for (const payload of payloads) {
    const previous = existing.find((asset) => asset.name === payload.name);
    if (
      previous &&
      previous.digest === payload.digest &&
      previous.size === payload.data.length &&
      previous.state === "uploaded"
    ) {
      continue;
    }
    if (previous) {
      await github.rest.repos.deleteReleaseAsset({
        owner,
        repo,
        asset_id: previous.id,
      });
    }
    const uploaded = (
      await github.rest.repos.uploadReleaseAsset({
        owner,
        repo,
        release_id: release.id,
        name: payload.name,
        data: payload.data,
        headers: {
          "content-type": "application/octet-stream",
          "content-length": payload.data.length,
        },
      })
    ).data;
    if (
      uploaded.digest !== payload.digest ||
      uploaded.size !== payload.data.length ||
      uploaded.state !== "uploaded"
    ) {
      throw new Error("Uploaded asset verification failed: " + payload.name);
    }
    core.info("Verified uploaded asset: " + payload.name);
  }
  const finalAssets = await github.paginate(
    github.rest.repos.listReleaseAssets,
    {
      owner,
      repo,
      release_id: release.id,
      per_page: 100,
    },
  );
  if (
    finalAssets.length !== payloads.length ||
    new Set(finalAssets.map((asset) => asset.name)).size !== payloads.length ||
    finalAssets.some((asset) => {
      const expected = wanted.get(asset.name);
      return (
        !expected ||
        asset.digest !== expected.digest ||
        asset.size !== expected.data.length ||
        asset.state !== "uploaded"
      );
    })
  ) {
    throw new Error(
      "Draft assets do not match the complete verified package set.",
    );
  }
  const latest = (
    await github.rest.repos.getRelease({
      owner,
      repo,
      release_id: release.id,
    })
  ).data;
  if (
    !latest.draft ||
    latest.target_commitish !== context.sha ||
    latest.tag_name !== tag
  ) {
    throw new Error("Draft changed during upload; publication stopped.");
  }
  // Create the tag at the checked commit explicitly; target_commitish cannot move an existing tag.
  await requireCurrentHead();
  if ((await requireCorrectTag()) === null) {
    await github.rest.git.createRef({
      owner,
      repo,
      ref: "refs/tags/" + tag,
      sha: context.sha,
    });
  }
  if ((await requireCorrectTag()) !== context.sha) {
    throw new Error("Release tag is missing before publication.");
  }
  await requireCurrentHead();
  await github.rest.repos.updateRelease({
    owner,
    repo,
    release_id: release.id,
    draft: false,
    make_latest: "true",
  });
  core.info("Published Zero " + version + " at " + context.sha);
};
export default publish;
