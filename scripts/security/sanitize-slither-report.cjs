const path = require("node:path");

const POSIX_HOME_PATH = /\/(?:Users|home)\/[^/\s"']+(?:\/[^\s"']*)?/g;
const WINDOWS_HOME_PATH = /[A-Za-z]:\\Users\\[^\\\s"']+(?:\\[^\s"']*)?/g;

function repositoryRelativePath(value, repoRoot) {
  if (typeof value !== "string") return value;
  const normalizedRoot = path.resolve(repoRoot);
  if (value === normalizedRoot) return ".";
  if (value.startsWith(`${normalizedRoot}${path.sep}`)) {
    return path.relative(normalizedRoot, value).split(path.sep).join("/");
  }
  return value
    .split(`${normalizedRoot}${path.sep}`)
    .join("")
    .replace(POSIX_HOME_PATH, "<local-path>")
    .replace(WINDOWS_HOME_PATH, "<local-path>");
}

function sanitizeSlitherReport(value, repoRoot) {
  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeSlitherReport(entry, repoRoot));
  }
  if (value && typeof value === "object") {
    const result = {};
    for (const [key, entry] of Object.entries(value)) {
      if (
        key === "filename_absolute" &&
        typeof value.filename_relative === "string"
      ) {
        result[key] = value.filename_relative.split(path.sep).join("/");
      } else {
        result[key] = sanitizeSlitherReport(entry, repoRoot);
      }
    }
    return result;
  }
  return repositoryRelativePath(value, repoRoot);
}

function findAbsoluteDeveloperPaths(value) {
  const serialized = typeof value === "string" ? value : JSON.stringify(value);
  return [
    ...(serialized.match(POSIX_HOME_PATH) || []),
    ...(serialized.match(WINDOWS_HOME_PATH) || [])
  ];
}

function assertNoAbsoluteDeveloperPaths(value) {
  const matches = findAbsoluteDeveloperPaths(value);
  if (matches.length > 0) {
    throw new Error(
      `SLITHER_ABSOLUTE_DEVELOPER_PATH:${matches.slice(0, 3).join(",")}`
    );
  }
}

module.exports = {
  assertNoAbsoluteDeveloperPaths,
  findAbsoluteDeveloperPaths,
  sanitizeSlitherReport
};
