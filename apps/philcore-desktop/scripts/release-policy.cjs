const REPLACEMENT_RELEASE_IDENTIFIER = "philcore-desktop-o11-1-trusted-tester-rc2";
const REVOKED_ARTIFACTS = Object.freeze({
  eb3ae7e67ecad33128477269dd2e8de98003671fdaa5156f3854d4744c045a9c: Object.freeze({
    releaseIdentifier: "philcore-desktop-o9-trusted-tester-rc1",
    reason: "AppleDouble contamination causing framework seal failure during normal Finder installation."
  })
});

module.exports = { REPLACEMENT_RELEASE_IDENTIFIER, REVOKED_ARTIFACTS };
