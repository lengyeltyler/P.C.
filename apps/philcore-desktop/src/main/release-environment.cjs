"use strict";

// Reject inherited test selectors before loading Runtime, storage, or auth.
// Never echo environment values, argv, paths, or credentials in this error.
const RELEASE_TEST_SELECTOR_ERROR = "PHILCORE_RELEASE_TEST_SELECTOR_REJECTED";
const TEST_ENVIRONMENT_NAMES = /^(?:PHILCORE_DESKTOP_(?:E2E|DEV)(?:_|$)|PHILCORE_UI_TEST_|PHILCORE_MACOS_USER_PRESENCE_HELPER(?:_SHA256)?$)/u;
const TEST_ARGUMENT = /^--(?:philcore[-_](?:e2e|test|fixture|ui-test)|(?:e2e|fixture|test-auth)(?:=|$))/iu;

function releaseEnvironmentError({ packaged, env = {}, argv = [] }) {
  if (!packaged) return null;
  return Object.keys(env).some((name) => TEST_ENVIRONMENT_NAMES.test(name))
    || argv.some((argument) => TEST_ARGUMENT.test(String(argument)))
    ? RELEASE_TEST_SELECTOR_ERROR : null;
}

module.exports = { RELEASE_TEST_SELECTOR_ERROR, releaseEnvironmentError };
