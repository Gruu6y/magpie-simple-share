import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Resolve the base Magpie configuration directory.
 * Precedence: MAGPIE_CONFIG_DIR -> $XDG_CONFIG_HOME/magpie -> <home>/.config/magpie.
 */
export function magpieConfigDir(env = process.env, { platform = process.platform } = {}) {
  const e = env ?? process.env;
  if (e.MAGPIE_CONFIG_DIR) {
    return e.MAGPIE_CONFIG_DIR;
  }
  if (e.XDG_CONFIG_HOME) {
    return join(e.XDG_CONFIG_HOME, "magpie");
  }
  const home =
    platform === "win32"
      ? e.USERPROFILE || e.HOME || homedir()
      : e.HOME || e.USERPROFILE || homedir();
  return join(home, ".config", "magpie");
}

/**
 * Resolve the magpie-simple-share plugin data directory.
 */
export function pluginDataDir(env = process.env, { platform = process.platform } = {}) {
  const e = env ?? process.env;
  if (e.MAGPIE_SIMPLE_SHARE_DATA) {
    return e.MAGPIE_SIMPLE_SHARE_DATA;
  }
  if (e.MAGPIE_SIMPLE_SHARE_DATA_DIR) {
    return e.MAGPIE_SIMPLE_SHARE_DATA_DIR;
  }
  return join(magpieConfigDir(e, { platform }), "magpie-simple-share");
}

/**
 * Path to the persisted device Ed25519 identity JSON file.
 */
export function identityPath(env = process.env) {
  return join(pluginDataDir(env), "identity.json");
}

/**
 * Path to the persisted plugin state JSON file.
 */
export function statePath(env = process.env) {
  return join(pluginDataDir(env), "state.json");
}

/**
 * Path to the on-demand @number0/iroh installation directory.
 */
export function irohDir(env = process.env) {
  return join(pluginDataDir(env), "iroh");
}
