// Reads the compiled validator out of plutus.json.
//
// The hash is never hardcoded: it changes on every recompile, and a stale
// constant would silently point at an address nothing lives at. The one
// hardcoded value here is EXPECTED_HASH, which exists only to shout if the
// blueprint has been rebuilt since the deployment was planned.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const blueprintPath = join(here, "..", "..", "plutus.json");

/** The hash the deployment brief was written against (commit fadede1). */
export const EXPECTED_HASH =
  "9ba2f71219943a1ce365cb7ecd46c9655f7db774ebf553c43d1ff726";

export function loadValidator() {
  const blueprint = JSON.parse(readFileSync(blueprintPath, "utf8"));

  // spend, mint and else are the three purposes of one script, so they share a
  // hash and a body. Any of them yields the same bytes; take the spend entry.
  const validator = blueprint.validators.find((v) => v.title === "order.order.spend");
  if (!validator) throw new Error("order.order.spend not found in plutus.json");

  return {
    type: "PlutusV3",
    script: validator.compiledCode,
    hash: validator.hash,
    plutusVersion: blueprint.preamble.plutusVersion,
    compiler: blueprint.preamble.compiler,
  };
}
