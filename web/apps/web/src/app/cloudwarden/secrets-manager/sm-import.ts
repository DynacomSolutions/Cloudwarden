// Cloudwarden: parsing and validating a Secrets Manager import file (web/NOTICE.md).
// The file is the JSON the export button writes: decrypted projects and secrets. Everything is
// checked here, before anything is encrypted or sent.
import { SmExportFile } from "./sm-api.service";

export const SM_IMPORT_MAX_ITEMS = 5000;
export const SM_IMPORT_MAX_BYTES = 20 * 1024 * 1024;
const MAX_NAME = 500;
const MAX_VALUE = 25000;
const MAX_NOTE = 7000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface SmImportCheck {
  /** The cleaned file, only when `errors` is empty. */
  file: SmExportFile | null;
  errors: string[];
  projects: number;
  secrets: number;
  /** Secrets that belong to no project (they need an owner or admin). */
  loose: number;
}

const str = (v: unknown): v is string => typeof v === "string";

/** `newId` supplies ids for entries a file leaves without one (hand written files). */
export function checkImport(text: string, newId: () => string = () => crypto.randomUUID()) {
  const out: SmImportCheck = { file: null, errors: [], projects: 0, secrets: 0, loose: 0 };
  const fail = (m: string) => {
    if (out.errors.length < 20) {
      out.errors.push(m);
    }
  };
  if (text.length > SM_IMPORT_MAX_BYTES) {
    fail("The file is too large.");
    return out;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    fail("The file is not valid JSON.");
    return out;
  }
  const root = raw as { projects?: unknown; secrets?: unknown } | null;
  if (!root || typeof root !== "object" || Array.isArray(root)) {
    fail("The file must be a JSON object with projects and secrets.");
    return out;
  }
  const projectsIn = root.projects ?? [];
  const secretsIn = root.secrets ?? [];
  if (!Array.isArray(projectsIn) || !Array.isArray(secretsIn)) {
    fail("projects and secrets must be lists.");
    return out;
  }
  if (projectsIn.length > SM_IMPORT_MAX_ITEMS || secretsIn.length > SM_IMPORT_MAX_ITEMS) {
    fail(`At most ${SM_IMPORT_MAX_ITEMS} projects and ${SM_IMPORT_MAX_ITEMS} secrets can be imported.`);
    return out;
  }

  const projects: SmExportFile["projects"] = [];
  const projectIds = new Set<string>();
  projectsIn.forEach((p: any, i) => {
    const where = `Project ${i + 1}`;
    const id = p?.id == null ? newId() : p.id;
    if (!str(id) || !UUID.test(id)) {
      fail(`${where}: the id is not a valid id.`);
    } else if (projectIds.has(id.toLowerCase())) {
      fail(`${where}: the id is used twice.`);
    }
    if (!str(p?.name) || p.name.trim() === "" || p.name.length > MAX_NAME) {
      fail(`${where}: the name is missing or longer than ${MAX_NAME} characters.`);
    }
    if (str(id)) {
      projectIds.add(id.toLowerCase());
      projects.push({ id: id.toLowerCase(), name: str(p?.name) ? p.name.trim() : "" });
    }
  });

  const secrets: SmExportFile["secrets"] = [];
  const secretIds = new Set<string>();
  secretsIn.forEach((s: any, i) => {
    const where = `Secret ${i + 1}`;
    const id = s?.id == null ? newId() : s.id;
    if (!str(id) || !UUID.test(id)) {
      fail(`${where}: the id is not a valid id.`);
    } else if (secretIds.has(id.toLowerCase())) {
      fail(`${where}: the id is used twice.`);
    }
    if (!str(s?.key) || s.key.trim() === "" || s.key.length > MAX_NAME) {
      fail(`${where}: the name is missing or longer than ${MAX_NAME} characters.`);
    }
    if (!str(s?.value) || s.value === "" || s.value.length > MAX_VALUE) {
      fail(`${where}: the value is missing or longer than ${MAX_VALUE} characters.`);
    }
    if (s?.note != null && (!str(s.note) || s.note.length > MAX_NOTE)) {
      fail(`${where}: the note is longer than ${MAX_NOTE} characters.`);
    }
    const links = s?.projectIds ?? [];
    if (
      !Array.isArray(links) ||
      links.length > 1 ||
      links.some((l) => !str(l) || !projectIds.has(l.toLowerCase()))
    ) {
      fail(`${where}: it must refer to at most one project that is in the file.`);
    }
    if (str(id)) {
      secretIds.add(id.toLowerCase());
      secrets.push({
        id: id.toLowerCase(),
        key: str(s?.key) ? s.key.trim() : "",
        value: str(s?.value) ? s.value : "",
        note: str(s?.note) ? s.note : "",
        projectIds: Array.isArray(links) ? links.filter(str).map((l) => l.toLowerCase()) : [],
      });
    }
  });

  out.projects = projects.length;
  out.secrets = secrets.length;
  out.loose = secrets.filter((s) => s.projectIds.length === 0).length;
  if (out.projects + out.secrets === 0) {
    fail("The file has no projects or secrets.");
  }
  if (out.errors.length === 0) {
    out.file = { projects, secrets };
  }
  return out;
}
