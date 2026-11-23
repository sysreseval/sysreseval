// The part of the dialog of an archive file (archive_file.js) computed without the page: what is
// shown of the sections GET /api/archives/{id}/file answers (the fields of `sre cat`).

// the keys of the `answers` of an archive that describe who answered and how, in the order
// shown; every other key is an answer, under the hash of its question
export const METADATA_KEYS = ['login', 'fullname', 'group', 'email', 'hostname', 'language', 'client',
                              'answers_updated_at', 'auto_eval_count', 'exam_mode', 'exam_started_at',
                              'exam_duration', 'exam_time_remaining'];

// the outcome of a command from its exit code: -1 is a timeout and -2 an output that was no
// exit code (lib/exetests.py)
export function codeKind(code) {
  if (code === 0) {
    return 'ok';
  }
  if (code === -1) {
    return 'timeout';
  }
  if (code === -2 || typeof code !== 'number') {
    return 'unknown';
  }
  return 'error';
}

// a size in bytes: 512 B, 14 KB, 2.3 MB
export function formatSize(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) {
    return '';
  }
  if (n < 1024) {
    return `${n} B`;
  }
  if (n < 1024 * 1024) {
    return `${Math.round(n / 1024)} KB`;
  }
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// the tests of an archive, one group per machine and step: {machine, step, commands, failed}
// (`failed` = the commands whose exit code is not 0)
export function testGroups(tests) {
  const groups = [];
  for (const entry of Array.isArray(tests) ? tests : []) {
    const commands = Array.isArray(entry.commands) ? entry.commands : [];
    groups.push({machine: String(entry.machine), step: entry.step, commands,
                 failed: commands.filter((c) => c.code !== 0).length});
  }
  return groups;
}

export function commandCount(tests) {
  return testGroups(tests).reduce((total, group) => total + group.commands.length, 0);
}

// a value as indented JSON (the Data and Grades sections, as `sre cat` prints them)
export function pretty(value) {
  return JSON.stringify(value === undefined ? null : value, null, 2);
}

// an answer as it is shown: the answer of a form is a JSON-encoded object, shown indented; the
// answer of a text question stays the text typed
export function answerText(value) {
  if (typeof value !== 'string') {
    return pretty(value);
  }
  const text = value.trim();
  if (text.startsWith('{') || text.startsWith('[')) {
    try {
      return pretty(JSON.parse(text));
    } catch (e) {
      return value;
    }
  }
  return value;
}

// {metadata: [[key, text]], answers: [[key, text]]} of the `answers` of an archive: the
// metadata present, in the order of METADATA_KEYS, then the answers in the order of the file
export function splitAnswers(answers) {
  const all = answers && typeof answers === 'object' ? answers : {};
  const metadata = [];
  for (const key of METADATA_KEYS) {
    if (Object.prototype.hasOwnProperty.call(all, key)) {
      const value = all[key];
      metadata.push([key, typeof value === 'string' ? value : pretty(value)]);
    }
  }
  const rows = [];
  for (const [key, value] of Object.entries(all)) {
    if (!METADATA_KEYS.includes(key)) {
      rows.push([key, answerText(value)]);
    }
  }
  return {metadata, answers: rows};
}
