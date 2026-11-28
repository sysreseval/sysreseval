// What an instructor may choose for a new project on the Open page: a host of the pool and a
// container engine, both automatic by default.  A host allows some engines (the `engines` of
// its row of GET /api/pool, the default one first; none told by an older agent: nothing is
// known of it, it is never left out), a lab may accept only some (the `engines` of its entry
// of the lab list; none: it accepts them all).  The rules are those of the placement of the
// portal (Pool._engines_fit): the page only keeps the instructor from asking what would be
// refused.  Pure functions: no page, no request.

function enginesOfRow(row) {
  return row && Array.isArray(row.engines) ? row.engines.filter((name) => typeof name === 'string' && name) : [];
}

// The engines the hosts allow, each once, in the order met.
export function enginesOf(rows) {
  const names = [];
  for (const row of Array.isArray(rows) ? rows : []) {
    for (const name of enginesOfRow(row)) {
      if (!names.includes(name)) {
        names.push(name);
      }
    }
  }
  return names;
}

// The engines a lab entry accepts: an array of names, or null when it accepts them all.
export function acceptedBy(lab) {
  const names = lab && Array.isArray(lab.engines) ? lab.engines.filter((name) => typeof name === 'string' && name) : [];
  return names.length ? names : null;
}

// Whether the host of `row` may run a project of a lab that accepts `accepted` (null: every
// engine) with `engine` ('' or null: whichever the host chooses).
export function hostFits(row, accepted, engine) {
  const allowed = enginesOfRow(row);
  if (engine) {
    return (!accepted || accepted.includes(engine)) && (!allowed.length || allowed.includes(engine));
  }
  return !allowed.length || !accepted || accepted.some((name) => allowed.includes(name));
}

// Whether `engine` may be asked for a project of a lab that accepts `accepted`, on the host of
// `row` (null: the automatic placement, then on some host of `rows`).
export function engineOffered(engine, row, accepted, rows) {
  if (accepted && !accepted.includes(engine)) {
    return false;
  }
  if (row) {
    const allowed = enginesOfRow(row);
    return !allowed.length || allowed.includes(engine);
  }
  return enginesOf(rows).includes(engine);
}
