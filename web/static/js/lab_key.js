// The key the summaries group the projects of one lab by: the lab file the project really runs
// (`canonical_lab`, the symbolic links resolved by the agent, so that a course directory linking
// the shipped labs and the labs themselves are one lab whatever the path the student picked),
// else the lab name of the row (the rows of an agent older than the key: a Watch row carries
// `lab_name` in the @ form, a row of the archives table `lab` in the / form).  Pure (no
// document): tests/test_web_templates.py runs it under node or bun.

export function labKey(row) {
  if (!row) {
    return '';
  }
  return row.canonical_lab || row.lab_name || row.lab || '';
}
