# ADR 011 Assessment finalisation and native Word exports

Accepted for the assessment sprint requested on 2026-10-16.

An explicit UI action freezes a run's reviewed report content into an additive local
database table. Existing imports, decisions and drafts are never rewritten by this
action. A frozen edition is immutable; later work uses a new assessment snapshot.
Provider-specific exports filter the same edition, including attack paths. Confirmation
and report approval remain separate; automatic checks never approve exploitation.

Native Word output uses bounded, literal OOXML authored with the Python standard
library, avoiding a new runtime dependency. Existing RTF endpoints remain compatible.
No imported XML, external links, macros, embedded files or remote templates are used.

Superseded 2026-10-17 (owner decision): the separate PDF output is withdrawn. Reports
are native Word (.docx) and Excel (.xlsx) only; the PDF writer, the
`/finalized.pdf` endpoint and the `approved-pdf` report kind were removed. Earlier
`approved-pdf` entries in a workspace's report history are hidden and their download
returns REPORT_FORMAT_WITHDRAWN. Synthetic reopen and render checks verify generated
Word and Excel output; native Word/Windows validation remains a separate platform gate.
