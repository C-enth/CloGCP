"""Display-only location labels. Stored regions, resource IDs and fingerprints are unchanged.

Legacy GCP Compute transports record a zone as a self-link URL. Shown verbatim, that URL
reads as an invented region. Only a URL's explicit zones/regions/locations segment is used;
anything else is shown as unrecorded rather than guessed.
"""

import re

SEGMENT = re.compile(r"/(?:zones|regions|locations)/([a-z][a-z0-9-]{0,62})/?$")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}")
UNRECORDED = "unrecorded"


def display_region(value: object) -> str:
    if not isinstance(value, str) or not value:
        return UNRECORDED
    if "/" in value or ":" in value:
        match = SEGMENT.search(value)
        return match[1] if match else UNRECORDED
    return value if LABEL.fullmatch(value) else UNRECORDED
