"""Test package defaults.

The template suite exercises the declarative probe engine through its reference
conformance runtime (``runtime="reference"``) because CI has no target Pod.
Production code refuses that runtime unless this variable is explicitly set, so
there is no silent host fallback.  Tests that verify the refusal clear the
variable locally.
"""

import os

os.environ.setdefault("INKBLADE_ALLOW_REFERENCE_PROBE", "1")
