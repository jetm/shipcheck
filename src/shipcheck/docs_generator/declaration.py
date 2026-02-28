"""EU Declaration of Conformity generator.

Renders the regulator-facing Declaration of Conformity required by
Article 28 and Annex V of Regulation (EU) 2024/2847 (Cyber Resilience
Act). Two forms are supported:

* **Full (Annex V)** - the eight mandatory fields (product identification,
  manufacturer identification, sole-responsibility statement, object of
  declaration, conformity statement, harmonised standards, notified
  body, additional information).
* **Simplified (Annex VI)** - the fixed one-sentence declaration with
  ``[manufacturer]`` and ``[type]`` substituted from
  :class:`shipcheck.product.ProductConfig`.

The §6 harmonised-standards field is always rendered as the verbatim
placeholder ``[TO BE FILLED BY MANUFACTURER: list applicable harmonised
standards]`` because Commission mandate M/596 is still in progress and
no CRA harmonised standards have been published yet (design decision
"No harmonised-standards logic yet" in proposal.md).

Templates live under :mod:`shipcheck.templates` (design Decision 6).
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader

if TYPE_CHECKING:
    from shipcheck.product import ProductConfig

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"

# Verbatim placeholder required by spec task 9.2: the §6
# harmonised-standards field must render this string exactly because
# CRA harmonised standards are not yet published (EU mandate M/596 is
# pending at time of writing).
HARMONISED_PLACEHOLDER = "[TO BE FILLED BY MANUFACTURER: list applicable harmonised standards]"

# Default URL placeholder for the simplified (Annex VI) form. Annex VI
# requires the simplified declaration to point at the full DoC; the
# vendor fills the real URL when publishing.
_DEFAULT_FULL_DECLARATION_URL = (
    "[TO BE FILLED BY MANUFACTURER: URL to the full EU Declaration of Conformity]"
)


def _require_manufacturer_address(product: ProductConfig) -> None:
    """Guard against manually constructed ``ProductConfig`` with empty address.

    ``load_product_config`` rejects a missing ``manufacturer.address``
    upstream, but the generator is also a public entry point. If a
    caller builds a :class:`ProductConfig` by hand with an empty string
    we still fail loudly, naming the field in the dotted-path form so
    the error surface matches the loader's.
    """
    if not product.manufacturer_address or not product.manufacturer_address.strip():
        raise ValueError("missing required field: manufacturer.address")


def generate_declaration(
    product: ProductConfig,
    out_path: Path,
    simplified: bool = False,
) -> None:
    """Render an EU Declaration of Conformity to ``out_path``.

    Args:
        product: Product identity and manufacturer details loaded from
            ``product.yaml``.
        out_path: Destination path for the rendered markdown document.
        simplified: When ``True``, emit the Annex VI simplified form;
            otherwise emit the full Annex V form (default).

    Raises:
        ValueError: When ``product.manufacturer_address`` is empty. The
            message names ``manufacturer.address`` so callers can locate
            the field in the source YAML. Normally rejected upstream by
            :func:`shipcheck.product.load_product_config`; the generator
            re-checks to cover the hand-constructed ``ProductConfig``
            case.
    """
    _require_manufacturer_address(product)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )

    template_name = "declaration_simplified.md.j2" if simplified else "declaration_full.md.j2"
    template = env.get_template(template_name)

    rendered = template.render(
        product=product,
        date_of_issue=dt.date.today().isoformat(),
        harmonised_placeholder=HARMONISED_PLACEHOLDER,
        full_declaration_url=_DEFAULT_FULL_DECLARATION_URL,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
