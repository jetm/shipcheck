"""Generators for CRA regulatory paperwork.

This package bundles the document generators that consume scan evidence
and a declarative ``product.yaml`` to produce the paperwork vendors must
file under Regulation (EU) 2024/2847:

* ``annex_vii`` - Annex VII technical documentation draft (task 8.2).
* ``declaration`` - Annex V (full) and Annex VI (simplified) Declaration
  of Conformity templates (task 9.2).

Consumers import entry points from the submodules directly, e.g.::

    from shipcheck.docs_generator.declaration import generate_declaration
    from shipcheck.docs_generator.annex_vii import generate_annex_vii

Submodules are not eagerly imported here so a missing sibling module
does not prevent the other from loading.
"""

from __future__ import annotations
