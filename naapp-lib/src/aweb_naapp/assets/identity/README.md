# Field identity assets

The favicon uses the incoming mark: an amber upper curve and monochrome centre
and lower strokes. Small PNG fallbacks are transparent; touch and app sizes have
a white ground. Social cards use native Archivo type at weight 850 and contain
only the product name. Authored content images are independent of these defaults.

To regenerate the PNGs from the SVG/type source, install Google Chrome, run
`npm ci` in `naapp-lib/renderer`, then `node export-identity.mjs`. An optional
absolute output path writes a 16/32/48/180 contact sheet. The exporter uses the
bundled Archivo variable font; its OFL licence is in the sibling fonts directory.
The SVG card sources retain editable text; raster exports load the bundled face.

Public chrome references `/brand/field-v1/` assets. A future artwork change must
use a new path version before serving immutable cache headers. No service or
external font provider is involved.
