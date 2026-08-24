// The theme picker (#1758).
//
// Replaces a row of 11px dots. A dot was an adequate preview when a "theme"
// was an accent swap; since Xore/theme#104 a theme owns the ground, the
// sidebar, the surface ramp, the borders and the whole text ramp, and the
// accent is the least of what changes. A dot would show the one part that
// matters least.
//
// Each tile is a small composition -- ground, sidebar band, card surface,
// border, a line of text, an accent element -- rendered by scoping the
// theme's own attributes onto the tile itself. That is not a stylistic
// preference: it means the preview is the real tokens rather than a
// hand-maintained copy that can be, and was, wrong.
//
// Tiles follow the mode the operator is actually in, so what is shown is what
// they will get.
import { THEMES } from '../lib/themes'
import { useAppearanceKey, getThemeMode, getThemeName, applyPalette } from '../lib/prefs'

function Tile({ id }: { id: string }) {
  // `system` means "no data-theme attribute", which lets color-scheme resolve
  // from the OS -- exactly what the page itself does, so the tile matches.
  const mode = getThemeMode()
  const modeAttr = mode === 'system' ? undefined : mode
  return (
    <span className="hp-theme-tile__art" data-hp-theme={id} data-theme={modeAttr} aria-hidden="true">
      <span className="hp-theme-tile__sidebar" />
      <span className="hp-theme-tile__body">
        <span className="hp-theme-tile__line hp-theme-tile__line--wide" />
        <span className="hp-theme-tile__line" />
        <span className="hp-theme-tile__accent" />
      </span>
    </span>
  )
}

export function ThemeGallery() {
  // Re-render when either axis moves: picking a theme must restyle the tile
  // borders, and switching mode must repaint every tile to the variant the
  // operator would now get.
  useAppearanceKey()
  const current = getThemeName()

  return (
    <div className="hp-theme-gallery" role="radiogroup" aria-label="Theme">
      {THEMES.map((theme) => {
        const selected = theme.id === current
        return (
          <button
            key={theme.id}
            type="button"
            role="radio"
            aria-checked={selected}
            className="hp-theme-tile"
            data-value={theme.id}
            onClick={() => applyPalette(theme.id)}
          >
            <Tile id={theme.id} />
            <span className="hp-theme-tile__label">{theme.label}</span>
            <span className="hp-theme-tile__desc">{theme.description}</span>
          </button>
        )
      })}
    </div>
  )
}
