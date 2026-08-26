// The "this panel's data failed to load" state (#1966).
//
// Deliberately built from the empty-state primitives (.empty-state and its
// children) rather than new CSS: a failure should read as the sibling of
// the empty state it was previously indistinguishable from, not as a new
// design language. The icon is the warning triangle against EmptyStateBlock's
// magnifier -- same frame, different news.
//
// role="alert" because the failure usually arrives long after mount: a
// skeleton was announced, and without live-region semantics the operator
// using a screen reader is never told it became an error.
export function ErrorStateBlock({
  title,
  hint,
  onRetry,
}: {
  title: string
  hint?: string
  onRetry?: () => void
}) {
  return (
    <div className="empty-state" role="alert">
      <div>
        <div className="empty-state__icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
        </div>
        <div className="empty-state__title">{title}</div>
        {hint ? <p className="empty-state__hint">{hint}</p> : null}
        {onRetry ? (
          <button type="button" className="btn btn-ghost btn-sm" onClick={onRetry}>
            Retry
          </button>
        ) : null}
      </div>
    </div>
  )
}
