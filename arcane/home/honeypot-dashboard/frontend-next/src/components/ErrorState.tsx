// The "this panel's data failed to load" state (#1966).
//
// A failure should read as the sibling of the empty state it was previously
// indistinguishable from. The icon is the warning triangle against
// EmptyStateBlock's magnifier -- same frame, different news.
//
// role="alert" because the failure usually arrives long after mount: a
// skeleton was announced, and without live-region semantics the operator
// using a screen reader is never told it became an error.
import { Button } from './ui/button'
import { Card, CardDescription, CardTitle } from './ui/card'
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
    <Card className="grid place-items-center px-5 py-6 text-center" role="alert">
      <div>
        <div className="text-muted-foreground opacity-60 [&_svg]:size-[26px]" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
        </div>
        <CardTitle className="heading-serif mb-0.5 mt-2 text-[17px] font-medium">{title}</CardTitle>
        {hint ? <CardDescription className="mx-auto max-w-[420px] text-[12.5px]">{hint}</CardDescription> : null}
        {onRetry ? (
          <Button variant="ghost" size="sm" type="button" onClick={onRetry}>
            Retry
          </Button>
        ) : null}
      </div>
    </Card>
  )
}
