// The "nothing asked, so nothing noticed" half of #1975's re-auth path.
//
// sessionAwareFetch only learns a session has expired when something makes
// a request. On a backgrounded tab nothing does: useLiveInterval's tick is
// gated on `document.visibilityState === 'visible'` (#1973), and the
// browser throttles the timer underneath it anyway -- Chrome's intensive
// throttling starts around five minutes hidden, which is exactly the window
// #1563 was reported in. So a tab left open over lunch comes back with a
// session that died an hour ago, and the operator sees a normal-looking
// dashboard of stale data until they touch something.
//
// Regaining visibility is therefore its own trigger, independent of any
// timer: it fires on the return itself, which is the moment before the
// operator starts reading numbers they would otherwise have trusted.
import { useEffect } from 'react'
import { checkSessionAlive } from './reauth'

export function useSessionWatch() {
  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === 'visible') void checkSessionAlive()
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => document.removeEventListener('visibilitychange', onVisible)
  }, [])
}
