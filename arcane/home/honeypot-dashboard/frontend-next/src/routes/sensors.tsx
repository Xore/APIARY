// /sensors has no page of its own (#1904).
//
// It used to be four tabs -- three hand-written sensor readings and an
// "All sensors" roster of twenty-seven tiles. The roster was a wall to read
// before anything could be chosen, and it gave dionaea's 17.8M events the
// same visual weight as wordpot's 38.
//
// Every sensor is an entry in the sidebar rail now, and each opens its own
// page. So this route only decides which one to open: the busiest, because
// it is the one most likely to be worth looking at, and because landing on
// an empty prompt teaches nothing.
//
// The three curated readings did not go anywhere -- they are three of the
// entries, rendered by components/CuratedSensorViews on those sensors' own
// pages.
import { createFileRoute, redirect } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

type SensorSummary = { sensor: string; events: number }

const fetchCatalog = createServerFn({ method: 'GET' }).handler(
  async (): Promise<{ sensors: SensorSummary[] } | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON('/api/v1/sensors/catalog')
  },
)

export const Route = createFileRoute('/sensors')({
  beforeLoad: async () => {
    const catalog = await fetchCatalog()
    // The catalog is ordered by count, so the first entry is the busiest.
    const busiest = catalog?.sensors?.[0]?.sensor
    // No catalog means the backend is unreachable, or nothing produced an
    // event in the window. cowrie is the fallback rather than a blank page:
    // it is the highest-volume sensor on every deployment this ships to,
    // and its own page says honestly when it has nothing.
    throw redirect({ to: '/sensors/$sensor', params: { sensor: busiest ?? 'cowrie' } })
  },
})
