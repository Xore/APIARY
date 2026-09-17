import { renderToStaticMarkup } from 'react-dom/server'
import { expect, it } from 'vitest'
import { InvestigateHeader } from './Investigate'

it('preserves heading semantics and the optional sibling action slot', () => {
  const host = document.createElement('div')
  const props = { label: 'Investigate', title: '<event>', subtitle: 'Recorded evidence' }
  host.innerHTML = renderToStaticMarkup(<InvestigateHeader {...props} chips={<a href="/events">Events</a>} />)
  expect(host.querySelectorAll('h1')).toHaveLength(1)
  expect(host.querySelector('h1')?.textContent).toBe('<event>')
  expect(host.querySelector('header')?.textContent).toContain('Recorded evidence')
  expect(host.querySelector('header')?.nextElementSibling?.querySelector('a')?.getAttribute('href')).toBe('/events')
  host.innerHTML = renderToStaticMarkup(<InvestigateHeader {...props} />)
  expect(host.children).toHaveLength(1)
})
