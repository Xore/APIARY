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

it('keeps the responsive display heading contract for long titles', () => {
  const host = document.createElement('div')
  host.innerHTML = renderToStaticMarkup(
    <InvestigateHeader label="Investigate" title={'A very long event title '.repeat(8)} subtitle="Recorded evidence" />,
  )
  const heading = host.querySelector('h1')!
  expect(heading.classList.contains('heading-serif')).toBe(true)
  expect(heading.classList.contains('break-all')).toBe(true)
  expect(heading.classList.contains('text-[clamp(1.5rem,2.2vw,2rem)]')).toBe(true)
  expect(heading.classList.contains('leading-[1.1]')).toBe(true)
})
