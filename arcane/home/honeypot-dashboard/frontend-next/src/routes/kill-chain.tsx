// Kill-chain analytics (#1224) — sankey flow, campaign timeline, ATT&CK
// coverage grid. Copy and layout mirror kill_chain.html.
import { Link, createFileRoute } from '@tanstack/react-router'
import { InvestigateHeader } from '../components/Investigate'
import { EChart } from '../components/EChart'

export const Route = createFileRoute('/kill-chain')({ component: KillChain })

function KillChain() {
  return (
    <>
      <InvestigateHeader
        label="Correlation"
        title="Kill-chain analytics"
        subtitle="Attacker progression through MITRE ATT&CK tactics (#1224), built on top of #1200/#1219's own correlation work — behavior context only, never actor attribution."
        chips={
          <>
            <Link className="chip" to="/">
              ← dashboard
            </Link>
            <Link className="chip" to="/campaigns">
              network campaigns
            </Link>
            <Link className="chip" to="/attackers">
              attacker identities
            </Link>
          </>
        }
      />
      <div className="card wide">
        <h2>Kill-chain flow</h2>
        <p className="note">
          Each attacker session (or, for sensors with no session concept, each source IP) contributes one flow unit between every
          pair of MITRE ATT&CK tactics its own traffic touched, in canonical kill-chain order — reads top to bottom.
        </p>
        <EChart kind="sankey" url="/api/chart/kill-chain-sankey" height={620} />
      </div>
      <div className="card wide">
        <h2>Campaign timeline</h2>
        <p className="note">Every current network campaign (#1199/#1219), plotted from first to last observed activity.</p>
        <EChart kind="timeline" url="/api/chart/campaign-timeline" height={420} />
      </div>
      <div className="card wide">
        <h2>ATT&CK coverage grid</h2>
        <p className="note">
          Every ATT&CK technique this deployment has evidence for, grouped by tactic. Darker cells mean more observed events, not
          more severe activity.
        </p>
        <EChart kind="heatmap" url="/api/chart/attck-coverage" height={420} />
      </div>
    </>
  )
}
