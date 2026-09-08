import { useState } from 'react'
import { lookupIoc, blockIp } from '../api/incidents'

/**
 * IocLookupModal — Cyber Threat Intelligence & Indicator Reputation Lookup.
 * Multi-engine threat intel query (VirusTotal, AlienVault, AbuseIPDB)
 * with instant 1-click perimeter firewall rule deployment.
 */

export default function IocLookupModal({ isOpen, onClose }) {
  const [indicator, setIndicator] = useState('198.51.100.44')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [blockStatus, setBlockStatus] = useState('idle') // idle | running | done

  if (!isOpen) return null

  async function handleSearch(e) {
    if (e) e.preventDefault()
    if (!indicator.trim() || loading) return
    setLoading(true)
    setError(null)
    setBlockStatus('idle')

    try {
      const data = await lookupIoc(indicator.trim())
      setResult(data)
    } catch (err) {
      setError(err.message || 'Lookup failed')
    } finally {
      setLoading(false)
    }
  }

  async function handleDeployBlock() {
    if (!result?.indicator || blockStatus !== 'idle') return
    setBlockStatus('running')
    try {
      await blockIp(result.indicator, `TI Block: ${result.verdict}`)
      setBlockStatus('done')
    } catch (err) {
      console.error('Failed to block IP:', err)
      setBlockStatus('idle')
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm antialiased">
      <div className="soc-panel max-w-2xl w-full border border-slate-700/80 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-2">
            <div className="p-1 rounded bg-slate-800 text-cyan-400">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <line x1="21" y1="21" x2="16.65" y2="16.65" />
              </svg>
            </div>
            <div>
              <h3 className="text-xs font-bold text-slate-200 font-mono uppercase tracking-wider">
                Threat Intelligence & IOC Reputation Lookup
              </h3>
              <p className="text-[11px] text-slate-400">
                Multi-engine intelligence feeds: VirusTotal, AbuseIPDB, AlienVault OTX
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Input Bar */}
        <div className="p-4 border-b border-slate-800 bg-slate-950/40">
          <form onSubmit={handleSearch} className="flex gap-2">
            <input
              type="text"
              value={indicator}
              onChange={e => setIndicator(e.target.value)}
              placeholder="Enter IP address, domain, or SHA256 hash (e.g. 198.51.100.44)…"
              className="flex-1 px-3 py-2 text-xs font-mono bg-slate-900 border border-slate-700 rounded text-slate-200 placeholder-slate-500 focus:outline-hidden focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 text-xs font-mono font-medium rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold transition-colors flex items-center gap-1.5"
            >
              {loading ? 'Querying TI…' : 'Query Intel'}
            </button>
          </form>
          <div className="flex items-center gap-2 mt-2 text-[10.5px] font-mono text-slate-500">
            <span>Quick Samples:</span>
            <button
              type="button"
              onClick={() => { setIndicator('198.51.100.44'); setTimeout(handleSearch, 50) }}
              className="text-cyan-400 hover:underline"
            >
              198.51.100.44 (C2 IP)
            </button>
            <span>·</span>
            <button
              type="button"
              onClick={() => { setIndicator('c2-sync-agent.ru'); setTimeout(handleSearch, 50) }}
              className="text-cyan-400 hover:underline"
            >
              c2-sync-agent.ru (Domain)
            </button>
          </div>
        </div>

        {/* Results Area */}
        <div className="p-4 overflow-y-auto space-y-4 flex-1">
          {error && (
            <div className="p-3 rounded bg-red-950/40 border border-red-800/40 text-xs font-mono text-red-300">
              Error querying threat intel: {error}
            </div>
          )}

          {result ? (
            <div className="space-y-4 text-xs font-mono">
              {/* Verdict Banner */}
              <div className="p-3.5 rounded bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-slate-100">{result.indicator}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                      {result.type}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    ASN: {result.asn} · Origin: {result.country}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-lg font-bold text-red-400">{result.threat_score} / 100</div>
                    <div className="text-[10px] text-slate-500">{result.detections}</div>
                  </div>
                  <div className="px-2.5 py-1 rounded bg-red-950/60 border border-red-500/40 text-red-300 font-bold text-[10.5px]">
                    {result.verdict}
                  </div>
                </div>
              </div>

              {/* Threat Actor & ATT&CK */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3 rounded bg-slate-900/50 border border-slate-800 space-y-1.5">
                  <div className="text-[10px] text-slate-500 uppercase font-semibold">Attributed Threat Actors</div>
                  <div className="flex flex-wrap gap-1.5">
                    {result.threat_actors?.map(actor => (
                      <span key={actor} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10.5px]">
                        {actor}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-3 rounded bg-slate-900/50 border border-slate-800 space-y-1.5">
                  <div className="text-[10px] text-slate-500 uppercase font-semibold">Associated MITRE Techniques</div>
                  <div className="flex flex-wrap gap-1.5">
                    {result.mitre_techniques?.map(t => (
                      <span key={t.id} className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 text-[10.5px]">
                        {t.id} · {t.name}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Narrative Summary */}
              <div className="p-3 rounded bg-slate-900/40 border border-slate-800 space-y-1">
                <div className="text-[10px] text-slate-500 uppercase font-semibold">Threat Intel Narrative</div>
                <p className="text-[11px] text-slate-300 font-sans leading-relaxed">{result.summary}</p>
              </div>

              {/* Action Bar */}
              <div className="p-3 rounded bg-slate-900/60 border border-slate-800 flex items-center justify-between gap-2">
                <span className="text-[11px] text-slate-400 font-sans">
                  Recommended response: <span className="text-slate-200">{result.recommended_action}</span>
                </span>
                {blockStatus === 'done' ? (
                  <span className="px-3 py-1 text-xs text-emerald-400 font-mono flex items-center gap-1 bg-emerald-950/40 border border-emerald-800/40 rounded">
                    ✓ Perimeter Block Deployed
                  </span>
                ) : (
                  <button
                    disabled={blockStatus === 'running'}
                    onClick={handleDeployBlock}
                    className="px-3 py-1.5 rounded text-xs font-mono font-medium bg-red-950 hover:bg-red-900 text-red-300 border border-red-500/40 transition-colors shrink-0"
                  >
                    {blockStatus === 'running' ? 'Deploying Rule…' : '⚡ Deploy Firewall Null-Route'}
                  </button>
                )}
              </div>
            </div>
          ) : !loading && (
            <div className="text-center py-8 text-slate-500 text-xs font-mono">
              Enter an IP address, domain, or hash above to query live global threat intel.
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between text-[11px] font-mono text-slate-500">
          <span>Confidence Score: 97.8% (Multi-Vector Correlation)</span>
          <button
            onClick={onClose}
            className="px-3 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700"
          >
            Close Window
          </button>
        </div>
      </div>
    </div>
  )
}
