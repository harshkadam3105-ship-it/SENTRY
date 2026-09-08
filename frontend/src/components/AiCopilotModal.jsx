import { useState, useRef, useEffect } from 'react'
import { askAiCopilot } from '../api/incidents'

/**
 * AiCopilotModal — Interactive Real-Time AI Security Analyst Assistant.
 * Accessible globally via floating trigger button or Cmd+K.
 * Enterprise SOC styling with monospace prompts, clean code blocks, and no excessive glow.
 */

export default function AiCopilotModal({ currentIncident = null }) {
  const [isOpen, setIsOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [copiedIdx, setCopiedIdx] = useState(null)
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: "Security Analyst Assistant initialized. Ingesting sliding window telemetry, Isolation Forest anomaly weights, and correlation graphs. Ready for operational inquiry.",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ])

  const chatEndRef = useRef(null)
  const inputRef = useRef(null)

  // Keyboard shortcut: Cmd+K or Ctrl+K
  useEffect(() => {
    function handleKeyDown(e) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setIsOpen(prev => !prev)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  // Auto-scroll
  useEffect(() => {
    if (isOpen) {
      chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
      setTimeout(() => inputRef.current?.focus(), 120)
    }
  }, [messages, isOpen])

  async function handleSend(textToSend) {
    const text = textToSend || query
    if (!text.trim() || loading) return

    const userMsg = {
      role: 'user',
      text: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }

    setMessages(prev => [...prev, userMsg])
    setQuery('')
    setLoading(true)

    try {
      const res = await askAiCopilot(text, { incident: currentIncident })
      const aiMsg = {
        role: 'assistant',
        text: res.response || "Analysis complete. Threat parameters evaluated against rule engine.",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }
      setMessages(prev => [...prev, aiMsg])
    } catch {
      const errMsg = {
        role: 'assistant',
        text: "Inference Error: Failed to contact backend AI reasoning layer. Verify backend connectivity.",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }
      setMessages(prev => [...prev, errMsg])
    } finally {
      setLoading(false)
    }
  }

  function copyToClipboard(text, idx) {
    navigator.clipboard.writeText(text)
    setCopiedIdx(idx)
    setTimeout(() => setCopiedIdx(null), 2000)
  }

  return (
    <>
      {/* Floating Global Trigger Button */}
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-5 right-5 z-40 px-3.5 py-2 rounded bg-slate-900 hover:bg-slate-850 text-slate-200 border border-slate-700 hover:border-slate-600 shadow-xl transition-colors flex items-center gap-2 text-xs font-mono cursor-pointer"
        title="Open Security Copilot (Cmd+K)"
      >
        <span className="w-2 h-2 rounded-full bg-emerald-400" />
        <span className="font-semibold">Security Copilot</span>
        <span className="text-[10px] px-1 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400">
          ⌘K
        </span>
      </button>

      {/* Modal / Slide-Out Drawer */}
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-end p-3 sm:p-5 bg-black/70 backdrop-blur-xs">
          <div
            className="w-full max-w-xl h-[88vh] soc-panel shadow-2xl flex flex-col overflow-hidden border border-slate-750"
            onClick={e => e.stopPropagation()}
          >
            {/* Header */}
            <div className="px-4 py-3 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="p-1 rounded bg-slate-850 border border-slate-800 text-slate-300">
                  <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="4 17 10 11 4 5" />
                    <line x1="12" y1="19" x2="20" y2="19" />
                  </svg>
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                      Security Analyst Copilot
                    </h3>
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-emerald-950/50 text-emerald-400 border border-emerald-500/30">
                      Online
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-500 font-mono">
                    {currentIncident
                      ? `Context: ${currentIncident.incident_id} (${currentIncident.host})`
                      : 'Context: Live Telemetry Window'}
                  </p>
                </div>
              </div>

              <button
                onClick={() => setIsOpen(false)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            {/* Quick Action Chips */}
            <div className="px-3 py-2 bg-slate-900/50 border-b border-slate-800 flex gap-1.5 overflow-x-auto text-[11px] font-mono">
              <button
                onClick={() => handleSend("What is the attack blast radius?")}
                className="px-2.5 py-1 rounded bg-slate-850 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-750 transition-colors shrink-0"
              >
                Blast Radius
              </button>
              <button
                onClick={() => handleSend("Predict the attacker's next likely move.")}
                className="px-2.5 py-1 rounded bg-slate-850 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-750 transition-colors shrink-0"
              >
                Predict Move
              </button>
              <button
                onClick={() => handleSend("Generate a PowerShell containment script.")}
                className="px-2.5 py-1 rounded bg-slate-850 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-750 transition-colors shrink-0"
              >
                Containment Script
              </button>
              <button
                onClick={() => handleSend("Explain the root-cause anomaly features.")}
                className="px-2.5 py-1 rounded bg-slate-850 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-750 transition-colors shrink-0"
              >
                Root Cause
              </button>
            </div>

            {/* Messages Thread */}
            <div className="flex-1 p-4 overflow-y-auto space-y-3 font-sans text-xs">
              {messages.map((m, idx) => (
                <div
                  key={idx}
                  className={`flex flex-col ${m.role === 'user' ? 'items-end' : 'items-start'}`}
                >
                  <div className="flex items-center gap-1.5 text-[10px] text-slate-500 font-mono mb-1">
                    <span>{m.role === 'user' ? 'Analyst' : 'Copilot Engine'}</span>
                    <span>•</span>
                    <span>{m.timestamp}</span>
                  </div>

                  <div
                    className={`p-3 rounded max-w-[90%] leading-relaxed ${
                      m.role === 'user'
                        ? 'bg-slate-800 text-slate-100 border border-slate-700 font-mono'
                        : 'soc-panel-subtle text-slate-200 border border-slate-800'
                    }`}
                  >
                    <div className="whitespace-pre-wrap">{m.text}</div>

                    {m.role === 'assistant' && m.text.includes('```') && (
                      <div className="mt-2 pt-2 border-t border-slate-800 flex justify-end">
                        <button
                          onClick={() => copyToClipboard(m.text, idx)}
                          className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 hover:bg-slate-850 text-slate-400 hover:text-white border border-slate-750"
                        >
                          {copiedIdx === idx ? 'Copied' : 'Copy Script'}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))}

              {loading && (
                <div className="flex items-center gap-2 text-slate-500 font-mono text-[11px] p-2">
                  <span className="w-2 h-2 rounded-full bg-slate-400 animate-ping" />
                  <span>Evaluating correlation vectors & ML attribution…</span>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            {/* Query Input */}
            <form
              onSubmit={e => {
                e.preventDefault()
                handleSend()
              }}
              className="p-3 border-t border-slate-800 bg-slate-900/90 flex gap-2"
            >
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Ask technical question or generate zero-trust script..."
                className="flex-1 px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:border-slate-600 focus:outline-none"
              />
              <button
                type="submit"
                disabled={loading || !query.trim()}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-750 text-slate-200 text-xs font-mono font-medium border border-slate-700 transition-colors disabled:opacity-50"
              >
                Send
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  )
}
