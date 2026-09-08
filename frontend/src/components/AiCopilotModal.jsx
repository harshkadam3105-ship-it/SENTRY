import { useState, useRef, useEffect } from 'react'
import { askAiCopilot } from '../api/incidents'

/**
 * AiCopilotModal — Interactive Real-Time AI Security Analyst Assistant
 * Accessible globally via floating trigger button or Cmd+K.
 * Generates context-aware investigations, blast radius estimates,
 * predictive next moves, and live containment scripts.
 */

export default function AiCopilotModal({ currentIncident = null }) {
  const [isOpen, setIsOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [copiedIdx, setCopiedIdx] = useState(null)
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: "👋 **Hello Analyst.** I am the **Sentry AI Defense Copilot**.\n\nI am actively analyzing in-memory telemetry, Isolation Forest anomaly vectors, and correlation graphs. How can I assist your investigation?",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }
  ])

  const chatEndRef = useRef(null)
  const inputRef = useRef(null)

  // Keyboard shortcut: Cmd+K or Ctrl+K to toggle
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

  // Auto-scroll chat to bottom
  useEffect(() => {
    if (isOpen) {
      chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
      setTimeout(() => inputRef.current?.focus(), 150)
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
        text: res.response || "Analysis complete. Threat parameters normalized.",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }
      setMessages(prev => [...prev, aiMsg])
    } catch (err) {
      const errMsg = {
        role: 'assistant',
        text: "⚠️ **AI Inference Error:** Failed to contact reasoning layer. Please verify backend connectivity.",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }
      setMessages(prev => [...prev, errMsg])
    } finally {
      setLoading(false)
    }
  }

  function handleQuickPrompt(promptText) {
    handleSend(promptText)
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
        className="fixed bottom-6 right-6 z-40 px-4 py-2.5 rounded-full bg-surface-800/90 hover:bg-surface-800 text-slate-100 border border-cyan-500/40 hover:border-cyan-400 shadow-xl shadow-cyan-500/10 hover:shadow-cyan-500/20 transition-all flex items-center gap-2.5 backdrop-blur-md group active:scale-95 cursor-pointer"
        title="Open Sentry AI Security Copilot (Cmd+K)"
      >
        <span className="relative flex h-3 w-3">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500"></span>
        </span>
        <span className="text-sm font-semibold tracking-tight text-white group-hover:text-cyan-300 transition-colors">
          Sentry AI Copilot
        </span>
        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface-700/80 border border-white/10 text-slate-400">
          ⌘K
        </span>
      </button>

      {/* Modal / Slide-Out Drawer */}
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-end p-4 sm:p-6 bg-black/60 backdrop-blur-sm animate-fade-in">
          <div
            className="w-full max-w-xl h-[85vh] bg-surface-900 border border-cyan-500/30 rounded-2xl shadow-2xl shadow-cyan-500/10 flex flex-col overflow-hidden animate-slide-in-right relative"
            onClick={e => e.stopPropagation()}
          >
            {/* Header */}
            <div className="px-5 py-4 border-b border-white/10 bg-surface-800/80 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-lg shadow-inner shadow-cyan-500/20">
                  🤖
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-white tracking-tight">Sentry AI Defense Copilot</h3>
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-semibold">
                      Online
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                    {currentIncident ? `Context: ${currentIncident.incident_id} (${currentIncident.host})` : 'Context: Fleet Telemetry Stream'}
                  </p>
                </div>
              </div>

              <button
                onClick={() => setIsOpen(false)}
                className="w-8 h-8 rounded-lg bg-surface-700/50 hover:bg-surface-700 text-slate-400 hover:text-white transition-colors flex items-center justify-center text-base"
              >
                ✕
              </button>
            </div>

            {/* Quick Action Chips */}
            <div className="px-4 py-2.5 bg-surface-800/30 border-b border-white/5 flex gap-2 overflow-x-auto text-xs no-scrollbar">
              <button
                onClick={() => handleQuickPrompt("What is the attack blast radius?")}
                className="px-2.5 py-1 rounded-lg bg-surface-700/60 hover:bg-surface-700 text-slate-300 hover:text-white border border-white/5 whitespace-nowrap transition-colors flex items-center gap-1.5 cursor-pointer text-[11px]"
              >
                <span>⚡</span> Blast Radius
              </button>
              <button
                onClick={() => handleQuickPrompt("Predict the attacker's next likely move.")}
                className="px-2.5 py-1 rounded-lg bg-surface-700/60 hover:bg-surface-700 text-slate-300 hover:text-white border border-white/5 whitespace-nowrap transition-colors flex items-center gap-1.5 cursor-pointer text-[11px]"
              >
                <span>🎯</span> Predict Next Move
              </button>
              <button
                onClick={() => handleQuickPrompt("Generate a PowerShell containment script.")}
                className="px-2.5 py-1 rounded-lg bg-surface-700/60 hover:bg-surface-700 text-slate-300 hover:text-white border border-white/5 whitespace-nowrap transition-colors flex items-center gap-1.5 cursor-pointer text-[11px]"
              >
                <span>📜</span> Remediation Script
              </button>
              <button
                onClick={() => handleQuickPrompt("Explain the root-cause anomaly features.")}
                className="px-2.5 py-1 rounded-lg bg-surface-700/60 hover:bg-surface-700 text-slate-300 hover:text-white border border-white/5 whitespace-nowrap transition-colors flex items-center gap-1.5 cursor-pointer text-[11px]"
              >
                <span>🔍</span> Root Cause
              </button>
            </div>

            {/* Messages Thread */}
            <div className="flex-1 p-4 overflow-y-auto space-y-4 font-sans text-sm">
              {messages.map((m, idx) => (
                <div
                  key={idx}
                  className={`flex flex-col ${m.role === 'user' ? 'items-end' : 'items-start'}`}
                >
                  <div className="flex items-center gap-1.5 text-[10px] text-slate-500 font-mono mb-1 px-1">
                    <span>{m.role === 'user' ? 'You' : 'Sentry AI'}</span>
                    <span>·</span>
                    <span>{m.timestamp}</span>
                  </div>

                  <div
                    className={`max-w-[90%] p-3.5 rounded-2xl leading-relaxed whitespace-pre-line text-xs ${
                      m.role === 'user'
                        ? 'bg-cyan-600 text-white rounded-br-none shadow-md shadow-cyan-600/10'
                        : 'bg-surface-800 border border-white/10 text-slate-200 rounded-bl-none shadow-md shadow-black/20'
                    }`}
                  >
                    {m.text}

                    {m.role === 'assistant' && m.text.includes('```') && (
                      <div className="mt-2 pt-2 border-t border-white/10 flex justify-end">
                        <button
                          onClick={() => copyToClipboard(m.text, idx)}
                          className="text-[10px] px-2 py-1 rounded bg-surface-700 text-slate-300 hover:text-white transition-colors"
                        >
                          {copiedIdx === idx ? '✓ Copied' : '📋 Copy Script'}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))}

              {loading && (
                <div className="flex items-center gap-2 text-xs text-cyan-400 font-mono bg-surface-800/60 p-3 rounded-xl border border-cyan-500/20 w-fit">
                  <div className="w-3 h-3 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                  <span>AI reasoning across telemetry & anomaly vectors…</span>
                </div>
              )}

              <div ref={chatEndRef} />
            </div>

            {/* Input Bar */}
            <form
              onSubmit={e => {
                e.preventDefault()
                handleSend()
              }}
              className="p-3 border-t border-white/10 bg-surface-800/60 flex items-center gap-2"
            >
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Ask Sentry AI (e.g., 'What is the blast radius?', 'Generate fix script')..."
                className="flex-1 bg-surface-900 border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors font-sans"
              />
              <button
                type="submit"
                disabled={!query.trim() || loading}
                className="px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white font-medium text-xs transition-colors flex items-center gap-1.5 cursor-pointer shadow-md shadow-cyan-600/20"
              >
                <span>Send</span>
                <span>➔</span>
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  )
}
