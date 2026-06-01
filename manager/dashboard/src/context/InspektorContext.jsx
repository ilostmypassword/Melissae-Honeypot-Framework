import {
  createContext, useContext, useState, useRef, useCallback, useEffect,
} from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchInspektorReport, generateInspektorReport, sendInspektorChat } from '../api'

const STORAGE_KEY = 'melissae.inspektor.chat'

let _idSeq = 0
const nextId = () => `m${Date.now().toString(36)}-${++_idSeq}`

export const INTRO = {
  id: 'intro',
  role: 'assistant',
  kind: 'chat',
  content:
    "Hi, I'm **Inspektor**, your AI threat analyst. Ask me anything about the honeypot network, or hit **Generate report** for a full threat briefing you can export to PDF.",
}

function loadStored() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw)
    if (Array.isArray(parsed) && parsed.length > 0) return parsed
  } catch {
    /* ignore corrupted storage */
  }
  return null
}

function previewOf(markdown, max = 120) {
  const text = String(markdown || '')
    .replace(/[#>*`_|-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return text.length > max ? `${text.slice(0, max)}…` : text
}

const InspektorContext = createContext(null)

// eslint-disable-next-line react-refresh/only-export-components
export function useInspektor() {
  const ctx = useContext(InspektorContext)
  if (!ctx) throw new Error('useInspektor must be used within <InspektorProvider>')
  return ctx
}

// Holds the whole Inspektor conversation at the app root so requests keep
// running (and replies still arrive) even when the user leaves the page.
export function InspektorProvider({ children }) {
  const navigate = useNavigate()
  const [messages, setMessages] = useState(() => loadStored() || [INTRO])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [lastMeta, setLastMeta] = useState(null)
  const [unread, setUnread] = useState(0)
  const [toast, setToast] = useState(null)

  const messagesRef = useRef(messages)
  const activeRef = useRef(false)        // page mounted AND tab visible
  const seededRef = useRef(loadStored() != null)
  const toastTimer = useRef(null)

  // Keep a ref in sync so async handlers always read the latest history
  useEffect(() => { messagesRef.current = messages }, [messages])

  // Persist on every change + track the latest report for the header
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(messages))
    } catch {
      /* storage unavailable: ignore */
    }
    const lastReport = [...messages].reverse().find(m => m.kind === 'report')
    setLastMeta(lastReport?.meta || null)
  }, [messages])

  // On a brand-new conversation, seed it with the last stored briefing
  useEffect(() => {
    if (seededRef.current) return
    seededRef.current = true
    let cancelled = false
    fetchInspektorReport()
      .then(data => {
        if (cancelled || !data?.markdown) return
        setMessages(prev => [
          ...prev,
          { id: nextId(), role: 'assistant', kind: 'report', content: data.markdown, meta: data },
        ])
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [])

  // Ask for notification permission lazily, on first interaction
  const ensurePermission = useCallback(() => {
    try {
      if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission().catch(() => {})
      }
    } catch {
      /* ignore */
    }
  }, [])

  const showToast = useCallback(t => {
    setToast(t)
    if (toastTimer.current) clearTimeout(toastTimer.current)
    toastTimer.current = setTimeout(() => setToast(null), 7000)
  }, [])

  // Fire a notification when a reply arrives and the user isn't watching
  const notifyReply = useCallback((title, body) => {
    const away = typeof document !== 'undefined' && (document.hidden || !activeRef.current)
    if (!away) return
    setUnread(u => u + 1)
    showToast({ title, body })
    try {
      if ('Notification' in window && Notification.permission === 'granted') {
        const n = new Notification(title, { body, icon: '/logo.png', tag: 'inspektor' })
        n.onclick = () => { window.focus(); navigate('/inspektor'); n.close() }
      }
    } catch {
      /* ignore */
    }
  }, [showToast, navigate])

  const send = useCallback(async text => {
    const value = (text || '').trim()
    if (!value || busy) return
    ensurePermission()
    setError(null)
    const history = messagesRef.current
      .filter(m => m.role === 'user' || m.role === 'assistant')
      .map(m => ({ role: m.role, content: m.content }))
    setMessages(prev => [...prev, { id: nextId(), role: 'user', kind: 'chat', content: value }])
    setBusy(true)
    try {
      const data = await sendInspektorChat(value, history)
      const reply = data.reply || '(no answer)'
      setMessages(prev => [...prev, { id: nextId(), role: 'assistant', kind: 'chat', content: reply }])
      notifyReply('Inspektor replied', previewOf(reply))
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }, [busy, ensurePermission, notifyReply])

  const runReport = useCallback(async () => {
    if (busy) return
    ensurePermission()
    setError(null)
    setMessages(prev => [
      ...prev,
      { id: nextId(), role: 'user', kind: 'chat', content: '📋 Generate a full threat briefing' },
    ])
    setBusy(true)
    try {
      const data = await generateInspektorReport()
      setMessages(prev => [
        ...prev,
        { id: nextId(), role: 'assistant', kind: 'report', content: data.markdown, meta: data },
      ])
      notifyReply('Inspektor briefing ready', previewOf(data.markdown))
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }, [busy, ensurePermission, notifyReply])

  const clearChat = useCallback(() => {
    if (busy) return
    setMessages([INTRO])
    setError(null)
    seededRef.current = false
    try {
      localStorage.removeItem(STORAGE_KEY)
    } catch {
      /* ignore */
    }
  }, [busy])

  // Called by the page to mark the conversation as seen / focused
  const markActive = useCallback(active => {
    activeRef.current = active
    if (active) setUnread(0)
  }, [])

  const value = {
    messages, busy, error, lastMeta, unread,
    send, runReport, clearChat, markActive,
  }

  return (
    <InspektorContext.Provider value={value}>
      {children}
      {toast && (
        <button
          onClick={() => { setToast(null); navigate('/inspektor') }}
          className="fixed bottom-5 right-5 z-[60] max-w-sm text-left animate-fade-in"
        >
          <div className="glass-card border border-accent/40 shadow-lg p-3.5 flex gap-3 items-start hover:border-accent/70 transition-colors">
            <span className="flex items-center justify-center w-9 h-9 rounded-lg bg-accent/15 text-accent shrink-0">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="10.5" cy="10.5" r="6.5" />
                <path d="m20 20-4.5-4.5" />
                <path d="m8 10.5 1.8 1.8L13 9" />
              </svg>
            </span>
            <div className="min-w-0">
              <div className="text-sm font-semibold text-text-primary">{toast.title}</div>
              <div className="text-xs text-text-muted line-clamp-2 mt-0.5">{toast.body}</div>
              <div className="text-[10px] text-accent mt-1 font-semibold">Open Inspektor →</div>
            </div>
          </div>
        </button>
      )}
    </InspektorContext.Provider>
  )
}
