import { useEffect, useRef, useCallback, useState } from "react"
import type { ApiClient } from "../lib/api"
import { useApi } from "./useApi"

export interface SSEEvent {
  type: string
  workspace_id?: string
  timestamp: string
  [key: string]: unknown
}

function normalizeBasePath(basePath?: string): string {
  if (!basePath) return ""
  let normalized = basePath.trim()
  if (!normalized) return ""

  normalized = normalized.replace(/\/{2,}/g, "/")
  normalized = normalized.replace(/\/+$/, "")
  if (!normalized) return ""

  if (!normalized.startsWith("/")) {
    normalized = `/${normalized}`
  }
  if (normalized === "/") return ""
  return normalized
}

interface UseSSEOptions {
  /**
   * Prefix for the API routes (e.g. '' for standalone, '/api' for embedded).
   * When set, SSE connects to `${basePath}/v1/status/stream`.
   */
  basePath?: string
  projectSlug?: string
  repo?: string
  humanName?: string
  eventTypes?: string[]
  onEvent?: (event: SSEEvent) => void
  onError?: (error: Event) => void
  enabled?: boolean
}

export function useSSE({
  basePath,
  projectSlug,
  repo,
  humanName,
  eventTypes,
  onEvent,
  onError,
  enabled = true,
}: UseSSEOptions) {
  const api = useApi<ApiClient>()
  const abortRef = useRef<AbortController | null>(null)
  const reconnectTimerRef = useRef<number | null>(null)
  const backoffDelayRef = useRef(5000)
  const connectRef = useRef<() => void>(() => {})
  const [connected, setConnected] = useState(false)
  const [lastEvent, setLastEvent] = useState<SSEEvent | null>(null)

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimerRef.current !== null) {
      window.clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
  }, [])

  const connect = useCallback(() => {
    if (!enabled) return

    clearReconnectTimer()

    // Abort any existing connection
    if (abortRef.current) {
      abortRef.current.abort()
      abortRef.current = null
    }

    // Build URL with query params
    const params = new URLSearchParams()
    if (projectSlug) params.set("project_slug", projectSlug)
    if (repo) params.set("repo", repo)
    if (humanName) params.set("human_name", humanName)
    if (eventTypes?.length) {
      params.set("event_types", eventTypes.join(","))
    }

    const normalizedBasePath = normalizeBasePath(basePath)
    const url = `${normalizedBasePath}/v1/status/stream?${params.toString()}`

    const controller = new AbortController()
    abortRef.current = controller

    const scheduleReconnect = (error: Event) => {
      setConnected(false)
      onError?.(error)
      const delay = backoffDelayRef.current
      backoffDelayRef.current = Math.min(delay * 2, 60000)
      reconnectTimerRef.current = window.setTimeout(() => {
        if (enabled) {
          connectRef.current()
        }
      }, delay)
    }

    ;(async () => {
      try {
        const response = await fetch(url, {
          headers: api.getHeaders(),
          signal: controller.signal,
        })
        if (!response.ok || !response.body) {
          scheduleReconnect(new Event("error"))
          return
        }

        setConnected(true)
        backoffDelayRef.current = 5000

        const reader = response.body.getReader()
        const decoder = new TextDecoder("utf-8")
        let buffer = ""

        while (true) {
          const { value, done } = await reader.read()
          if (done) break
          buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n")

          // Process complete SSE frames separated by a blank line.
          while (true) {
            const idx = buffer.indexOf("\n\n")
            if (idx === -1) break
            const frame = buffer.slice(0, idx)
            buffer = buffer.slice(idx + 2)

            const dataLines = frame
              .split("\n")
              .filter((l) => l.startsWith("data:"))
              .map((l) => l.slice(5).trimStart())
            if (dataLines.length === 0) continue

            const raw = dataLines.join("\n")
            try {
              const data = JSON.parse(raw) as SSEEvent
              setLastEvent(data)
              onEvent?.(data)
            } catch (e) {
              console.error("Failed to parse SSE event:", e, raw)
            }
          }
        }
      } catch {
        if (controller.signal.aborted) return
        scheduleReconnect(new Event("error"))
      }
    })()
  }, [
    api,
    basePath,
    clearReconnectTimer,
    projectSlug,
    repo,
    humanName,
    eventTypes,
    onEvent,
    onError,
    enabled,
  ])

  const disconnect = useCallback(() => {
    clearReconnectTimer()
    if (abortRef.current) {
      abortRef.current.abort()
      abortRef.current = null
    }
    setConnected(false)
  }, [clearReconnectTimer])

  useEffect(() => {
    connectRef.current = connect
  }, [connect])

  useEffect(() => {
    connect()
    return () => disconnect()
  }, [connect, disconnect]) // Reconnect when connect changes (includes basePath and filter changes)

  return {
    connected,
    lastEvent,
    reconnect: connect,
    disconnect,
  }
}
