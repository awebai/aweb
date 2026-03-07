import React, { useCallback } from "react"
import { Link } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { useApi } from "../hooks/useApi"
import {
  Activity,
  GitBranch,
  AlertTriangle,
  Users,
  User,
  Wifi,
  WifiOff,
  RefreshCw,
  Trash2,
} from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card"
import { Badge } from "../components/ui/badge"
import { Button } from "../components/ui/button"
import { Separator } from "../components/ui/separator"
import { Tooltip, TooltipTrigger, TooltipContent } from "../components/ui/tooltip"
import { type ApiClient, type StatusResponse, type WorkspacePresence } from "../lib/api"
import { useSSE, type SSEEvent } from "../hooks/useSSE"
import { useStore } from "../hooks/useStore"
import { cn, formatRelativeTime, formatEventDescription } from "../lib/utils"

function StatCard({
  title,
  value,
  icon: Icon,
  variant = "default",
  to,
}: {
  title: string
  value: number | string
  icon: React.ComponentType<{ className?: string }>
  variant?: "default" | "warning" | "success"
  to?: string
}) {
  const content = (
    <CardContent className="p-3 sm:p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-muted-foreground uppercase tracking-wide">
            {title}
          </p>
          <p
            className={cn(
              "text-2xl font-bold mt-1",
              variant === "warning" && "text-warning",
              variant === "success" && "text-success"
            )}
          >
            {value}
          </p>
        </div>
        <div
          className={cn(
            "h-10 w-10 rounded flex items-center justify-center",
            variant === "default" && "bg-secondary",
            variant === "warning" && "bg-warning/10 text-warning",
            variant === "success" && "bg-success/10 text-success"
          )}
        >
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </CardContent>
  )

  if (to) {
    return (
      <Link to={to} className="block">
        <Card className="transition-colors hover:bg-secondary/50 cursor-pointer">
          {content}
        </Card>
      </Link>
    )
  }

  return <Card>{content}</Card>
}

function WorkspaceRow({
  workspace,
  workspaceInfo,
  showHumanName,
  currentProjectSlug,
}: {
  workspace: StatusResponse["agents"][0]
  workspaceInfo?: WorkspacePresence
  showHumanName: boolean
  currentProjectSlug?: string
}) {
  const statusColors: Record<string, string> = {
    active: "bg-success",
    idle: "bg-muted-foreground",
    working: "bg-accent",
    unknown: "bg-muted-foreground",
  }

  const humanName = workspace.human_name ?? workspaceInfo?.human_name
  const repo = workspace.canonical_origin ?? workspaceInfo?.repo
  const branch = workspace.current_branch ?? workspaceInfo?.branch

  // Build the metadata items for line 2
  const metaItems: Array<{ key: string; node: React.ReactNode }> = []
  if (workspace.role) {
    metaItems.push({ key: "role", node: <span className="italic shrink-0">{workspace.role}</span> })
  } else if (workspace.program) {
    metaItems.push({ key: "program", node: <span className="shrink-0">{workspace.program}</span> })
  }
  if (showHumanName && humanName) {
    const humanSpan = (
      <span className="flex items-center gap-1 shrink-0">
        <User className="h-3 w-3" />
        {humanName}
      </span>
    )
    if (workspace.timezone) {
      metaItems.push({
        key: "human",
        node: (
          <Tooltip delayDuration={300}>
            <TooltipTrigger asChild>{humanSpan}</TooltipTrigger>
            <TooltipContent side="bottom">{workspace.timezone}</TooltipContent>
          </Tooltip>
        ),
      })
    } else {
      metaItems.push({ key: "human", node: humanSpan })
    }
  }
  if (repo) {
    const repoLabel = branch ? `${repo}:${branch}` : repo
    metaItems.push({
      key: "repo",
      node: (
        <span className="flex items-center gap-1 min-w-0">
          <GitBranch className="h-3 w-3 shrink-0" />
          <span className="truncate">{repoLabel}</span>
        </span>
      ),
    })
  }

  return (
    <div className="flex items-center justify-between gap-4 py-3 border-b last:border-0">
      <div className="flex items-center gap-3 min-w-0 flex-1">
        <div
          className={cn(
            "h-2 w-2 rounded-full shrink-0",
            statusColors[workspace.status] || statusColors.unknown
          )}
        />
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="font-medium text-sm whitespace-nowrap">{workspace.alias}</p>
            {workspaceInfo?.project_slug && workspaceInfo.project_slug !== currentProjectSlug && (
              <span className="px-1.5 py-0.5 bg-muted text-muted-foreground rounded text-xs">
                {workspaceInfo.project_slug}
              </span>
            )}
          </div>
          {metaItems.length > 0 && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground min-w-0">
              {metaItems.map(({ key, node }, i) => (
                <React.Fragment key={key}>
                  {i > 0 && <span className="shrink-0">·</span>}
                  {node}
                </React.Fragment>
              ))}
            </div>
          )}
        </div>
      </div>
      <div className="flex items-center gap-4 text-sm shrink-0">
        {workspace.current_issue && (
          <Badge variant="outline" className="font-mono text-xs whitespace-nowrap">
            {workspace.current_issue}
          </Badge>
        )}
      </div>
    </div>
  )
}

function EventFeed({ events, currentProjectSlug }: { events: SSEEvent[]; currentProjectSlug?: string }) {
  if (events.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground text-sm">
        No events yet. Activity will appear here in real-time.
      </div>
    )
  }

  const eventTypeColors: Record<string, string> = {
    "bead.claimed": "text-accent",
    "bead.unclaimed": "text-muted-foreground",
    "bead.status_changed": "text-primary",
    "message.delivered": "text-info",
    "message.acknowledged": "text-info",
    "chat.message_sent": "text-info",
    "escalation.created": "text-warning",
    "escalation.responded": "text-success",
    "reservation.acquired": "text-muted-foreground",
    "reservation.released": "text-muted-foreground",
    "reservation.renewed": "text-muted-foreground",
  }

  return (
    <div className="space-y-2 max-h-[300px] overflow-y-auto">
      {events.map((event, i) => (
        <div
          key={`${event.timestamp}-${i}`}
          className="flex items-start gap-2 text-xs py-1.5 border-b border-dashed last:border-0"
        >
          <Tooltip delayDuration={300}>
            <TooltipTrigger asChild>
              <span className="text-muted-foreground font-mono whitespace-nowrap tabular-nums w-[4.5rem] text-right shrink-0">
                {formatRelativeTime(event.timestamp)}
              </span>
            </TooltipTrigger>
            <TooltipContent side="bottom">
              {new Date(event.timestamp).toLocaleString()}
            </TooltipContent>
          </Tooltip>
          {typeof event.project_slug === "string" && event.project_slug && event.project_slug !== currentProjectSlug && (
            <span className="px-1 py-0.5 bg-muted text-muted-foreground rounded text-[10px] shrink-0">
              {event.project_slug}
            </span>
          )}
          <span className={cn("font-medium min-w-0", eventTypeColors[event.type] || "")}>
            {formatEventDescription(event)}
          </span>
        </div>
      ))}
    </div>
  )
}

function ScopeLabel({ workspace }: { workspace: StatusResponse["workspace"] }) {
  if (workspace.workspace_id) {
    return <span className="font-mono">{workspace.workspace_id}</span>
  }
  if (workspace.repo) {
    return <span>Repo: <span className="font-mono">{workspace.repo}</span> ({workspace.workspace_count} workspaces)</span>
  }
  if (workspace.project_slug) {
    return <span>Project: <span className="font-mono">{workspace.project_slug}</span> ({workspace.workspace_count} workspaces)</span>
  }
  return <span>All workspaces</span>
}

export function StatusPage() {
  const api = useApi<ApiClient>()
  const apiBasePath = useStore((s) => s.apiBasePath)
  const repoFilter = useStore((s) => s.repoFilter)
  const ownerFilter = useStore((s) => s.ownerFilter)
  const events = useStore((s) => s.events)
  const clearEvents = useStore((s) => s.clearEvents)
  const addEvent = useStore((s) => s.addEvent)

  const filters = repoFilter ? { repo: repoFilter } : undefined

  // Fetch status - always enabled, no workspace required
  const {
    data: status,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ["status", filters],
    queryFn: () => api.getStatus(filters),
    refetchInterval: 30000,
  })

  // Fetch workspaces to get project_slug and repo info for each agent
  const { data: workspacesData } = useQuery({
    queryKey: ["workspaces", repoFilter, ownerFilter],
    queryFn: () => api.listWorkspaces({
      repo: repoFilter || undefined,
      humanName: ownerFilter || undefined,
    }),
    staleTime: 60000,
  })

  // Create lookup map by workspace_id (alias is not unique across projects)
  const workspaceById = new Map<string, WorkspacePresence>()
  workspacesData?.workspaces?.forEach((ws) => {
    workspaceById.set(ws.workspace_id, ws)
  })

  // Memoize SSE event handler to prevent reconnection on every render
  const handleSSEEvent = useCallback(
    (event: SSEEvent) => {
      addEvent(event)
      refetch()
    },
    [addEvent, refetch]
  )

  // SSE connection - always enabled, streams all events when no filter
  // Priority order: repo > project (matching the REST API filters)
  // humanName can be combined with any filter level
  const { connected } = useSSE({
    basePath: apiBasePath,
    repo: repoFilter || undefined,
    humanName: ownerFilter || undefined,
    enabled: true,
    onEvent: handleSSEEvent,
  })

  return (
    <div className="space-y-4 sm:space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Status</h1>
          {status && (
            <p className="text-sm text-muted-foreground">
              <ScopeLabel workspace={status.workspace} />
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-sm">
            {connected ? (
              <>
                <Wifi className="h-4 w-4 text-success" />
                <span className="text-success">Live</span>
              </>
            ) : (
              <>
                <WifiOff className="h-4 w-4 text-muted-foreground" />
                <span className="text-muted-foreground">Polling</span>
              </>
            )}
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isLoading}
          >
            <RefreshCw className={cn("h-4 w-4", isLoading && "animate-spin")} />
          </Button>
        </div>
      </div>

      {error ? (
        <Card className="border-destructive">
          <CardContent className="p-4">
            <p className="text-sm text-destructive">
              Failed to load status: {(error as Error).message}
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Urgent items and stats */}
          {(() => {
            const conflictCount = status?.conflicts?.length ?? 0
            const hasUrgentItems = (status?.escalations_pending ?? 0) > 0 || conflictCount > 0

            return (
              <>
                {/* Urgent Items Alert - shown when escalations or conflicts exist */}
                {hasUrgentItems && (
                  <Card className="border-warning bg-warning/5">
                    <CardContent className="p-3 sm:p-4">
                      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                        <div className="flex items-center gap-3 flex-1">
                          <AlertTriangle className="h-5 w-5 text-warning shrink-0" />
                          <div>
                            <p className="font-medium text-warning">Attention Required</p>
                            <p className="text-sm text-muted-foreground">
                              {status?.escalations_pending ?? 0} pending escalation{(status?.escalations_pending ?? 0) !== 1 ? 's' : ''}
                              {conflictCount > 0 && (
                                <>, {conflictCount} claim conflict{conflictCount !== 1 ? 's' : ''}</>
                              )}
                            </p>
                          </div>
                        </div>
                        <div className="flex gap-2">
                          {(status?.escalations_pending ?? 0) > 0 && (
                            <Link to="escalations">
                              <Button variant="outline" size="sm">View Escalations</Button>
                            </Link>
                          )}
                          {conflictCount > 0 && (
                            <Link to="claims">
                              <Button variant="outline" size="sm">View Conflicts</Button>
                            </Link>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Stats Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4">
                  <StatCard
                    title="Pending Escalations"
                    value={status?.escalations_pending ?? 0}
                    icon={AlertTriangle}
                    variant={(status?.escalations_pending ?? 0) > 0 ? "warning" : "default"}
                    to="escalations"
                  />
                  <StatCard
                    title="Claim Conflicts"
                    value={conflictCount}
                    icon={AlertTriangle}
                    variant={conflictCount > 0 ? "warning" : "default"}
                    to="claims"
                  />
                  <StatCard
                    title="Active Claims"
                    value={status?.claims.length ?? 0}
                    icon={GitBranch}
                    to="claims"
                  />
                </div>
              </>
            )
          })()}

          <div className="grid md:grid-cols-2 gap-4 sm:gap-6">
            {/* Workspaces */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Users className="h-4 w-4" />
                  Active Workspaces
                </CardTitle>
              </CardHeader>
              <CardContent>
                {(() => {
                  // Filter agents based on active filters
                  const hasFilters = repoFilter || ownerFilter
                  const filteredAgents = hasFilters
                    ? (status?.agents ?? []).filter(agent => workspaceById.has(agent.workspace_id))
                    : (status?.agents ?? [])

                  if (filteredAgents.length === 0) {
                    return (
                      <p className="text-sm text-muted-foreground text-center py-4">
                        No workspaces connected
                      </p>
                    )
                  }
                  return (
                    <div>
                      {filteredAgents.map((workspace) => (
                        <WorkspaceRow
                          key={workspace.workspace_id}
                          workspace={workspace}
                          workspaceInfo={workspaceById.get(workspace.workspace_id)}
                          showHumanName={!ownerFilter}
                          currentProjectSlug={status?.workspace.project_slug}
                        />
                      ))}
                    </div>
                  )
                })()}
              </CardContent>
            </Card>

            {/* Event Feed */}
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Activity className="h-4 w-4" />
                    Event Feed
                    {events.length > 0 && (
                      <Badge variant="secondary" className="text-xs">
                        {events.length}
                      </Badge>
                    )}
                    {connected && (
                      <span className="inline-flex h-2 w-2 rounded-full bg-success animate-pulse"></span>
                    )}
                  </CardTitle>
                  {events.length > 0 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={clearEvents}
                      className="h-7 px-2 text-muted-foreground hover:text-destructive"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </div>
              </CardHeader>
              <Separator />
              <CardContent className="pt-3">
                <EventFeed events={events} currentProjectSlug={status?.workspace.project_slug} />
              </CardContent>
            </Card>
          </div>
        </>
      )}
    </div>
  )
}
