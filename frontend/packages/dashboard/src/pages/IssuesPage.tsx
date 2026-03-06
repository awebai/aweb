import { useState, useMemo, useCallback, useEffect, useRef } from "react"
import { useQuery } from "@tanstack/react-query"
import { useSearchParams } from "react-router-dom"
import { useApi } from "../hooks/useApi"
import {
  ListTodo,
  RefreshCw,
  User,
  ChevronRight,
  ChevronDown,
  ChevronsUpDown,
  Search,
  X,
  Clock,
  Calendar,
  Copy,
  Check,
} from "lucide-react"
import { Card, CardContent } from "../components/ui/card"
import { Badge } from "../components/ui/badge"
import { Button } from "../components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../components/ui/select"
import { Input } from "../components/ui/input"
import { IssueDetailSheet } from "../components/IssueDetailSheet"
import { Pagination } from "../components/Pagination"
import { type ApiClient, type Task } from "../lib/api"
import { useStore } from "../hooks/useStore"
import { cn, formatRelativeTime } from "../lib/utils"

type SortedIssue = Task & {
  _indentLevel: number
  _hasChildren: boolean
  _parentId?: string
}

// Unique identifier for a task — task_id for native tasks, task_ref for beads fallback (where task_id is null)
function taskUid(t: Task): string {
  return t.task_id ?? t.task_ref
}

const issueTypes = [
  { value: "all", label: "All types" },
  { value: "bug", label: "Bug" },
  { value: "feature", label: "Feature" },
  { value: "task", label: "Task" },
  { value: "epic", label: "Epic" },
  { value: "chore", label: "Chore" },
]

const viewModes = [
  { value: "flat", label: "Flat" },
  { value: "tree", label: "Tree" },
]

const sortOrders = [
  { value: "priority", label: "Priority" },
  { value: "recent", label: "Recent" },
  { value: "oldest", label: "Oldest" },
]

const priorityStyles: Record<number, string> = {
  0: "text-destructive border-destructive",
  1: "text-warning border-warning",
  2: "text-foreground",
  3: "text-muted-foreground",
  4: "text-muted-foreground/50",
}

const statusColors: Record<string, string> = {
  open: "bg-green-500",
  in_progress: "bg-blue-500",
  closed: "bg-purple-500",
}

function IssueCard({
  issue,
  onSelect,
  indentLevel = 0,
  hasChildren = false,
  isCollapsed = false,
  onToggleCollapse,
}: {
  issue: Task
  onSelect: (issue: Task) => void
  indentLevel?: number
  hasChildren?: boolean
  isCollapsed?: boolean
  onToggleCollapse?: () => void
}) {
  const [copied, setCopied] = useState(false)
  const copyTimeoutRef = useRef<number | null>(null)
  const hasBlockers = issue.blocked_by && issue.blocked_by.length > 0

  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current)
    }
  }, [])

  const handleCopyId = async (e: React.MouseEvent) => {
    e.stopPropagation()
    try {
      await navigator.clipboard.writeText(issue.task_ref)
      setCopied(true)
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current)
      copyTimeoutRef.current = window.setTimeout(() => setCopied(false), 1500)
    } catch (err) {
      console.error("Failed to copy task ref:", err)
    }
  }

  return (
    <Card className={cn(indentLevel > 0 && "border-l-2 border-l-muted-foreground/30")}>
      <CardContent className="p-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 mb-1">
              {hasChildren ? (
                <button
                  onClick={onToggleCollapse}
                  className="p-0.5 -ml-1 rounded hover:bg-muted transition-colors"
                  aria-label={isCollapsed ? "Expand" : "Collapse"}
                >
                  {isCollapsed ? (
                    <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                  ) : (
                    <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
                  )}
                </button>
              ) : indentLevel > 0 ? (
                <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground/40 ml-0.5" />
              ) : null}
              <div
                className={cn(
                  "h-2.5 w-2.5 shrink-0 rounded-full",
                  statusColors[issue.status] || "bg-muted-foreground"
                )}
              />
              <h3
                className="text-sm font-medium truncate cursor-pointer hover:text-primary hover:underline"
                onClick={() => onSelect(issue)}
              >
                {issue.title}
              </h3>
            </div>
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
              <Badge
                variant="outline"
                className="font-mono text-xs cursor-pointer hover:bg-accent hover:text-accent-foreground group/badge"
                onClick={handleCopyId}
                title="Click to copy task ref"
              >
                {issue.task_ref}
                {copied ? (
                  <Check className="h-3 w-3 ml-1.5 text-green-500" />
                ) : (
                  <Copy className="h-3 w-3 ml-1.5 opacity-40 group-hover/badge:opacity-100" />
                )}
              </Badge>
              {issue.task_type && (
                <>
                  <span>·</span>
                  <span>{issue.task_type}</span>
                </>
              )}
              {issue.assignee_agent_id && (
                <>
                  <span>·</span>
                  <span className="flex items-center gap-1">
                    <User className="h-3 w-3" />
                    {issue.assignee_agent_id}
                  </span>
                </>
              )}
              {issue.created_by_agent_id && (
                <>
                  <span>·</span>
                  <span className="flex items-center gap-1">
                    <User className="h-3 w-3" />
                    {issue.created_by_agent_id}
                  </span>
                </>
              )}
              {hasBlockers && (
                <>
                  <span>·</span>
                  <span className="text-warning">
                    blocked by {issue.blocked_by!.length}
                  </span>
                </>
              )}
              {issue.created_at && (
                <>
                  <span>·</span>
                  <span className="flex items-center gap-1" title={new Date(issue.created_at).toLocaleString()}>
                    <Calendar className="h-3 w-3" />
                    {formatRelativeTime(issue.created_at)}
                  </span>
                </>
              )}
              {issue.updated_at && (
                <>
                  <span>·</span>
                  <span className="flex items-center gap-1" title={new Date(issue.updated_at).toLocaleString()}>
                    <Clock className="h-3 w-3" />
                    {formatRelativeTime(issue.updated_at)}
                  </span>
                </>
              )}
            </div>
            {issue.labels && issue.labels.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                {issue.labels.map((label) => (
                  <Badge key={label} variant="secondary" className="text-xs">
                    {label}
                  </Badge>
                ))}
              </div>
            )}
          </div>
          <Badge
            variant="outline"
            className={cn(
              priorityStyles[issue.priority]
            )}
          >
            P{issue.priority}
          </Badge>
        </div>
      </CardContent>
    </Card>
  )
}

const DEBOUNCE_MS = 300

export function IssuesPage() {
  const api = useApi<ApiClient>()
  const { repoFilter } = useStore()
  const [searchParams, setSearchParams] = useSearchParams()
  const [statusFilter, setStatusFilter] = useState<string>("active")
  const [typeFilter, setTypeFilter] = useState<string>("all")
  const [viewMode, setViewMode] = useState<string>(() => {
    if (typeof window !== "undefined") {
      return localStorage.getItem("tasks-view-mode") || "flat"
    }
    return "flat"
  })
  const [sortOrder, setSortOrder] = useState<string>(() => {
    if (typeof window !== "undefined") {
      return localStorage.getItem("tasks-sort-order") || "priority"
    }
    return "priority"
  })
  const [selectedIssue, setSelectedIssue] = useState<Task | null>(null)
  const [collapsedTasks, setCollapsedTasks] = useState<Set<string>>(new Set())

  // Pagination state
  const [allIssues, setAllIssues] = useState<Task[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const [isLoadingMore, setIsLoadingMore] = useState(false)

  // Search state: URL param is source of truth, local state for input
  const searchQuery = searchParams.get("q") || ""
  const [searchInput, setSearchInput] = useState(searchQuery)
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Sync search input with URL param when URL changes externally
  useEffect(() => {
    setSearchInput(searchQuery)
  }, [searchQuery])

  // Debounced search: update URL after delay
  const handleSearchChange = useCallback((value: string) => {
    setSearchInput(value)
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current)
    }
    debounceTimerRef.current = setTimeout(() => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev)
        if (value.trim()) {
          next.set("q", value.trim())
        } else {
          next.delete("q")
        }
        return next
      }, { replace: true })
    }, DEBOUNCE_MS)
  }, [setSearchParams])

  // Clear search
  const clearSearch = useCallback(() => {
    setSearchInput("")
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current)
    }
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.delete("q")
      return next
    }, { replace: true })
  }, [setSearchParams])

  // Cleanup timer on unmount
  useEffect(() => {
    return () => {
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current)
      }
    }
  }, [])

  // Persist view preferences to localStorage
  useEffect(() => {
    localStorage.setItem("tasks-view-mode", viewMode)
  }, [viewMode])

  useEffect(() => {
    localStorage.setItem("tasks-sort-order", sortOrder)
  }, [sortOrder])

  // All tasks query using global filters
  const {
    data,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: [
      "tasks-all",
      statusFilter,
      typeFilter,
      searchQuery,
    ],
    queryFn: () =>
      api.listTasks({
        status: statusFilter === "active" ? undefined : statusFilter || undefined,
        task_type: typeFilter === "all" ? undefined : typeFilter,
        q: searchQuery || undefined,
        limit: 50,
      }),
    refetchInterval: 30000,
  })

  // Sync query data to local state (fixes navigation cache bug + enables pagination)
  // Client-side filter for "active" tab since the backend doesn't support comma-separated statuses
  useEffect(() => {
    if (data) {
      const tasks = statusFilter === "active"
        ? data.tasks.filter(t => t.status !== "closed")
        : data.tasks
      setAllIssues(tasks)
      setNextCursor(data.next_cursor ?? null)
      setHasMore(data.has_more ?? false)
    }
  }, [data, statusFilter])

  // Load more tasks
  const handleLoadMore = useCallback(async () => {
    if (!nextCursor || isLoadingMore) return

    setIsLoadingMore(true)
    try {
      const result = await api.listTasks({
        status: statusFilter === "active" ? undefined : statusFilter || undefined,
        task_type: typeFilter === "all" ? undefined : typeFilter,
        q: searchQuery || undefined,
        limit: 50,
        cursor: nextCursor,
      })
      setAllIssues(prev => [...prev, ...result.tasks])
      setNextCursor(result.next_cursor ?? null)
      setHasMore(result.has_more ?? false)
    } finally {
      setIsLoadingMore(false)
    }
  }, [nextCursor, isLoadingMore, api, statusFilter, typeFilter, searchQuery])

  const toggleCollapse = useCallback((taskId: string) => {
    setCollapsedTasks(prev => {
      const next = new Set(prev)
      if (next.has(taskId)) {
        next.delete(taskId)
      } else {
        next.add(taskId)
      }
      return next
    })
  }, [])

  const collapseAll = useCallback(() => {
    if (allIssues.length === 0) return
    const allParentIds = new Set<string>()
    const uidToTask = new Map(allIssues.map(i => [taskUid(i), i]))
    for (const issue of allIssues) {
      if (issue.parent_task_id && uidToTask.has(issue.parent_task_id)) {
        allParentIds.add(issue.parent_task_id)
      }
    }
    setCollapsedTasks(allParentIds)
  }, [allIssues])

  const expandAll = useCallback(() => {
    setCollapsedTasks(new Set())
  }, [])

  // Get sort comparator based on sortOrder
  const getSortComparator = useCallback((order: string) => {
    return (a: Task, b: Task): number => {
      if (order === "recent") {
        const dateA = a.updated_at ? new Date(a.updated_at).getTime() : 0
        const dateB = b.updated_at ? new Date(b.updated_at).getTime() : 0
        return dateB - dateA
      }
      if (order === "oldest") {
        const dateA = a.updated_at ? new Date(a.updated_at).getTime() : 0
        const dateB = b.updated_at ? new Date(b.updated_at).getTime() : 0
        return dateA - dateB
      }
      // Default: priority (lower = higher priority)
      return a.priority - b.priority
    }
  }, [])

  // Sort and group issues based on viewMode and sortOrder
  const sortedIssues = useMemo((): SortedIssue[] => {
    if (allIssues.length === 0) return []

    const issues = [...allIssues]
    const comparator = getSortComparator(sortOrder)

    if (viewMode === "flat") {
      return issues
        .sort(comparator)
        .map(i => ({ ...i, _indentLevel: 0, _hasChildren: false }))
    }

    // Tree view: build hierarchy using parent_task_id
    // Use taskUid() as the canonical identifier (handles beads fallback where task_id is null)
    const uidSet = new Set(issues.map(i => taskUid(i)))

    // Build children map: parent task_id -> children
    const childrenMap = new Map<string, Task[]>()
    for (const issue of issues) {
      const parentId = issue.parent_task_id
      if (parentId && uidSet.has(parentId)) {
        if (!childrenMap.has(parentId)) {
          childrenMap.set(parentId, [])
        }
        childrenMap.get(parentId)!.push(issue)
      }
    }

    // Find root tasks (no parent_task_id or parent not in current set)
    const roots = issues.filter(i => {
      return !i.parent_task_id || !uidSet.has(i.parent_task_id)
    })

    // Sort roots using the selected sort order
    roots.sort(comparator)

    // Build flat list with indentation levels and children info
    const result: Array<Task & { _indentLevel: number; _hasChildren: boolean; _parentId?: string }> = []
    const visited = new Set<string>()

    const addWithChildren = (issue: Task, level: number, parentId?: string) => {
      const uid = taskUid(issue)
      if (visited.has(uid)) return
      visited.add(uid)
      const children = childrenMap.get(uid) || []
      result.push({ ...issue, _indentLevel: level, _hasChildren: children.length > 0, _parentId: parentId })

      // Sort children using the selected sort order
      children.sort(comparator)
      for (const child of children) {
        addWithChildren(child, level + 1, uid)
      }
    }

    for (const root of roots) {
      addWithChildren(root, 0)
    }

    // Add any orphaned tasks (in case of circular dependencies)
    for (const issue of issues) {
      if (!visited.has(taskUid(issue))) {
        result.push({ ...issue, _indentLevel: 0, _hasChildren: false })
      }
    }

    return result
  }, [allIssues, viewMode, sortOrder, getSortComparator])

  // Filter out collapsed children
  const visibleIssues = useMemo((): SortedIssue[] => {
    if (viewMode !== "tree" || collapsedTasks.size === 0) {
      return sortedIssues
    }

    // Check if any ancestor is collapsed
    const findCollapsedAncestor = (issue: SortedIssue): boolean => {
      if (!issue._parentId) return false
      if (collapsedTasks.has(issue._parentId)) return true
      const parent = sortedIssues.find(i => taskUid(i) === issue._parentId)
      return parent ? findCollapsedAncestor(parent) : false
    }

    return sortedIssues.filter(issue => !findCollapsedAncestor(issue))
  }, [sortedIssues, viewMode, collapsedTasks])

  // Build scope label
  const scopeLabel = repoFilter
    ? `Repo: ${repoFilter}`
    : "All workspaces"

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">Tasks</h1>
          <p className="text-sm text-muted-foreground">{scopeLabel}</p>
        </div>
        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative w-[220px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search..."
              value={searchInput}
              onChange={(e) => handleSearchChange(e.target.value)}
              className="pl-9 pr-8 h-9"
              aria-label="Search tasks by ref or title"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={clearSearch}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                aria-label="Clear search"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          <Select value={viewMode} onValueChange={setViewMode}>
            <SelectTrigger className="w-[90px] h-9">
              <SelectValue placeholder="View" />
            </SelectTrigger>
            <SelectContent>
              {viewModes.map((mode) => (
                <SelectItem key={mode.value} value={mode.value}>
                  {mode.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {viewMode === "tree" && (
            <Button
              variant="outline"
              size="sm"
              onClick={collapsedTasks.size > 0 ? expandAll : collapseAll}
              title={collapsedTasks.size > 0 ? "Expand all" : "Collapse all"}
            >
              <ChevronsUpDown className="h-4 w-4" />
            </Button>
          )}
          <Select value={sortOrder} onValueChange={setSortOrder}>
            <SelectTrigger className="w-[100px] h-9">
              <SelectValue placeholder="Sort" />
            </SelectTrigger>
            <SelectContent>
              {sortOrders.map((order) => (
                <SelectItem key={order.value} value={order.value}>
                  {order.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={typeFilter} onValueChange={setTypeFilter}>
            <SelectTrigger className="w-[120px] h-9">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              {issueTypes.map((type) => (
                <SelectItem key={type.value} value={type.value}>
                  {type.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
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

      {/* Tabs */}
      <Tabs value={statusFilter} onValueChange={setStatusFilter}>
        <TabsList>
          <TabsTrigger value="active">Active</TabsTrigger>
          <TabsTrigger value="closed">Closed</TabsTrigger>
          <TabsTrigger value="">All</TabsTrigger>
        </TabsList>

        <TabsContent value={statusFilter} className="mt-4">
          {/* Error State */}
          {error && (
            <Card className="border-destructive">
              <CardContent className="p-4">
                <p className="text-sm text-destructive">
                  Failed to load tasks: {(error as Error).message}
                </p>
              </CardContent>
            </Card>
          )}

          {/* Loading State */}
          {isLoading && !data && (
            <div className="text-center py-12 text-muted-foreground">
              Loading tasks...
            </div>
          )}

          {/* Empty State */}
          {visibleIssues.length === 0 && !isLoading && (
            <Card>
              <CardContent className="p-8 text-center">
                <ListTodo className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" />
                <p className="text-muted-foreground">
                  {searchQuery
                    ? `No tasks matching "${searchQuery}"`
                    : statusFilter === "active"
                    ? "No active tasks"
                    : statusFilter === "closed"
                    ? "No closed tasks"
                    : "No tasks found"}
                </p>
                {searchQuery && (
                  <Button
                    variant="link"
                    className="mt-2"
                    onClick={clearSearch}
                  >
                    Clear search
                  </Button>
                )}
              </CardContent>
            </Card>
          )}

          {/* Issues List */}
          {visibleIssues.length > 0 && (
            <div className="grid gap-2">
              {visibleIssues.map((issue) => (
                <div
                  key={taskUid(issue)}
                  style={{ marginLeft: (issue._indentLevel || 0) * 20 }}
                >
                  <IssueCard
                    issue={issue}
                    onSelect={setSelectedIssue}
                    indentLevel={issue._indentLevel || 0}
                    hasChildren={issue._hasChildren || false}
                    isCollapsed={collapsedTasks.has(taskUid(issue))}
                    onToggleCollapse={() => toggleCollapse(taskUid(issue))}
                  />
                </div>
              ))}
            </div>
          )}

          {/* Pagination */}
          <Pagination
            onLoadMore={handleLoadMore}
            hasMore={hasMore}
            isLoading={isLoadingMore}
            itemCount={allIssues.length}
          />
        </TabsContent>
      </Tabs>

      {/* Issue Detail Sheet */}
      <IssueDetailSheet
        issue={selectedIssue}
        onClose={() => setSelectedIssue(null)}
        onNavigate={(taskRef) => {
          const issue = allIssues.find((i) => i.task_ref === taskRef)
          if (issue) setSelectedIssue(issue)
        }}
      />
    </div>
  )
}
