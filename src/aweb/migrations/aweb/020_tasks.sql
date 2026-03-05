-- aweb tasks: project-scoped task management

CREATE TABLE IF NOT EXISTS {{tables.task_counters}} (
    project_id UUID PRIMARY KEY REFERENCES {{tables.projects}}(project_id),
    next_number INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS {{tables.tasks}} (
    task_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    task_number INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'in_progress', 'closed')),
    priority INTEGER NOT NULL DEFAULT 2
        CHECK (priority >= 0 AND priority <= 4),
    task_type TEXT NOT NULL DEFAULT 'task'
        CHECK (task_type IN ('task', 'bug', 'feature')),
    assignee_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    created_by_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    closed_by_agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    labels TEXT[] NOT NULL DEFAULT '{}',
    parent_task_id UUID REFERENCES {{tables.tasks}}(task_id),
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ,
    UNIQUE (project_id, task_number)
);

CREATE INDEX IF NOT EXISTS idx_tasks_project_status
ON {{tables.tasks}} (project_id, status)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tasks_project_assignee
ON {{tables.tasks}} (project_id, assignee_agent_id)
WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tasks_parent
ON {{tables.tasks}} (parent_task_id)
WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS {{tables.task_dependencies}} (
    task_id UUID NOT NULL REFERENCES {{tables.tasks}}(task_id) ON DELETE CASCADE,
    depends_on_task_id UUID NOT NULL REFERENCES {{tables.tasks}}(task_id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (task_id, depends_on_task_id),
    CHECK (task_id != depends_on_task_id)
);

CREATE TABLE IF NOT EXISTS {{tables.task_comments}} (
    comment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES {{tables.tasks}}(task_id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES {{tables.projects}}(project_id),
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_task_comments_task
ON {{tables.task_comments}} (task_id, created_at);
