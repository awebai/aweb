"""One route surface over explicitly provisioned instances of the shared executor.

Dispatch selects custody by exact trusted context, never by a worker-selected
key or raw signing bytes. All instances use the same DB, origin and B3 schema.
"""

from aweb_naapp.runtime.protected_signer import ProtectedKeyContext, SignerRefused


class _Executors:
    def __init__(self, group):
        self.group = group
        self.db, self.passkeys = group.db, group.passkeys
        self.policies = group.selected.signer.policies

    async def lookup_context(self, operation_id):
        return await self.group.selected.signer.lookup_context(operation_id)

    async def lookup_handoff(self, handoff_id):
        return await self.group.selected.signer.lookup_handoff(handoff_id)

    async def prepare(self, operation, *, requester):
        return await self.group.component(operation.context).signer.prepare(operation, requester=requester)

    async def inspect(self, operation_id, *, human, human_session=None):
        return await self.group.component(human.context).signer.inspect(operation_id, human=human, human_session=human_session)

    async def requested_by_you(self, operation_id, *, human, human_session=None):
        return await self.group.component(human.context).signer.requested_by_you(operation_id, human=human, human_session=human_session)

    async def approval_options(self, operation_id, *, human, human_session=None):
        return await self.group.component(human.context).signer.approval_options(operation_id, human=human, human_session=human_session)

    async def execute(self, operation_id, proof, *, human, human_session=None):
        return await self.group.component(human.context).signer.execute(operation_id, proof, human=human, human_session=human_session)

    async def execute_request(self, operation_id, *, requester):
        return await self.group.component(requester.context).signer.execute_request(operation_id, requester=requester)

    async def receipt(self, operation_id, *, reader, human_session=None):
        return await self.group.component(reader.context, receipt=True).signer.receipt(operation_id, reader=reader, human_session=human_session)


class ProtectedSignerGroup:
    def __init__(self, components, *, selected):
        if not components or selected not in components:
            raise ValueError("selected protected context required")
        self.components, self.selected = tuple(components), selected
        self.db, self.passkeys = selected.db, selected.passkeys
        self.context, self.authority, self.registry = selected.context, selected.authority, selected.registry
        self.request_origin = selected.request_origin
        contexts = set()
        protected_keys = frozenset(c.authority.custody.team_key_did for c in self.components if hasattr(c.authority, "custody"))
        for c in self.components:
            c.protected_authority_keys = protected_keys
            context = tuple(str(c.context.fields()[key]) for key in sorted(c.context.fields()))
            if c.db is not self.db or c.request_origin != self.request_origin or context in contexts:
                raise ValueError("protected context group is inconsistent")
            contexts.add(context)
        self.signer = _Executors(self)

    def component(self, context, *, receipt=False):
        def fields(c):
            value = c.fields()
            if receipt:
                value.pop("generation")
            return value
        matches = [c for c in self.components if fields(c.context) == fields(context)]
        if len(matches) != 1:
            raise SignerRefused("scope_refused")
        return matches[0]

    async def for_b3_scope(self, scope, *, tx):
        row = await tx.fetch_one(
            "SELECT * FROM {{tables.protected_authorizer_bindings}} WHERE b3_scope=$1 AND active=TRUE", scope,
        )
        if row is None:
            raise SignerRefused("scope_refused")
        context = ProtectedKeyContext(row["service_id"], row["authority_kind"], row["team_id"],
            row["authority_domain"] or row["team_id"].partition(":")[2], row["human_id"], row["human_domain"], row["generation"])
        return self.component(context)

    async def context_for_scope(self, scope, *, tx):
        c = await self.for_b3_scope(scope, tx=tx)
        return await c.authority.context_for_scope(scope, tx=tx)

    async def authenticate_prepare(self, request, operation):
        return await self.component(operation.context).authenticate_prepare(request, operation)

    async def authenticate_receipt(self, request, operation_id):
        context = await self.signer.lookup_context(operation_id)
        if context is None:
            raise SignerRefused("operation_not_found")
        return await self.component(context, receipt=True).authenticate_receipt(request, operation_id)

    async def authenticate_execute(self, request, operation_id):
        context = await self.signer.lookup_context(operation_id)
        if context is None:
            raise SignerRefused("operation_not_found")
        return await self.component(context).authenticate_execute(request, operation_id)

    async def read_admission_policy(self, request, team_id):
        matches = [c for c in self.components if c.context.authority_kind == "team_controller" and c.context.authority_id == team_id]
        if len(matches) != 1:
            raise SignerRefused("scope_refused")
        return await matches[0].read_admission_policy(request, team_id)

    def protected_sessions(self):
        from aweb_naapp.console import ConsoleSessions

        async def current_scope(scope):
            try:
                await self.context_for_scope(scope, tx=self.db)
                return True
            except SignerRefused:
                return False
        return ConsoleSessions(self.db, passkeys=self.passkeys, scopes=current_scope)

    async def prepare_owner_selection(self, selection, session):
        async with self.db.transaction() as tx:
            component = await self.for_b3_scope(session.scope, tx=tx)
        return await component.prepare_owner_selection(selection, session)

    def operations_http(self, **kwargs):
        from aweb_naapp.runtime.protected_signer import ProtectedOperationsHTTP

        return ProtectedOperationsHTTP(self.signer, request_origin=self.request_origin,
            requester=self.authenticate_prepare, reader=self.authenticate_receipt, executor=self.authenticate_execute,
            policy_reader=self.read_admission_policy, owner_prepare=self.prepare_owner_selection, **kwargs)

    async def migrate(self):
        await self.selected.migrate()
