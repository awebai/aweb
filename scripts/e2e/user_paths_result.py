"""Required inventory and qualification, separate from product execution."""
PAIRS = [('g1', 'g2'), ('g2', 'g1'), ('t1', 't2'), ('t2', 't1'), ('t1', 'g1'), ('g1', 't1')]
CONTROLS = ['same-team/team-and-contacts', 'contacts-only/mail', 'contacts-only/chat',
            'nonresident/mail', 'nonresident/chat', 'cross-server/mail', 'cross-server/chat',
            'waiting-chat', 'fresh-chat/plain-v2-plain']
HUMANS = ['g-to-human/mail-by-address', 't-to-human/mail-by-address', 'human-to-g/mail',
          'human-to-t/mail', 'human-chat-refusal', 'hosted-human-explicit-e2ee-refusal-if-hosted']


def qualification(lanes, seconds, cleanup_errors):
    required = [f'{lane}/{sender}->{receiver}/{kind}/{mode}'
                for lane in ['head', 'released'] for sender, receiver in PAIRS
                for kind in ['mail', 'chat'] for mode in ['plain', 'v2']]
    required += [f'{lane}/{case}' for lane in ['head', 'released'] for case in CONTROLS]
    outcomes = [outcome for lane in lanes.values() for outcome in lane.get('outcomes', [])]
    observed = {outcome['case']: outcome for outcome in outcomes}
    missing = sorted(set(required) - observed.keys())
    failures = [row['case'] for row in outcomes if row['status'] != 'PASSED']
    duplicates = len(outcomes) != len(observed)
    failed = bool(missing or failures or cleanup_errors or duplicates or seconds >= 600)
    return dict(status='FAILED' if failed else 'INCOMPLETE', seconds=seconds,
                required_agent_cases=required, missing_agent_cases=missing,
                failed_cases=failures, duplicate_cases=duplicates,
                required_humans=[dict(case=f'{lane}/{case}', status='PENDING aweb-actu')
                                 for lane in ['head', 'released'] for case in HUMANS],
                cleanup_errors=cleanup_errors)
