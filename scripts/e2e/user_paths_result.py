"""Required inventory and qualification, separate from product execution."""
import re

PAIRS = [('g1', 'g2'), ('g2', 'g1'), ('t1', 't2'), ('t2', 't1'), ('t1', 'g1'), ('g1', 't1')]
CONTROLS = ['same-team/team-and-contacts', 'contacts-only/mail', 'contacts-only/chat',
            'nonresident/mail', 'nonresident/chat', 'cross-server/mail', 'cross-server/chat',
            'waiting-chat', 'fresh-chat/plain-v2-plain']
HUMANS = ['g-to-human/mail-by-address', 't-to-human/mail-by-address', 'human-to-g/mail',
          'human-to-t/mail', 'human-chat-refusal', 'hosted-human-explicit-e2ee-refusal-if-hosted']
COVERAGE_SUMMARY = 'incomplete: human paths not covered'
HUMAN_STATUS = 'NOT COVERED: pending aweb-actu'

# Coordinator 143e403a supersedes d51223e6: npm latest aw 1.36.55 carries
# the actw fix. Future exceptions still require exact reviewed failure receipts.
KNOWN_RELEASED_ISSUES = []


def classify_outcome(outcome, version):
    """Only an exact, version-bounded failure at the measured command is budgeted."""
    result = dict(outcome)
    actual = outcome.get('observed_status', outcome['status'])
    result['observed_status'] = actual
    rule = next((rule for rule in KNOWN_RELEASED_ISSUES if rule['case'] == outcome['case']), None)
    if rule is None:
        result['status'] = 'PASSED' if actual == 'PASSED' else 'FAILED'
        return result
    result['known_issue'] = rule
    if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        result.update(status='FAILED', budget_error='known-issue budget needs an exact released final version')
        return result
    numbers = lambda value: tuple(map(int, value.split('.')))
    if not numbers(rule['minimum_version']) <= numbers(version) <= numbers(rule['maximum_version']):
        result.update(status='FAILED', budget_error='released version is outside the reviewed budget; update or remove the entry')
        return result
    failure = outcome.get('failure') or {}
    args = failure.get('args') or []
    expected = ['chat', 'send-and-wait', rule['target'], None, '--e2ee', '--wait', '0']
    command_matches = (len(args) == len(expected) and args[:3] == expected[:3] and args[4:] == expected[4:]
                       and isinstance(args[3], str) and re.fullmatch(re.escape(rule['case']) + r'/[0-9a-f]{32}', args[3]))
    if (actual == 'FAILED' and failure.get('exit') == rule['exit'] and failure.get('actor') == rule['actor']
            and command_matches and failure.get('response') == {'error': {'code': rule['code'], 'message': rule['message']}}
            and failure.get('stderr') == rule['message'] + '\n'):
        result['status'] = 'KNOWN_ISSUE'
    else:
        result.update(status='FAILED', budget_error='declared known issue passed unexpectedly or failed differently')
    return result


def qualification(lanes, seconds, cleanup_errors):
    required = [f'{lane}/{sender}->{receiver}/{kind}/{mode}'
                for lane in ['head', 'released'] for sender, receiver in PAIRS
                for kind in ['mail', 'chat'] for mode in ['plain', 'v2']]
    required += [f'{lane}/{case}' for lane in ['head', 'released'] for case in CONTROLS]
    outcomes = [classify_outcome(outcome, lane.get('version'))
                for lane in lanes.values() for outcome in lane.get('outcomes', [])]
    observed = {outcome['case']: outcome for outcome in outcomes}
    missing = sorted(set(required) - observed.keys())
    failures = [row['case'] for row in outcomes if row['status'] not in ['PASSED', 'KNOWN_ISSUE']]
    duplicates = len(outcomes) != len(observed)
    failed = bool(missing or failures or cleanup_errors or duplicates or seconds >= 600)
    return dict(status='FAILED' if failed else 'PASSED', seconds=seconds,
                required_agent_cases=required, missing_agent_cases=missing,
                failed_cases=failures, duplicate_cases=duplicates,
                passed_agent_cases=[row['case'] for row in outcomes if row['status'] == 'PASSED' and row['case'] in required],
                known_issue_budget=KNOWN_RELEASED_ISSUES,
                known_issues=[row for row in outcomes if row['status'] == 'KNOWN_ISSUE'],
                coverage_summary=COVERAGE_SUMMARY,
                required_humans=[dict(case=f'{lane}/{case}', status=HUMAN_STATUS)
                                 for lane in ['head', 'released'] for case in HUMANS],
                cleanup_errors=cleanup_errors)
