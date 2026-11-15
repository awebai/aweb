"""Select the served member-list action by its declared initiation hook."""


def member_removal_definition(definitions):
    selected = [row for row in definitions if row.owner_initiable and row.effect.initiation_prepare == "prepare_selection"]
    if len(selected) > 1:
        raise ValueError("ambiguous member-removal initiation hook")
    return selected[0] if selected else None
