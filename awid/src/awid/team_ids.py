from __future__ import annotations


def build_team_id(domain: str, name: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    name = name.strip().lower()
    if not domain or not name:
        raise ValueError("domain and name are required")
    return f"{name}:{domain}"


def parse_team_id(team_id: str) -> tuple[str, str]:
    team_id = team_id.strip()
    name, sep, domain = team_id.partition(":")
    if sep != ":" or not name.strip() or not domain.strip():
        raise ValueError(f"Invalid team_id format: {team_id}")
    return domain.strip().lower().rstrip("."), name.strip().lower()


def team_slug(team_id: str) -> str:
    _, name = parse_team_id(team_id)
    return name
