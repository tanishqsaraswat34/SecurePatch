from html import escape


def render_profile(username: str) -> str:
    # INTENTIONALLY VULNERABLE:
    # User input is inserted directly into HTML.
    return "<div class='profile'>" + username + "</div>"