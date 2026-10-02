import unicodedata

ALLOWED_CHARS = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "._%+-@<>,\"' "
)

def find_spoof_characters(text: str) -> list[dict]:
    if not text:
        return []

    flagged = []
    for index, char in enumerate(text):
        if char not in ALLOWED_CHARS:
            try:
                name = unicodedata.name(char)
            except ValueError:
                name = "unknown"
            flagged.append(
                {
                    "char": char,
                    "unicode_name": name,
                    "position": index,
                }
            )
    return flagged
