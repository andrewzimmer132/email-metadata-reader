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
    spoof_m = False
    spoof_l = False
    spoof_o = False

    flagged = []
    for index, char in enumerate(text):
        #Checking for spoofed "o" as "0"
        if spoof_o and char in "0":
            flagged.append(
                {
                    "char": char,
                    "unicode_name": unicodedata.name(char),
                    "position": index,
                }
            )
            spoof_o = False
        elif spoof_o and char not in "0":
            spoof_o = False
        #Checking for spoofed "l" as "I"
        if spoof_l and char in "I1":
            flagged.append(
                {
                    "char": char,
                    "unicode_name": unicodedata.name(char),
                    "position": index,
                }
            )
            spoof_l = False
        elif spoof_l and char not in "I1":
            spoof_l = False
        #Checking for spoofed "m" as "rn"
        if spoof_m and char in "n":
            flagged.append(
                {
                    "char": "r",
                    "unicode_name": unicodedata.name("r"),
                    "position": index - 1,
                }
            )
            flagged.append(
                {
                    "char": char,
                    "unicode_name": unicodedata.name(char),
                    "position": index,
                }
            )
            spoof_m = False
        elif spoof_m and char not in "n":
            spoof_m = False
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
        if char in "r":
            spoof_m = True
        if char not in " ":
            spoof_l = True
            spoof_o = True
    return flagged
