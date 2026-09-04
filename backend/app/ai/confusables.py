"""A curated Unicode-confusables table for domain-homoglyph detection.

This is not the full Unicode confusables.txt (thousands of entries covering
every script) -- it's a hand-picked table of the characters that actually
show up in real-world domain-spoofing attacks: Cyrillic and Greek letters
that are visually near-identical to Latin letters, plus a few common
"leetspeak" digit-for-letter substitutions. Small and auditable beats
exhaustive and opaque for this use case: the goal is normalizing a
candidate domain to the Latin "skeleton" it's visually impersonating, not
cataloguing every confusable code point in Unicode.
"""

# Maps a confusable character to the ASCII Latin letter it visually mimics.
CONFUSABLES: dict[str, str] = {
    # Cyrillic -> Latin
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ѕ": "s",
    "ј": "j",
    "һ": "h",
    "ԁ": "d",
    "ԛ": "q",
    "ѡ": "w",
    "ц": "u",
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    # Greek -> Latin
    "α": "a",
    "β": "b",
    "ο": "o",
    "ρ": "p",
    "υ": "u",
    "ν": "v",
    "κ": "k",
    "τ": "t",
    "χ": "x",
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    # Common digit-for-letter substitutions ("leetspeak" typosquats)
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
}


def to_skeleton(text: str) -> str:
    """Normalize text to its Latin "skeleton" by mapping each confusable
    character to what it visually mimics, lowercased. Two domains that
    look alike to a human but use different scripts/digits produce the
    same skeleton."""
    return "".join(CONFUSABLES.get(ch, ch) for ch in text).lower()


def contains_non_ascii(text: str) -> bool:
    return any(ord(ch) > 127 for ch in text)
