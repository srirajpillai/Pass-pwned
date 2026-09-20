"""
Password strength analyser.

Replaces rigid "one upper, one digit, one symbol" complexity rules with a
measurement of how a real cracking engine would attack the password:

  * how large is the character pool the password actually draws from
  * how much Shannon-style entropy does that give
  * which *human* patterns (dictionary words, sequences, repeats, keyboard
    walks, dates) collapse the effective search space
  * how long would an offline fast-hash cracking rig need

Every result is deterministic - no network access is required.
"""

import math
import re

# --------------------------------------------------------------------------- #
#  data
# --------------------------------------------------------------------------- #
# A compact list of the passwords that appear at the very top of every leaked
# corpus.  Real deployments should use a much larger list (or the offline
# zxcvbn package); this keeps the project dependency free.
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "1234567890", "1234567", "12345",
    "1234", "123123", "111111", "000000", "password", "password1",
    "password123", "passw0rd", "passwd", "p@ssword", "qwerty", "qwerty123",
    "qwertyuiop", "qwerty1", "abc123", "admin", "admin123", "letmein",
    "welcome", "welcome1", "monkey", "dragon", "sunshine", "princess",
    "football", "baseball", "iloveyou", "shadow", "master", "superman",
    "trustno1", "1q2w3e4r", "zxcvbnm", "asdfgh", "login", "hello", "secret",
    "starwars", "whatever", "internet", "computer", "michael", "jordan",
    "harley", "ranger", "hunter", "buster", "thomas", "summer", "winter",
    "freedom", "chocolate", "password@123", "india", "mumbai", "delhi",
}

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

LEET_MAP = str.maketrans({
    "4": "a", "@": "a", "8": "b", "(": "c", "{": "c", "[": "c",
    "3": "e", "6": "g", "9": "g", "1": "l", "!": "i", "|": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "+": "t", "2": "z",
})

# guesses per second of a commodity GPU rig against a *fast* (unsalted) hash
GUESSES_PER_SECOND = 1e10

VERDICTS = [
    (0, 20, "Very Weak", "danger"),
    (21, 40, "Weak", "warn"),
    (41, 60, "Fair", "warn"),
    (61, 80, "Strong", "ok"),
    (81, 100, "Excellent", "ok"),
]


# --------------------------------------------------------------------------- #
#  helpers
# --------------------------------------------------------------------------- #
def _charset_size(pwd):
    """Size of the character pool the password actually draws from."""
    pool = 0
    if re.search(r"[a-z]", pwd):
        pool += 26
    if re.search(r"[A-Z]", pwd):
        pool += 26
    if re.search(r"[0-9]", pwd):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", pwd):
        pool += 33
    return max(pool, 1)


def _effective_length(pwd):
    """Length after collapsing runs and ordered sequences.

    Repeating the same character ("aaaa") or walking one step at a time
    ("1234", "abcd") adds almost no search space for a cracking engine, so
    those characters are discounted before the entropy is computed.
    """
    if not pwd:
        return 0
    low = pwd.lower()
    n = 1
    for i in range(1, len(low)):
        a, b = low[i - 1], low[i]
        if a == b:                                   # repeated character
            continue
        if a.isalnum() and b.isalnum() and abs(ord(b) - ord(a)) == 1:
            continue                                 # +1 / -1 step
        n += 1
    return max(n, 1)


def _entropy_bits(pwd):
    """Entropy of the *effective* password, not of the raw character count."""
    if not pwd:
        return 0.0
    return _effective_length(pwd) * math.log2(_charset_size(pwd))


def _deleet(pwd):
    return pwd.translate(LEET_MAP).lower()


def _longest_run(pwd, alphabet):
    """Longest substring of `pwd` that walks `alphabet` forwards or back."""
    best = 0
    low = pwd.lower()
    for direction in (alphabet, alphabet[::-1]):
        run = 1
        for i in range(1, len(low)):
            a, b = low[i - 1], low[i]
            if a in direction and b in direction:
                if direction.index(b) - direction.index(a) == 1:
                    run += 1
                    best = max(best, run)
                else:
                    run = 1
            else:
                run = 1
    return best


def _is_digit_sequence(pwd):
    return bool(re.search(r"(?:0123|1234|2345|3456|4567|5678|6789|7890|"
                          r"0987|9876|8765|7654|6543|5432|4321|3210)", pwd))


def _is_letter_sequence(pwd):
    return _longest_run(pwd, "abcdefghijklmnopqrstuvwxyz") >= 4


def _keyboard_walk(pwd):
    for row in KEYBOARD_ROWS:
        if _longest_run(pwd, row) >= 4:
            return True
    return False


def _find_repeats(pwd):
    """Return the longest run of identical characters."""
    best, run = 1, 1
    for i in range(1, len(pwd)):
        if pwd[i] == pwd[i - 1]:
            run += 1
            best = max(best, run)
        else:
            run = 1
    return best


def _contains_year(pwd):
    return bool(re.search(r"(19\d{2}|20\d{2})", pwd))


def _has_word(pwd):
    """True when the (de-leeted) password contains a very common word."""
    norm = re.sub(r"[^a-z]", "", _deleet(pwd))
    if norm in COMMON_PASSWORDS:
        return True
    for word in COMMON_PASSWORDS:
        w = re.sub(r"[^a-z]", "", word.lower())
        if len(w) >= 4 and w in norm:
            return True
    return False


# --------------------------------------------------------------------------- #
#  crack time
# --------------------------------------------------------------------------- #
_UNITS = [
    (1, "second", "seconds"),
    (60, "minute", "minutes"),
    (3600, "hour", "hours"),
    (86400, "day", "days"),
    (2592000, "month", "months"),
    (31536000, "year", "years"),
]


def _humanise(seconds):
    """Format a duration in seconds as a short human readable string."""
    if seconds < 1:
        return "instant"
    # pick the largest unit that still gives a value >= 1
    limit, singular, plural = 1, "second", "seconds"
    for lim, s, p in _UNITS:
        if seconds / lim >= 1:
            limit, singular, plural = lim, s, p
        else:
            break
    value = seconds / limit
    if singular == "year" and value > 1000:
        return "centuries"
    if value < 10:
        text = "%.1f" % value
        text = text.rstrip("0").rstrip(".")
    else:
        text = "{:,}".format(int(round(value)))
    return "%s %s" % (text, singular if float(text.replace(",", "")) == 1
                      else plural)


def crack_time(entropy_bits):
    guesses = max(2 ** (entropy_bits - 1), 1)
    seconds = guesses / GUESSES_PER_SECOND
    return _humanise(seconds)


# --------------------------------------------------------------------------- #
#  public API
# --------------------------------------------------------------------------- #
def analyse(password):
    """Score a password.

    Returns a JSON-serialisable dictionary describing the strength of
    `password` together with the weaknesses that were detected.
    """
    pwd = password or ""
    length = len(pwd)

    if length == 0:
        return {
            "length": 0, "score": 0, "verdict": "Very Weak", "tone": "danger",
            "entropy_bits": 0.0, "charset_size": 0, "crack_time": "instant",
            "patterns": [], "suggestions": ["Type a password to begin."],
            "checks": [],
        }

    entropy = _entropy_bits(pwd)
    charset = _charset_size(pwd)
    score = min(100.0, entropy * 2.6)

    patterns = []

    def add(name, detail, penalty):
        nonlocal score
        patterns.append({"name": name, "detail": detail, "penalty": penalty})
        score -= penalty

    # ---- structural weaknesses ---------------------------------------------
    exact_common = (pwd.lower() in COMMON_PASSWORDS
                    or _deleet(pwd) in COMMON_PASSWORDS)
    wordy = exact_common or _has_word(pwd)
    if exact_common:
        add("Found in common password list",
            "This exact password is one of the most frequently used "
            "passwords in the world.", 45)
    elif wordy:
        add("Contains a common word",
            "Dictionary words are tried first by every cracking tool.", 34)

    if _is_digit_sequence(pwd):
        add("Number sequence", "Contains a run of consecutive digits "
                               "(e.g. 1234, 9876).", 22)
    if _is_letter_sequence(pwd):
        add("Letter sequence", "Contains four or more consecutive letters "
                               "(e.g. abcd).", 20)
    if _keyboard_walk(pwd):
        add("Keyboard walk", "Follows a straight line across the keyboard "
                             "(e.g. qwer, asdf).", 24)

    repeats = _find_repeats(pwd)
    if repeats >= 3:
        add("Repeated characters",
            "The character '%s' repeats %d times in a row."
            % (next((c for i, c in enumerate(pwd)
                     if i and c == pwd[i - 1]), pwd[0]), repeats), 18)

    if _contains_year(pwd):
        add("Contains a year", "Birth years and calendar years are among the "
                               "first things a cracker appends.", 14)

    if length < 8:
        add("Too short", "Passwords below 8 characters are trivially "
                         "brute forced.", 25)
    elif length < 12:
        add("Could be longer", "Length is the single biggest factor in "
                               "resisting an offline attack.", 8)

    # ---- character variety --------------------------------------------------
    checks = [
        ("Lowercase letter", bool(re.search(r"[a-z]", pwd))),
        ("Uppercase letter", bool(re.search(r"[A-Z]", pwd))),
        ("Digit", bool(re.search(r"[0-9]", pwd))),
        ("Symbol", bool(re.search(r"[^A-Za-z0-9]", pwd))),
        ("12 or more characters", length >= 12),
        ("No common word", not _has_word(pwd)),
    ]
    missing = [label for label, ok in checks if not ok]
    if len(missing) >= 3:
        add("Low character variety",
            "Missing: %s." % ", ".join(missing[:3]), 10)

    # ---- clamp & verdict ----------------------------------------------------
    score = int(round(max(0, min(100, score))))
    # a password taken straight from a leaked top-list can never leave the
    # "Very Weak" band, and a dictionary based one can never reach "Strong"
    if exact_common:
        score = min(score, 8)
    elif wordy:
        score = min(score, 38)
    # a password that triggered nothing and is long enough can never be "weak"
    if not patterns and length >= 12:
        score = max(score, 82)

    verdict, tone = "Very Weak", "danger"
    for lo, hi, name, tn in VERDICTS:
        if lo <= score <= hi:
            verdict, tone = name, tn
            break

    # ---- suggestions --------------------------------------------------------
    suggestions = []
    if length < 12:
        suggestions.append("Use at least 12 characters - length beats "
                           "complexity rules.")
    if _has_word(pwd):
        suggestions.append("Avoid dictionary words, even with numbers or "
                           "symbols attached.")
    if any(p["name"] == "Keyboard walk" for p in patterns):
        suggestions.append("Do not use keys that sit next to each other.")
    if any(p["name"] == "Repeated characters" for p in patterns):
        suggestions.append("Avoid repeating the same character.")
    if len(missing) >= 2:
        suggestions.append("Mix character types - add %s."
                           % ", ".join(missing[:3]))
    if not suggestions:
        suggestions.append("Good. Store it in a password manager and never "
                           "reuse it on another site.")

    return {
        "length": length,
        "score": score,
        "verdict": verdict,
        "tone": tone,
        "entropy_bits": round(entropy, 1),
        "charset_size": charset,
        "crack_time": crack_time(entropy),
        "patterns": patterns,
        "suggestions": suggestions,
        "checks": [{"label": l, "passed": bool(o)} for l, o in checks],
    }


def summarise(analysis):
    """Short one-line summary used in the history table."""
    return "%d/100 - %s" % (analysis["score"], analysis["verdict"])
