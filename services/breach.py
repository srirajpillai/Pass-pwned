"""
Breach lookup using the Have I Been Pwned *range* API (k-anonymity).

The full SHA-1 digest never leaves the machine.  Only the first five
characters of the digest are transmitted; the comparison against the returned
suffixes happens locally.
"""

import hashlib
import time

import requests

from config import Config

# --------------------------------------------------------------------------- #
#  offline fallback corpus
# --------------------------------------------------------------------------- #
# SHA-1 (upper case) of a handful of publicly known breached passwords.  It is
# used only when the machine running the project has no internet access, so
# that the breach feature stays demonstrable in a lab / viva setting.
OFFLINE_BREACHED_SHA1 = {
    "7C4A8D09CA3762AF61E59520943DC26494F8941B",
    "F7C3BC1D808E04732ADF679965CCC34CA7AE3441",
    "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
    "B1B3773A05C0ED0176787A4F1574FF0075F7521E",
    "7C222FB2927D828AF22F592134E8932480637C0D",
    "3D4F2BF07DC1BE38B20CD6E46949A1071F9D0E3D",
    "01B307ACBA4F54F55AAFC33BB06BBBF6CA803E9A",
    "20EABE5D64B0E216796E834F52D61FD0B70332FC",
    "E38AD214943DAAD1D64C102FAEC29DE4AFE9DA3D",
    "6367C48DD193D56EA7B0BAAD25B19455E529F5EE",
    "D033E22AE348AEB5660FC2140AEC35850C4DA997",
    "C0B137FE2D792459F26FF763CCE44574A5B5AB03",
    "AB87D24BDC7452E55738DEB5F868E1F16DEA5ACE",
    "B7A875FC1EA228B9061041B7CEC4BD3C52AB3CE3",
    "AF8978B1797B72ACFFF9595A5A2A373EC3D9106D",
    "8D6E34F987851AA599257D3831A1AF040886842F",
    "775BB961B81DA1CA49217A48E533C832C337154A",
    "2D27B62C597EC858F6E7B54E7E58525E6A95E6D8",
    "EE8D8728F435FD550F83852AABAB5234CE1DA528",
    "ED9D3D832AF899035363A69FD53CD3BE8F71501C",
    "4F26AEAFDB2367620A393C973EDDBE8F8B846EBD",
    "18C28604DD31094A8D69DAE60F1BCD347F1AFC5A",
    "E68E11BE8B70E435C65AEF8BA9798FF7775C361E",
    "C984AED014AEC7623A54F0591DA07A85FD4B762D",
    "5CEC175B165E3D5E62C9E13CE848EF6FEAC81BFF",
    "25C2C9AFDD83B8D34234AA2881CC341C09689AAA",
    "EBFC7910077770C8340F63CD2DCA2AC1F120444F",
    "E074138D45B0494966B85AB2E31FA7BA0684F43B",
    "9F8C93C9264008118450E03BD2772CA1B18EDFED",
    "8CB2237D0679CA88DB6464EAC60DA96345513964",
    "601F1889667EFAEBB33B8C12572835DA3F027F78",
    "48EFC4851E15940AF5D477D3C0CE99211A70A3BE",
    "B0399D2029F64D445BD131FFAA399A42D2F8E7DC",
    "93EC71B22793A81569C94CA17E4D9C293D8E201F",
}

# simple in-process cache : prefix -> (expires_at, suffixes dict)
_CACHE = {}


# --------------------------------------------------------------------------- #
def sha1_hex(password):
    """Upper case SHA-1 digest of `password`."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_digest(digest):
    """Return (prefix, suffix) for a k-anonymity range query."""
    return digest[:5], digest[5:]


# --------------------------------------------------------------------------- #
def fetch_range(prefix):
    """Return the suffix -> count mapping for a 5 character SHA-1 prefix.

    Response: (suffixes: dict, source: str)
    `source` is one of "hibp" (live), "offline" (local corpus) or
    "unavailable" (no data at all).
    """
    prefix = (prefix or "").upper()
    if len(prefix) != 5:
        raise ValueError("prefix must be exactly 5 hexadecimal characters")

    now = time.time()
    hit = _CACHE.get(prefix)
    if hit and hit[0] > now:
        return hit[1], hit[2]

    try:
        resp = requests.get(
            Config.HIBP_RANGE_URL + prefix,
            timeout=Config.HIBP_TIMEOUT,
            headers={"User-Agent": Config.HIBP_USER_AGENT},
        )
        if resp.status_code == 200:
            suffixes = {}
            for line in resp.text.splitlines():
                line = line.strip()
                if ":" in line:
                    sfx, _, cnt = line.partition(":")
                    try:
                        suffixes[sfx.upper()] = int(cnt)
                    except ValueError:
                        continue
            _CACHE[prefix] = (now + Config.RANGE_CACHE_TTL, suffixes, "hibp")
            return suffixes, "hibp"
    except Exception:
        pass                                    # fall through to offline mode

    # ---- offline -----------------------------------------------------------
    offline = {}
    for digest in OFFLINE_BREACHED_SHA1:
        if digest.startswith(prefix):
            offline[digest[5:]] = 1
    _CACHE[prefix] = (now + 60, offline, "offline")
    return offline, "offline"


def check_breach(password):
    """Full server-side k-anonymity check (used by tests and the CLI)."""
    digest = sha1_hex(password)
    prefix, suffix = split_digest(digest)
    suffixes, source = fetch_range(prefix)
    if source == "unavailable":
        return {"available": False, "breached": None, "count": 0,
                "source": "unavailable", "prefix": prefix}
    count = suffixes.get(suffix, 0)
    return {"available": True,
            "breached": count > 0,
            "count": count,
            "source": "hibp" if source == "hibp" else "offline-corpus",
            "prefix": prefix}
