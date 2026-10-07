#!/usr/bin/env python
"""Fail if any translatable string is missing, untranslated, or fuzzy.

Runs makemessages to pick up strings not yet extracted, checks the result,
then restores the .po files so the working tree is left untouched.
"""

import os
import sys
from pathlib import Path

import django
import polib
from django.conf import settings
from django.core.management import call_command

BASE_DIR = Path(__file__).resolve().parent.parent
LOCALE_DIR = BASE_DIR / "locale"

DOMAINS = {
    "django": ["node_modules", "theme/static_src/*", "staticfiles/*", ".venv/*"],
    "djangojs": ["node_modules", "theme/*", "staticfiles/*", ".venv/*"],
}


def main():
    os.chdir(BASE_DIR)
    sys.path.insert(0, str(BASE_DIR))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "psst_secret.settings")
    os.environ.setdefault("DEBUG", "True")
    django.setup()

    source_lang = settings.LANGUAGE_CODE.split("-")[0]
    languages = [code for code, _ in settings.LANGUAGES if code != source_lang]

    backup = {p: p.read_bytes() for p in LOCALE_DIR.rglob("*.po")}
    problems = []
    try:
        for domain, ignore in DOMAINS.items():
            call_command(
                "makemessages",
                locale=languages,
                domain=domain,
                ignore_patterns=ignore,
                verbosity=0,
            )
        for lang in languages:
            for domain in DOMAINS:
                po_path = LOCALE_DIR / lang / "LC_MESSAGES" / f"{domain}.po"
                if not po_path.exists():
                    continue
                for entry in polib.pofile(str(po_path)):
                    if entry.obsolete or entry.translated():
                        continue
                    state = "fuzzy" if entry.fuzzy else "untranslated"
                    where = entry.occurrences[0][0] if entry.occurrences else "?"
                    problems.append(
                        f"{po_path.relative_to(BASE_DIR)}: {state}: "
                        f"{entry.msgid[:70]!r} ({where})"
                    )
    finally:
        for path in LOCALE_DIR.rglob("*.po"):
            if path in backup:
                path.write_bytes(backup[path])
            else:
                path.unlink()

    if problems:
        print("Missing translations:")
        print("\n".join(f"  {p}" for p in problems))
        print("\nRun makemessages, translate the entries above, then compilemessages.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
