"""Unit tests for NIST OSCAL catalog parsing.

These exercise ``parse_oscal`` against a tiny inline OSCAL fixture so the
parsing contract is verified without any network access or model download.
The fixture mirrors the real catalog's shape: a group containing a control
that itself nests a control enhancement, each carrying a ``statement`` part.
"""
from app.nist import parse_oscal

# Minimal OSCAL catalog: one group -> one control -> one enhancement.
FIXTURE = {
    "catalog": {
        "groups": [
            {
                "id": "si",
                "controls": [
                    {
                        "id": "si-2",
                        "title": "Flaw Remediation",
                        "parts": [
                            {"name": "statement", "prose": "Identify, report, and correct system flaws."}
                        ],
                        "controls": [
                            {
                                "id": "si-2.1",
                                "title": "Automated Flaw Remediation Status",
                                "parts": [
                                    {"name": "statement", "prose": "Determine status using automated mechanisms."}
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
}


def test_parse_flattens_controls_and_enhancements():
    """Both a base control and its nested enhancement are returned, flattened."""
    controls = parse_oscal(FIXTURE)

    ids = {c["id"] for c in controls}
    assert "si-2" in ids
    assert "si-2.1" in ids


def test_parse_extracts_statement_prose_and_title():
    """A control's statement prose and human title are captured verbatim."""
    controls = parse_oscal(FIXTURE)

    si2 = next(c for c in controls if c["id"] == "si-2")
    assert si2["title"] == "Flaw Remediation"
    assert "correct system flaws" in si2["text"]


def test_parse_captures_enhancement_prose():
    """Enhancement prose is extracted independently of its parent control."""
    controls = parse_oscal(FIXTURE)

    enhancement = next(c for c in controls if c["id"] == "si-2.1")
    assert "automated mechanisms" in enhancement["text"].lower()


# OSCAL embeds organization-defined parameters as placeholders in the prose and
# defines their human labels in a sibling ``params`` list.
PARAM_FIXTURE = {
    "catalog": {
        "groups": [
            {
                "id": "si",
                "controls": [
                    {
                        "id": "si-2",
                        "title": "Flaw Remediation",
                        "params": [
                            {"id": "si-02_odp", "label": "time period"},
                            {
                                "id": "si-02_sel",
                                "select": {"choice": ["remove", "disable"]},
                            },
                        ],
                        "parts": [
                            {
                                "name": "statement",
                                "prose": (
                                    "Install updates within {{ insert: param, si-02_odp }} "
                                    "and {{ insert: param, si-02_sel }} the component."
                                ),
                            }
                        ],
                    }
                ],
            }
        ]
    }
}


def test_parse_resolves_assignment_and_selection_parameters():
    """Parameter placeholders are rendered as readable assignment/selection text."""
    controls = parse_oscal(PARAM_FIXTURE)

    si2 = next(c for c in controls if c["id"] == "si-2")
    assert "[assignment: time period]" in si2["text"]
    assert "[selection: remove; disable]" in si2["text"]


def test_parse_leaves_no_raw_placeholder():
    """No raw ``{{ ... }}`` placeholder survives parsing, even for unknown ids."""
    fixture = {
        "catalog": {
            "controls": [
                {
                    "id": "xx-1",
                    "title": "Unknown Param",
                    "parts": [
                        {
                            "name": "statement",
                            "prose": "Act within {{ insert: param, undefined_odp }}.",
                        }
                    ],
                }
            ]
        }
    }

    controls = parse_oscal(fixture)

    assert "{{" not in controls[0]["text"]
    assert "[assignment: organization-defined value]" in controls[0]["text"]
