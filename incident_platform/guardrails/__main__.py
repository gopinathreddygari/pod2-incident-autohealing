"""python -m guardrails "some text" [--ner off|heuristic|spacy]

Prints every PII finding with the layer that detected it (regex / heuristic-ner / spacy-ner).
"""

from .pii_detector import main

main()
