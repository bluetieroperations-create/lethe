"""Synthetic candidate data for the demo. A tiny keyword 'embedding' over a fixed
vocab so the semantic search is real and explainable with ZERO ML dependencies —
the deletion behavior is identical to a real model. Swap embed() for your real
embedder when demoing on a prospect's stack."""

VOCAB = [
    "senior", "junior", "staff", "react", "vue", "python", "golang", "java",
    "frontend", "backend", "fullstack", "ml", "data", "devops",
    "berlin", "london", "amsterdam", "remote",
    "fintech", "health", "ecommerce", "designer", "nurse", "sales",
]
DIM = len(VOCAB)


def embed(text: str):
    t = text.lower()
    return [1.0 if term in t else 0.0 for term in VOCAB]


CANDIDATES = [
    {"id": "cand-alice", "subject": "alice.chen@demo.test", "name": "Alice Chen",
     "text": "Senior React frontend engineer, Berlin, fintech"},
    {"id": "cand-bob", "subject": "bob.marsh@demo.test", "name": "Bob Marsh",
     "text": "Backend Golang engineer, London, health"},
    {"id": "cand-carol", "subject": "carol.diaz@demo.test", "name": "Carol Diaz",
     "text": "Senior ML data engineer, remote, python"},
]
