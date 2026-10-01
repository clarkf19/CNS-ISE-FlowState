"""Protocol foundation shared by every other package.

Nothing outside ``flowstate.core.crypto`` may import the ``cryptography``
library directly (enforced by ``tests/core/test_architecture.py``).
"""
