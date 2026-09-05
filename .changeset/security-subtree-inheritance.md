---
"@kilocode/cli": patch
---

Treat removing a directory as a change to everything protected inside it, so deleting a CI directory's parent is held like editing the workflows themselves.
