---
title: picklelens
emoji: 🥒
colorFrom: blue
colorTo: red
sdk: gradio
app_file: app.py
pinned: false
short_description: Is this AI model file safe to load? Static pickle scanner.
---

# picklelens

Upload an ML model file (`.pkl .pt .pth .bin .ckpt .npy .npz .keras .h5 .7z`)
and see what it would run when loaded — **without loading it**.

picklelens reads the pickle opcode stream statically, resolves what it would
actually call (seeing through reflection and alias tricks), and classifies the
behavior — ransomware, infostealer, reverse shell, dropper, persistence — with
MITRE ATT&CK tags and extracted indicators. Nothing is ever executed or
deserialized.

Source and full test suite: https://github.com/Fatemeh-Najafi1/picklelens
