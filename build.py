import PyInstaller.__main__
import os
import sys

# Build main application
print("Building TaskMonitor...")
PyInstaller.__main__.run([
    'task_monitor.py',
    '--onefile',
    '--windowed',
    '--noconsole',
    '--name=TaskMonitor',
])

# Build password restore application
print("\nBuilding PasswordRestore...")
PyInstaller.__main__.run([
    'password_restore.py',
    '--onefile',
    '--windowed',
    '--noconsole',
    '--name=PasswordRestore',
])
