import PyInstaller.__main__

PyInstaller.__main__.run([
    'task_monitor.py',
    '--onefile',
    '--windowed',
    '--noconsole',
    '--name=TaskMonitor',
])
