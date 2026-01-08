import PyInstaller.__main__
import os
import sys
import shutil

def cleanup_build_artifacts():
    """Remove build artifacts from previous builds"""
    print("Cleaning up build artifacts...")

    artifacts = [
        'build',
        'dist',
        '__pycache__',
        'TaskMonitor.spec',
        'PasswordRestore.spec',
        'AdminKeyGen.spec',
    ]

    for artifact in artifacts:
        if os.path.exists(artifact):
            if os.path.isdir(artifact):
                shutil.rmtree(artifact)
                print(f"  ✓ Removed directory: {artifact}/")
            else:
                os.remove(artifact)
                print(f"  ✓ Removed file: {artifact}")

    # Clean up Python cache files recursively
    for root, dirs, files in os.walk('.'):
        # Don't visit hidden directories or __pycache__
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']

        # Remove __pycache__ directories
        if '__pycache__' in dirs:
            pycache_path = os.path.join(root, '__pycache__')
            shutil.rmtree(pycache_path)
            print(f"  ✓ Removed cache: {pycache_path}/")

        # Remove .pyc files
        for file in files:
            if file.endswith('.pyc'):
                pyc_path = os.path.join(root, file)
                os.remove(pyc_path)
                print(f"  ✓ Removed cache: {pyc_path}")

    print("Cleanup complete!\n")

# Check if --clean flag was passed
if '--clean' in sys.argv:
    cleanup_build_artifacts()
    sys.exit(0)

# Always cleanup before building for a fresh build
cleanup_build_artifacts()

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

# Build admin key generator (console application)
print("\nBuilding AdminKeyGen...")
PyInstaller.__main__.run([
    'admin_key_gen.py',
    '--onefile',
    '--console',
    '--name=AdminKeyGen',
])

# Post-build cleanup: remove build/ folder, keeping only dist/
print("\nCleaning up intermediate build files...")
if os.path.exists('build'):
    shutil.rmtree('build')
    print("  ✓ Removed build/ directory")

# Clean up .spec files
spec_files = ['TaskMonitor.spec', 'PasswordRestore.spec', 'AdminKeyGen.spec']
for spec_file in spec_files:
    if os.path.exists(spec_file):
        os.remove(spec_file)
        print(f"  ✓ Removed {spec_file}")

print("\n" + "="*50)
print("Build complete!")
print("="*50)
print("\nOutput folder: dist/")
print("  • TaskMonitor.exe - Main application")
print("  • PasswordRestore.exe - Password restore tool")
print("  • AdminKeyGen.exe - Admin key generator")
