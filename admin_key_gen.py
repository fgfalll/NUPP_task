# Admin Key Generator for Task Monitor
# Run this to generate an admin override file

import sys
import os
import hashlib
import hmac
import json
from datetime import datetime

from PyQt6.QtCore import QSettings

def main():
    print("=" * 50)
    print("Генерація адміністративного ключа Task Monitor")
    print("=" * 50)
    print()

    # Initialize password manager
    settings = QSettings("TaskMonitor", "Password")

    # Check if password is set
    password_hash = settings.value("password_hash")
    if not password_hash:
        print("Помилка: Пароль не встановлено.")
        input("\nНатисніть Enter для виходу...")
        sys.exit(1)

    print("ПОПЕРЕДЖЕННЯ: Адміністративний ключ дозволяє відновити")
    print("доступ без знання поточного пароля.")
    print()

    # Prompt for admin key
    admin_key = input("Введіть адміністративний ключ: ").strip()
    if not admin_key or len(admin_key) < 4:
        print("\nПомилка: Ключ повинен містити щонайменше 4 символи.")
        input("\nНатисніть Enter для виходу...")
        sys.exit(1)

    # HARDCODED EXPECTED KEY - must match the one in password_restore.py
    expected_key = "Taras2025"  # CHANGE BEFORE PRODUCTION!

    if admin_key != expected_key:
        print("\nПомилка: Невірний адміністративний ключ.")
        input("\nНатисніть Enter для виходу...")
        sys.exit(1)

    # Generate admin key file
    timestamp = datetime.now().isoformat()
    app_id = "TaskMonitor"

    # Create signature using the admin key as the secret
    signature_data = f"{admin_key}:{timestamp}:{app_id}"
    signature = hmac.new(admin_key.encode(), signature_data.encode(), hashlib.sha256).hexdigest()

    # File content
    file_content = {
        "signature": signature,
        "timestamp": timestamp,
        "app_id": app_id
    }

    # Get output filename
    output_filename = ".task_monitor_admin.key"
    if len(sys.argv) > 1:
        # Check if next arg is not a flag
        potential_file = sys.argv[1]
        if not potential_file.startswith('-'):
            output_filename = potential_file

    # Save to file - in same directory as the exe
    if getattr(sys, 'frozen', False):
        # Running as compiled exe
        exe_dir = os.path.dirname(sys.executable)
    else:
        # Running as script
        exe_dir = os.path.dirname(os.path.abspath(__file__))

    output_path = os.path.join(exe_dir, output_filename)
    try:
        with open(output_path, 'w') as f:
            json.dump(file_content, f, indent=2)
        print("\nГотово.")
    except Exception as e:
        print(f"\nПомилка при створенні файлу: {e}")
        input("\nНатисніть Enter для виходу...")
        sys.exit(1)

    input("Натисніть Enter для виходу...")

if __name__ == "__main__":
    main()
