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
        print("Спочатку запустіть TaskMonitor для встановлення пароля.")
        input("\nНатисніть Enter для виходу...")
        sys.exit(1)

    print("Інсталяція TaskMonitor виявлено.")
    print()
    print("ПОПЕРЕДЖЕННЯ: Адміністративний ключ дозволяє відновити доступ")
    print("без знання поточного пароля. Використовуйте обережно!")
    print()

    # Prompt for admin key
    while True:
        admin_key = input("Введіть адміністративний ключ: ").strip()
        if len(admin_key) >= 4:
            break
        print("Помилка: Ключ повинен містити щонайменше 4 символи.")

    # Confirm admin key
    admin_key_confirm = input("Підтвердьте адміністративний ключ: ").strip()
    if admin_key != admin_key_confirm:
        print("\nПомилка: Ключі не співпадають!")
        input("\nНатисніть Enter для виходу...")
        sys.exit(1)

    print("\nГенерація адміністративного файлу...")

    # Generate admin key file with user-provided admin key
    timestamp = datetime.now().isoformat()
    app_id = "TaskMonitor"

    # Hash the admin key for storage (security - never store raw key)
    admin_key_hash = hashlib.sha256(admin_key.encode()).hexdigest()

    # Create signature using the admin key as the secret
    signature_data = f"{admin_key}:{timestamp}:{app_id}"
    signature = hmac.new(admin_key.encode(), signature_data.encode(), hashlib.sha256).hexdigest()

    # File content
    file_content = {
        "signature": signature,
        "admin_key_hash": admin_key_hash,
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
        print(f"\nУспіх! Адміністративний ключ створено:")
        print(f"Шлях: {output_path}")
        print()
        print("Використання:")
        print("1. Запустіть PasswordRestore.exe")
        print("2. Перетягніть цей файл у вікно програми")
        print()
    except Exception as e:
        print(f"\nПомилка при створенні файлу: {e}")
        input("\nНатисніть Enter для виходу...")
        sys.exit(1)

    input("Натисніть Enter для виходу...")

if __name__ == "__main__":
    main()
