# Password Restore Application
# Standalone app for recovering forgotten Task Monitor password

import sys
import os
import hashlib
import hmac
import json
import secrets
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (QApplication, QDialog, QVBoxLayout, QHBoxLayout,
                            QLabel, QLineEdit, QPushButton, QMessageBox,
                            QTabWidget, QCheckBox, QWidget, QGroupBox, QFrame)
from PyQt6.QtCore import Qt, QSettings, QUrl
from PyQt6.QtGui import QFont, QDragEnterEvent, QDropEvent
from PyQt6.QtCore import QMimeData


class DraggableLineEdit(QLineEdit):
    """Line edit that supports drag-and-drop for admin override file"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.admin_file_callback = None

    def set_admin_file_callback(self, callback):
        """Set callback function to be called when admin file is dropped"""
        self.admin_file_callback = callback

    def dragEnterEvent(self, event: QDragEnterEvent):
        """Accept drag events with files"""
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        """Accept drag move events with files"""
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        """Handle file drop events"""
        if event.mimeData().hasUrls() and self.admin_file_callback:
            files = [f.toLocalFile() for f in event.mimeData().urls()]
            if files:
                self.admin_file_callback(files[0])
        event.accept()


class PasswordRestoreManager:
    """Manages password restoration operations"""

    def __init__(self):
        self.settings = QSettings("TaskMonitor", "Password")

    def hash_password(self, password):
        """Create a secure hash of the password"""
        return hashlib.sha256(password.encode()).hexdigest()

    # Recovery key verification
    def verify_recovery_key(self, recovery_key):
        """Verify the recovery key"""
        stored_hash = self.settings.value("recovery_key_hash")
        if not stored_hash:
            return False
        entered_hash = self.hash_password(recovery_key)
        return stored_hash == entered_hash

    # Security questions verification
    def get_security_question(self, question_num):
        """Get a stored security question"""
        return self.settings.value(f"security_question_{question_num}")

    def verify_security_answer(self, question_num, answer):
        """Verify a security question answer"""
        stored_hash = self.settings.value(f"security_answer_{question_num}_hash")
        if not stored_hash:
            return False
        entered_hash = self.hash_password(answer.lower().strip())
        return stored_hash == entered_hash

    # Admin file verification
    def verify_admin_file(self, filepath):
        """Verify admin override file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            # HARDCODED ADMIN KEY - must match the one in admin_key_gen.py
            admin_key = "Taras2025"  # CHANGE BEFORE PRODUCTION!

            timestamp = data.get("timestamp", "")
            app_id = data.get("app_id", "")
            signature = data.get("signature", "")

            # Recreate signature data
            signature_data = f"{admin_key}:{timestamp}:{app_id}"
            expected_signature = hmac.new(
                admin_key.encode(),
                signature_data.encode(),
                hashlib.sha256
            ).hexdigest()

            return signature == expected_signature
        except Exception:
            return False

    # Password reset
    def reset_password(self, new_password):
        """Reset the password to a new value"""
        if len(new_password) < 4:
            return False, "Пароль повинен містити щонайменше 4 символи!"
        password_hash = self.hash_password(new_password)
        self.settings.setValue("password_hash", password_hash)
        return True, "Пароль успішно змінено!"

    def is_password_set(self):
        """Check if password has been set"""
        return self.settings.value("password_hash") is not None

    def are_security_questions_set(self):
        """Check if security questions have been set up"""
        q1 = self.settings.value("security_question_1")
        q2 = self.settings.value("security_question_2")
        return q1 is not None and q2 is not None

    def is_legacy_installation(self):
        """Check if this is a legacy installation without recovery key"""
        return self.settings.value("recovery_key_hash") is None

    def has_admin_override_capability(self):
        """Check if admin override is available (always true for any installation)"""
        return True

    # Emergency recovery code (for forgotten passwords on legacy installations)
    EMERGENCY_CODE = "NGIT-2025-RESET"

    def verify_emergency_code(self, code):
        """Verify emergency recovery code"""
        return code == self.EMERGENCY_CODE


class AdminOverrideDialog(QDialog):
    """Hidden dialog for admin override password reset"""

    def __init__(self, restore_manager, parent=None):
        super().__init__(parent)
        self.restore_manager = restore_manager
        self.initUI()

    def initUI(self):
        self.setWindowTitle("🔧 Режим відновлення доступу")
        self.setModal(True)
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title_label = QLabel("Адміністративний доступ підтверджено")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        title_label.setStyleSheet("color: green;")
        layout.addWidget(title_label)

        # Spacer
        layout.addSpacing(15)

        # New password
        new_password_layout = QHBoxLayout()
        new_password_layout.addWidget(QLabel("Новий пароль:"))
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password_input.setPlaceholderText("Введіть новий пароль")
        new_password_layout.addWidget(self.new_password_input)
        layout.addLayout(new_password_layout)

        # Confirm new password
        confirm_password_layout = QHBoxLayout()
        confirm_password_layout.addWidget(QLabel("Підтвердьте:"))
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_input.setPlaceholderText("Підтвердьте пароль")
        confirm_password_layout.addWidget(self.confirm_password_input)
        layout.addLayout(confirm_password_layout)

        layout.addSpacing(10)

        # Buttons
        button_layout = QHBoxLayout()

        cancel_button = QPushButton("Вихід")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        set_button = QPushButton("Встановити")
        set_button.clicked.connect(self.accept)
        set_button.setDefault(True)
        set_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        button_layout.addWidget(set_button)

        layout.addLayout(button_layout)

        self.adjustSize()
        self.new_password_input.setFocus()

    def get_passwords(self):
        return self.new_password_input.text(), self.confirm_password_input.text()

    def accept(self):
        new_password, confirm_password = self.get_passwords()

        if not new_password:
            QMessageBox.warning(self, "Помилка", "Пароль не може бути порожнім!")
            return

        if new_password != confirm_password:
            QMessageBox.warning(self, "Помилка", "Паролі не збігаються!")
            return

        if len(new_password) < 4:
            QMessageBox.warning(self, "Помилка", "Пароль повинен містити щонайменше 4 символи!")
            return

        success, message = self.restore_manager.reset_password(new_password)
        if success:
            QMessageBox.information(self, "Успіх", "Пароль успішно змінено!")
            super().accept()
        else:
            QMessageBox.critical(self, "Помилка", message)


class PasswordRestoreDialog(QDialog):
    """Main dialog for password restoration"""

    def __init__(self, restore_manager, parent=None):
        super().__init__(parent)
        self.restore_manager = restore_manager
        self.verified = False  # Track if user is verified
        self.initUI()

    def initUI(self):
        self.setWindowTitle("🔐 Відновлення паролю")
        self.resize(500, 300)
        self.setMinimumSize(500, 300)
        self.setModal(True)
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)

        layout = QVBoxLayout(self)

        # Title
        title_label = QLabel("Відновлення доступу до програми")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(title_label)

        # Tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Tab 1: Recovery Key
        self.tab1 = self.create_recovery_key_tab()
        self.tab_widget.addTab(self.tab1, "Ключ відновлення")

        # Tab 2: Security Questions (only if set up)
        if self.restore_manager.are_security_questions_set():
            self.tab2 = self.create_security_questions_tab()
            self.tab_widget.addTab(self.tab2, "Питання для працівників")

        # Tab 3: Legacy / Admin Override (for older versions without recovery key)
        if self.restore_manager.is_legacy_installation():
            self.tab3 = self.create_legacy_tab()
            self.tab_widget.addTab(self.tab3, "⚠ Стара версія")
            # Set legacy tab as active for older versions
            self.tab_widget.setCurrentWidget(self.tab3)

        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet("padding: 10px;")
        layout.addWidget(self.status_label)

    def create_recovery_key_tab(self):
        """Create recovery key tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Recovery key input
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("Ключ відновлення:"))
        self.recovery_key_input = DraggableLineEdit()
        self.recovery_key_input.setPlaceholderText("Введіть ключ або перетягніть файл")
        self.recovery_key_input.set_admin_file_callback(self.on_admin_file_dropped)
        key_layout.addWidget(self.recovery_key_input)
        layout.addLayout(key_layout)

        layout.addSpacing(10)

        # Verify button (shown initially)
        self.verify_key_button = QPushButton("Перевірити ключ")
        self.verify_key_button.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        self.verify_key_button.clicked.connect(self.verify_recovery_key)
        layout.addWidget(self.verify_key_button)

        # Password group (hidden initially)
        self.key_password_group = QGroupBox("Встановіть новий пароль:")
        key_password_layout = QVBoxLayout()

        # New password
        new_password_layout = QHBoxLayout()
        new_password_layout.addWidget(QLabel("Новий пароль:"))
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password_input.setPlaceholderText("Введіть новий пароль")
        new_password_layout.addWidget(self.new_password_input)
        key_password_layout.addLayout(new_password_layout)

        # Confirm new password
        confirm_password_layout = QHBoxLayout()
        confirm_password_layout.addWidget(QLabel("Підтвердьте:"))
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_input.setPlaceholderText("Підтвердьте пароль")
        confirm_password_layout.addWidget(self.confirm_password_input)
        key_password_layout.addLayout(confirm_password_layout)

        # Restore button (hidden initially)
        self.restore_key_button = QPushButton("Змінити пароль")
        self.restore_key_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        self.restore_key_button.clicked.connect(self.restore_with_key)
        key_password_layout.addWidget(self.restore_key_button)

        self.key_password_group.setLayout(key_password_layout)
        self.key_password_group.hide()  # Hide initially
        layout.addWidget(self.key_password_group)

        # Cancel button
        cancel_button = QPushButton("Скасувати")
        cancel_button.clicked.connect(self.reject)
        layout.addWidget(cancel_button)

        layout.addStretch()
        return widget

    def create_security_questions_tab(self):
        """Create security questions tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Question 1
        q1 = self.restore_manager.get_security_question(1)
        q1_layout = QVBoxLayout()
        q1_label = QLabel(f"Питання 1: {q1}")
        q1_label.setWordWrap(True)
        q1_layout.addWidget(q1_label)
        self.answer1_input = QLineEdit()
        self.answer1_input.setPlaceholderText("Ваша відповідь...")
        self.answer1_input.setEchoMode(QLineEdit.EchoMode.Password)
        q1_layout.addWidget(self.answer1_input)
        layout.addLayout(q1_layout)

        # Question 2
        q2 = self.restore_manager.get_security_question(2)
        q2_layout = QVBoxLayout()
        q2_label = QLabel(f"Питання 2: {q2}")
        q2_label.setWordWrap(True)
        q2_layout.addWidget(q2_label)
        self.answer2_input = QLineEdit()
        self.answer2_input.setPlaceholderText("Ваша відповідь...")
        self.answer2_input.setEchoMode(QLineEdit.EchoMode.Password)
        q2_layout.addWidget(self.answer2_input)
        layout.addLayout(q2_layout)

        layout.addSpacing(10)

        # Verify button (shown initially)
        self.verify_questions_button = QPushButton("Перевірити відповіді")
        self.verify_questions_button.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        self.verify_questions_button.clicked.connect(self.verify_security_questions)
        layout.addWidget(self.verify_questions_button)

        # Password group (hidden initially)
        self.questions_password_group = QGroupBox("Встановіть новий пароль:")
        questions_password_layout = QVBoxLayout()

        # New password
        new_password_layout = QHBoxLayout()
        new_password_layout.addWidget(QLabel("Новий пароль:"))
        self.sq_new_password_input = QLineEdit()
        self.sq_new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.sq_new_password_input.setPlaceholderText("Введіть новий пароль")
        new_password_layout.addWidget(self.sq_new_password_input)
        questions_password_layout.addLayout(new_password_layout)

        # Confirm new password
        confirm_password_layout = QHBoxLayout()
        confirm_password_layout.addWidget(QLabel("Підтвердьте:"))
        self.sq_confirm_password_input = QLineEdit()
        self.sq_confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.sq_confirm_password_input.setPlaceholderText("Підтвердьте пароль")
        confirm_password_layout.addWidget(self.sq_confirm_password_input)
        questions_password_layout.addLayout(confirm_password_layout)

        # Restore button (hidden initially)
        self.restore_questions_button = QPushButton("Змінити пароль")
        self.restore_questions_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        self.restore_questions_button.clicked.connect(self.restore_with_questions)
        questions_password_layout.addWidget(self.restore_questions_button)

        self.questions_password_group.setLayout(questions_password_layout)
        self.questions_password_group.hide()  # Hide initially
        layout.addWidget(self.questions_password_group)

        # Cancel button
        cancel_button = QPushButton("Скасувати")
        cancel_button.clicked.connect(self.reject)
        layout.addWidget(cancel_button)

        layout.addStretch()
        return widget

    def create_legacy_tab(self):
        """Create legacy installation tab (for older versions without recovery key)"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Warning box
        warning_group = QGroupBox("⚠️ Виялено стару версію програми")
        warning_layout = QVBoxLayout()

        warning_text = QLabel(
            "У цій версії не налаштовано ключ відновлення.\n\n"
            "Зверніться до системного адміністратора для відновлення доступу."
        )
        warning_text.setWordWrap(True)
        warning_text.setStyleSheet("padding: 10px; font-weight: bold;")
        warning_layout.addWidget(warning_text)

        warning_group.setLayout(warning_layout)
        layout.addWidget(warning_group)

        # Admin file drop zone (undocumented - invisible but functional)
        self.legacy_admin_input = DraggableLineEdit()
        self.legacy_admin_input.setPlaceholderText("")
        self.legacy_admin_input.setReadOnly(True)
        self.legacy_admin_input.set_admin_file_callback(self.on_legacy_admin_file_dropped)
        self.legacy_admin_input.setStyleSheet("background-color: transparent; border: none;")
        layout.addWidget(self.legacy_admin_input)

        layout.addStretch()

        # Contact support
        support_text = QLabel("Зверніться до системного адміністратора")
        support_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        support_text.setStyleSheet("padding: 10px; color: #666;")
        layout.addWidget(support_text)

        # Cancel button
        cancel_button = QPushButton("Скасувати")
        cancel_button.clicked.connect(self.reject)
        layout.addWidget(cancel_button)

        return widget

    def on_legacy_admin_file_dropped(self, filepath):
        """Handle admin file drop event from legacy tab"""
        if self.restore_manager.verify_admin_file(filepath):
            # Show admin override dialog
            admin_dialog = AdminOverrideDialog(self.restore_manager, self)
            admin_dialog.exec()
            if admin_dialog.result() == QDialog.DialogCode.Accepted:
                self.accept()
            else:
                # User cancelled - close app
                self.reject()
        else:
            QMessageBox.warning(self, "Помилка",
                "Невірний адміністративний файл!\n\n"
                "Переконайтеся, що:\n"
                "1. Файл створений для цієї установки програми\n"
                "2. Файл не був змінений")

    def verify_emergency_code(self):
        """Verify emergency code and show password fields"""
        self.clear_status()
        code = self.emergency_code_input.text().strip()

        if not code:
            self.show_status("Введіть код відновлення!", True)
            return

        if not self.restore_manager.verify_emergency_code(code):
            self.show_status("Невірний код відновлення!", True)
            return

        # Code verified - show password fields
        self.verify_emergency_button.hide()
        self.emergency_password_group.show()
        self.emergency_code_input.setReadOnly(True)
        self.show_status("Код прийнято! Тепер встановіть новий пароль.", False)
        self.emerg_new_password_input.setFocus()

    def restore_with_emergency_code(self):
        """Restore password using emergency code (after verification)"""
        new_password = self.emerg_new_password_input.text()
        confirm_password = self.emerg_confirm_password_input.text()

        if not new_password:
            self.show_status("Введіть новий пароль!", True)
            return

        if new_password != confirm_password:
            self.show_status("Паролі не збігаються!", True)
            return

        if len(new_password) < 4:
            self.show_status("Пароль повинен містити щонайменше 4 символи!", True)
            return

        # Reset password
        success, message = self.restore_manager.reset_password(new_password)
        if success:
            QMessageBox.information(self, "Успіх",
                "Пароль успішно змінено через термінове відновлення!\n\n"
                "Тепер ви можете увійти, використовуючи новий пароль.\n\n"
                "Рекомендується встановити ключ відновлення в налаштуваннях.")
            self.accept()
        else:
            self.show_status(message, True)

    def show_status(self, message, is_error=False):
        """Show status message"""
        color = "red" if is_error else "green"
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"padding: 10px; color: {color}; font-weight: bold;")

    def clear_status(self):
        """Clear status message"""
        self.status_label.setText("")
        self.status_label.setStyleSheet("padding: 10px;")

    def on_admin_file_dropped(self, filepath):
        """Handle admin file drop event"""
        if self.restore_manager.verify_admin_file(filepath):
            # Show admin override dialog
            admin_dialog = AdminOverrideDialog(self.restore_manager, self)
            admin_dialog.exec()
            if admin_dialog.result() == QDialog.DialogCode.Accepted:
                self.accept()
            else:
                # User cancelled - close app
                self.reject()
        else:
            self.show_status("Невірний файл адміністративного ключа!", True)

    def verify_recovery_key(self):
        """Verify recovery key and show password fields"""
        self.clear_status()
        recovery_key = self.recovery_key_input.text().strip()

        if not recovery_key:
            self.show_status("Введіть ключ відновлення!", True)
            return

        if not self.restore_manager.verify_recovery_key(recovery_key):
            self.show_status("Невірний ключ відновлення!", True)
            return

        # Key verified - show password fields
        self.verified = True
        self.verify_key_button.hide()
        self.key_password_group.show()
        self.recovery_key_input.setReadOnly(True)
        self.show_status("Ключ підтверджено! Тепер встановіть новий пароль.", False)
        self.new_password_input.setFocus()
        self.adjustSize()  # Resize window to fit new content

    def verify_security_questions(self):
        """Verify security answers and show password fields"""
        self.clear_status()
        answer1 = self.answer1_input.text().strip()
        answer2 = self.answer2_input.text().strip()

        if not answer1 or not answer2:
            self.show_status("Введіть відповіді на обидва питання!", True)
            return

        if not self.restore_manager.verify_security_answer(1, answer1):
            self.show_status("Невірна відповідь на перше питання!", True)
            return

        if not self.restore_manager.verify_security_answer(2, answer2):
            self.show_status("Невірна відповідь на друге питання!", True)
            return

        # Answers verified - show password fields
        self.verified = True
        self.verify_questions_button.hide()
        self.questions_password_group.show()
        self.answer1_input.setReadOnly(True)
        self.answer2_input.setReadOnly(True)
        self.show_status("Відповіді підтверджено! Тепер встановіть новий пароль.", False)
        self.sq_new_password_input.setFocus()
        self.adjustSize()  # Resize window to fit new content

    def restore_with_key(self):
        """Restore password using recovery key (after verification)"""
        new_password = self.new_password_input.text()
        confirm_password = self.confirm_password_input.text()

        if not new_password:
            self.show_status("Введіть новий пароль!", True)
            return

        if new_password != confirm_password:
            self.show_status("Паролі не збігаються!", True)
            return

        if len(new_password) < 4:
            self.show_status("Пароль повинен містити щонайменше 4 символи!", True)
            return

        # Reset password
        success, message = self.restore_manager.reset_password(new_password)
        if success:
            QMessageBox.information(self, "Успіх",
                "Пароль успішно змінено!\n\nТепер ви можете увійти, використовуючи новий пароль.")
            self.accept()
        else:
            self.show_status(message, True)

    def restore_with_questions(self):
        """Restore password using security questions (after verification)"""
        new_password = self.sq_new_password_input.text()
        confirm_password = self.sq_confirm_password_input.text()

        if not new_password:
            self.show_status("Введіть новий пароль!", True)
            return

        if new_password != confirm_password:
            self.show_status("Паролі не збігаються!", True)
            return

        if len(new_password) < 4:
            self.show_status("Пароль повинен містити щонайменше 4 символи!", True)
            return

        # Reset password
        success, message = self.restore_manager.reset_password(new_password)
        if success:
            QMessageBox.information(self, "Успіх",
                "Пароль успішно змінено!\n\nТепер ви можете увійти, використовуючи новий пароль.")
            self.accept()
        else:
            self.show_status(message, True)


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    # Initialize restore manager
    restore_manager = PasswordRestoreManager()

    # Check if password is set
    if not restore_manager.is_password_set():
        QMessageBox.critical(None, "Помилка",
            "Програма Task Monitor не налаштована!\n\n"
            "Спочатку запустіть основну програму для встановлення пароля.")
        sys.exit(1)

    # Show restore dialog
    restore_dialog = PasswordRestoreDialog(restore_manager)

    if restore_dialog.exec() == QDialog.DialogCode.Accepted:
        # Password was successfully restored
        sys.exit(0)
    else:
        # User cancelled
        sys.exit(0)


if __name__ == "__main__":
    main()
