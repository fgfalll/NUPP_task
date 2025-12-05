# Task Monitor Application
# Author: Petrenko Taras Sergiyovich

import sys
import os
import requests
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QLabel, QLineEdit, QPushButton,
                            QTableWidget, QTableWidgetItem, QMessageBox,
                            QTabWidget, QHeaderView, QCheckBox,
                            QProgressBar, QFileDialog, QToolBar, QSplitter, QDialog, QGroupBox, QGridLayout, QTextEdit, QSizePolicy)
from PyQt6.QtCore import QMimeData
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings, QUrl
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt6.QtGui import QFont, QColor, QIcon, QPixmap, QDesktopServices, QAction
from PyQt6.QtWidgets import QToolButton
from PyQt6.QtNetwork import QNetworkRequest, QNetworkReply
from bs4 import BeautifulSoup
import json
import hashlib
import base64
from datetime import datetime
import os
import urllib.parse
import webbrowser
import re
import time
import pickle
from pathlib import Path

class TaskTracker:
    """Manages task tracking and archiving functionality"""

    def __init__(self):
        self.app_data_dir = Path.home() / '.task_monitor'
        self.app_data_dir.mkdir(exist_ok=True)
        self.archive_file = self.app_data_dir / 'task_archive.json'
        self.current_tasks_file = self.app_data_dir / 'current_tasks.pkl'
        self.archived_tasks = self.load_archive()
        self.current_known_tasks = self.load_current_tasks()
        self.recently_archived_tasks = set()  # Track tasks archived in current session

    def load_archive(self):
        """Load archived tasks from file"""
        try:
            if self.archive_file.exists():
                with open(self.archive_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading archive: {e}")
        return {}

    def save_archive(self):
        """Save archived tasks to file"""
        try:
            with open(self.archive_file, 'w', encoding='utf-8') as f:
                json.dump(self.archived_tasks, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Error saving archive: {e}")

    def load_current_tasks(self):
        """Load current known tasks from file"""
        try:
            if self.current_tasks_file.exists():
                with open(self.current_tasks_file, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            print(f"Error loading current tasks: {e}")
        return {}

    def save_current_tasks(self):
        """Save current known tasks to file"""
        try:
            with open(self.current_tasks_file, 'wb') as f:
                pickle.dump(self.current_known_tasks, f)
        except Exception as e:
            print(f"Error saving current tasks: {e}")

    def get_task_key(self, task):
        """Generate unique key for task identification"""
        # Use task_id if available, otherwise use combination of task_name and dates
        if task.get('task_id'):
            return f"id_{task['task_id']}"
        else:
            # Create hash from task_name and dates for identification
            content = f"{task.get('task_name', '')}_{task.get('dates', '')}"
            return f"hash_{hashlib.md5(content.encode()).hexdigest()[:16]}"

    def compare_tasks(self, task1, task2):
        """Compare two tasks to see if they are the same (ignoring percentage and status)"""
        # Compare essential fields that don't change
        fields_to_compare = ['task_name', 'task_description', 'dates']
        for field in fields_to_compare:
            if task1.get(field, '') != task2.get(field, ''):
                return False
        return True

    def identify_new_tasks(self, current_tasks):
        """Identify new tasks compared to previously known tasks"""
        new_tasks = []

        # First, archive overdue tasks BEFORE checking for new tasks
        # This prevents archived tasks from being detected as "new"
        overdue_archived = self.archive_overdue_tasks_new(current_tasks)

        # Archive 100% complete tasks
        completed_archived = self.archive_completed_tasks(current_tasks)

        # Archive tasks that are no longer in current tasks
        self.archive_old_tasks(current_tasks)

        # Now check for new tasks after archiving is complete
        for task in current_tasks:
            task_key = self.get_task_key(task)

            # Skip if this task was just archived
            if task_key not in self.current_known_tasks:
                # Check if this task was recently archived (in current session)
                if task_key not in self.recently_archived_tasks:
                    # This is a truly new task
                    new_tasks.append(task)
                    self.current_known_tasks[task_key] = task
                    print(f"New task found: {task.get('task_name', 'Unknown')} (key: {task_key})")
                else:
                    print(f"Skipping recently archived task: {task.get('task_name', 'Unknown')} (key: {task_key})")
            else:
                # Check if task has significantly changed (but not just percentage/status)
                known_task = self.current_known_tasks[task_key]
                if not self.compare_tasks(task, known_task):
                    # Task has changed in significant way - treat as new
                    new_tasks.append(task)
                    self.current_known_tasks[task_key] = task
                    print(f"Task updated: {task.get('task_name', 'Unknown')} (key: {task_key})")

        # Save updated current tasks
        self.save_current_tasks()

        return new_tasks, overdue_archived + completed_archived

    def archive_overdue_tasks_new(self, current_tasks):
        """Archive tasks that are overdue by more than 60 days and return count of newly archived tasks"""
        newly_archived_count = 0

        # Check each current task for overdue status
        for task in current_tasks:
            if self.is_task_overdue_more_than_days(task, 60):
                task_key = self.get_task_key(task)
                if task_key in self.current_known_tasks:
                    # Check if this task is already archived with overdue reason
                    already_archived = False
                    for archive_key, archive_data in self.archived_tasks.items():
                        if (archive_key.startswith(task_key + '_') and
                            archive_data.get('archive_reason') == 'overdue_more_than_60_days'):
                            already_archived = True
                            break

                    if not already_archived:
                        # Archive the overdue task for the first time
                        archive_key = f"{task_key}_{datetime.now().isoformat()}"
                        self.archived_tasks[archive_key] = {
                            'task': self.current_known_tasks[task_key].copy(),
                            'archived_date': datetime.now().isoformat(),
                            'archive_reason': 'overdue_more_than_60_days'
                        }
                        # Remove from current tasks
                        del self.current_known_tasks[task_key]
                        # Track as recently archived to prevent false new task detection
                        self.recently_archived_tasks.add(task_key)
                        newly_archived_count += 1
                        print(f"Newly auto-archived overdue task: {task.get('task_name', 'Unknown')}")

        if newly_archived_count > 0:
            self.save_current_tasks()
            self.save_archive()

        return newly_archived_count

    def archive_completed_tasks(self, current_tasks):
        """Archive tasks that are 100% complete and return count of newly archived tasks"""
        newly_archived_count = 0

        # Check each current task for 100% completion
        for task in current_tasks:
            task_key = self.get_task_key(task)
            if task_key in self.current_known_tasks:
                current_task = self.current_known_tasks[task_key]
                percentage = current_task.get('percentage', 0)

                # Check if task is 100% complete
                if percentage == 100:
                    # Check if this task is already archived with completed reason
                    already_archived = False
                    for archive_key, archive_data in self.archived_tasks.items():
                        if (archive_key.startswith(task_key + '_') and
                            archive_data.get('archive_reason') == 'completed_100_percent'):
                            already_archived = True
                            break

                    if not already_archived:
                        # Archive the completed task
                        archive_key = f"{task_key}_{datetime.now().isoformat()}"
                        self.archived_tasks[archive_key] = {
                            'task': current_task.copy(),
                            'archived_date': datetime.now().isoformat(),
                            'archive_reason': 'completed_100_percent'
                        }
                        # Remove from current tasks
                        del self.current_known_tasks[task_key]
                        # Track as recently archived to prevent false new task detection
                        self.recently_archived_tasks.add(task_key)
                        newly_archived_count += 1
                        print(f"Auto-archived completed task: {task.get('task_name', 'Unknown')} (100%)")

        if newly_archived_count > 0:
            self.save_current_tasks()
            self.save_archive()

        return newly_archived_count

    def archive_old_tasks(self, current_tasks):
        """Move tasks that are no longer active to archive"""
        current_keys = set(self.get_task_key(task) for task in current_tasks)

        for task_key, task in list(self.current_known_tasks.items()):
            if task_key not in current_keys:
                # Move to archive
                archive_key = f"{task_key}_{datetime.now().isoformat()}"
                self.archived_tasks[archive_key] = {
                    'task': task,
                    'archived_date': datetime.now().isoformat(),
                    'archive_reason': 'no_longer_active'
                }
                del self.current_known_tasks[task_key]
                print(f"Archived task: {task.get('task_name', 'Unknown')}")

        # Save archive
        self.save_archive()

    def get_archive_count(self):
        """Get number of archived tasks"""
        return len(self.archived_tasks)

    def get_current_task_count(self):
        """Get number of current tracked tasks"""
        return len(self.current_known_tasks)

    def restore_task(self, archive_key):
        """Restore an archived task back to active tasks"""
        if archive_key not in self.archived_tasks:
            return False, "Archive key not found"

        archive_data = self.archived_tasks[archive_key]
        task_data = archive_data.get('task', {})

        if not task_data:
            return False, "No task data found in archive"

        # Generate task key for the restored task
        task_key = self.get_task_key(task_data)

        # Check if task already exists in current tasks
        if task_key in self.current_known_tasks:
            return False, "Task already exists in current tasks"

        # Add task back to current known tasks
        self.current_known_tasks[task_key] = task_data

        # Remove from archive
        del self.archived_tasks[archive_key]

        # Save changes
        self.save_current_tasks()
        self.save_archive()

        return True, f"Task '{task_data.get('task_name', 'Unknown')}' restored successfully"

    def can_restore_task(self, archive_key):
        """Check if a task can be restored (not overdue more than 60 days)"""
        if archive_key not in self.archived_tasks:
            return False, "Archive key not found"

        archive_data = self.archived_tasks[archive_key]
        archive_reason = archive_data.get('archive_reason', '')

        # Tasks auto-archived for being overdue cannot be restored
        if archive_reason == 'overdue_more_than_60_days':
            return False, "Tasks archived for being overdue cannot be restored"

        # Tasks can be restored if they were manually archived (no_longer_active)
        if archive_reason == 'no_longer_active':
            return True, "Task can be restored"

        return False, f"Task cannot be restored (archive reason: {archive_reason})"

    def get_restorable_tasks(self):
        """Get list of archive keys for tasks that can be restored"""
        restorable = []
        for archive_key, archive_data in self.archived_tasks.items():
            can_restore, _ = self.can_restore_task(archive_key)
            if can_restore:
                restorable.append({
                    'archive_key': archive_key,
                    'task': archive_data.get('task', {}),
                    'archive_data': archive_data
                })
        return restorable

    def is_task_overdue_more_than_days(self, task, days=60):
        """Check if a task is overdue by more than specified days"""
        dates = task.get('dates', '')
        status = task.get('status', '')

        # Only check overdue status for tasks that are marked as overdue
        if status != 'Прострочена':  # Ukrainian for "Overdue"
            return False

        if not dates or '-' not in dates:
            return False

        try:
            # Parse dates (format: "YYYY-MM-DD - YYYY-MM-DD")
            date_parts = dates.split(' - ')
            if len(date_parts) >= 2:
                end_date_str = date_parts[1].strip()
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
                today = datetime.now()

                # Calculate days overdue
                days_overdue = (today - end_date).days
                return days_overdue > days
        except Exception as e:
            print(f"Error parsing dates for overdue check: {e}")
            return False

        return False

class LoginWorker(QThread):
    login_success = pyqtSignal(dict)
    login_failed = pyqtSignal(str)
    data_received = pyqtSignal(list)
    new_tasks_found = pyqtSignal(list)  # Signal for new tasks
    tasks_auto_archived = pyqtSignal(int)  # Signal for auto-archived tasks

    def __init__(self, username, password, task_tracker=None):
        super().__init__()
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.task_tracker = task_tracker

    def run(self):
        try:
            # Real authentication using the correct login URL
            login_url = "https://calendar.nupp.edu.ua/login.php"

            # First, get the login page to establish session
            response = self.session.get(login_url, timeout=30)

            # Analyze the login form
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all forms
            forms = soup.find_all('form')

            for i, form in enumerate(forms):
                if form.get('action'):
                    print(f"  - Action: {form['action']}")
                if form.get('method'):
                    print(f"  - Method: {form['method']}")

                # Find all input fields
                inputs = form.find_all('input')
                print(f"  - Input fields ({len(inputs)}):")
                for inp in inputs:
                    name = inp.get('name', 'NO_NAME')
                    input_type = inp.get('type', 'NO_TYPE')
                    value = inp.get('value', '')
                    print(f"    * {name} (type: {input_type}, value: '{value}')")

            # Try to find the correct form and field names
            login_form = None
            username_field = None
            password_field = None
            submit_field = None

            for form in forms:
                inputs = form.find_all('input')
                for inp in inputs:
                    input_type = inp.get('type', '').lower()
                    input_name = inp.get('name', '').lower()

                    if input_type == 'text' and not username_field:
                        username_field = inp.get('name')
                    elif input_type == 'password' and not password_field:
                        password_field = inp.get('name')
                    elif input_type == 'submit' and not submit_field:
                        submit_field = inp.get('name')

                if username_field and password_field:
                    login_form = form
                    break

            if not username_field or not password_field:
                username_field = 'username'
                password_field = 'password'
                submit_field = 'login'
            else:
                print(f"  - Username field: {username_field}")
                print(f"  - Password field: {password_field}")
                print(f"  - Submit field: {submit_field}")

            # Prepare login data
            login_data = {
                username_field: self.username,
                password_field: self.password,
            }

            if submit_field:
                login_data[submit_field] = 'Вхід'
            for key, value in login_data.items():
                if 'password' in key.lower():
                    print(f"  - {key}: {'*' * len(str(value))}")
                else:
                    print(f"  - {key}: {value}")

            # Determine form action URL
            if login_form and login_form.get('action'):
                form_action = login_form['action']
                if form_action.startswith('http'):
                    post_url = form_action
                else:
                    post_url = f"https://calendar.nupp.edu.ua/{form_action.lstrip('/')}"
            else:
                post_url = login_url

            # Attempt login
            response = self.session.post(post_url, data=login_data, timeout=30)

            # Check for login success indicators
            response_lower = response.text.lower()

            # Check for JavaScript redirect (indicates successful login)
            js_redirect_success = False
            if "location=" in response_lower or "window.location" in response_lower or "location=index.php" in response_lower:
                js_redirect_success = True

            # List of possible success indicators
            success_indicators = [
                "logout", "вихід", "exit", "sign out",
                "календар", "calendar", "завдання", "tasks",
                "dashboard", "панель", "profile", "профіль"
            ]

            found_indicators = []
            for indicator in success_indicators:
                if indicator in response_lower:
                    found_indicators.append(indicator)

            # Check for failure indicators
            failure_indicators = [
                "error", "помилка", "incorrect", "неправильний",
                "invalid", "невірний", "failed", "не вдалося",
                "access denied", "доступ заборонено"
            ]

            found_failure = []
            for indicator in failure_indicators:
                if indicator in response_lower:
                    found_failure.append(indicator)

            if response.status_code == 200:
                if js_redirect_success or (found_indicators and not found_failure):
                    self.login_success.emit({"status": "success"})

                    # Now get the main calendar page with tasks
                    calendar_url = "https://calendar.nupp.edu.ua/index.php"

                    tasks_response = self.session.get(calendar_url, timeout=30)

                    if tasks_response.status_code == 200:
                        tasks = self.parse_tasks_html(tasks_response.text)

                        # Check for new tasks and auto-archive overdue tasks if task_tracker is available
                        new_tasks = []
                        if self.task_tracker and tasks:
                            new_tasks, auto_archived_count = self.task_tracker.identify_new_tasks(tasks)

                            if new_tasks:
                                self.new_tasks_found.emit(new_tasks)

                            if auto_archived_count > 0:
                                self.tasks_auto_archived.emit(auto_archived_count)

                        self.data_received.emit(tasks)
                    else:
                        self.login_failed.emit(f"Failed to fetch calendar page: {tasks_response.status_code}")
                else:
                    if found_failure:
                        self.login_failed.emit(f"Login failed: {', '.join(found_failure)}")
                    else:
                        self.login_failed.emit("Invalid credentials or login failed")
            else:
                self.login_failed.emit(f"HTTP Error: {response.status_code}")

        except requests.exceptions.RequestException as e:
            self.login_failed.emit(f"Connection error: {str(e)}")
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.login_failed.emit(f"Unexpected error: {str(e)}")

    def parse_task_row(self, row):
        """Parse a single task row and return task data"""
        cells = row.find_all('td')

        if len(cells) < 5:
            return None

        try:
            task_name = cells[0].get_text(strip=True)

            # Get full description from column 1 (Опис задачі)
            description_cell = cells[1]
            task_description = description_cell.get_text(strip=True) if description_cell else ""

            dates = cells[2].get_text(strip=True)

            # Status from the 4th column
            status_cell = cells[3]
            status = status_cell.get_text(strip=True)

            # Percentage from input tag or text in 5th cell
            percentage = 0
            task_id = None

            # Extract task ID from the <td> tag id attribute first
            percentage_cell = cells[4]
            if percentage_cell.has_attr('id'):
                cell_id = percentage_cell['id']
                if cell_id.startswith('td'):
                    task_id = cell_id.replace('td', '')

            # Try to find input field (for tasks that can be updated)
            percentage_input = percentage_cell.find('input')
            if percentage_input:
                # Extract percentage from input value
                if percentage_input.has_attr('value'):
                    try:
                        percentage = int(percentage_input['value'].replace('%', ''))
                    except ValueError:
                        percentage = 0

                # Extract task ID from input name/id (as backup)
                if not task_id:
                    if percentage_input.has_attr('name'):
                        name_attr = percentage_input['name']
                        if name_attr.startswith('links'):
                            task_id = name_attr.replace('links', '')
                    elif percentage_input.has_attr('id'):
                        id_attr = percentage_input['id']
                        if id_attr.startswith('links'):
                            task_id = id_attr.replace('links', '')
            else:
                # No input field - extract percentage from cell text (for 100% tasks)
                cell_text = percentage_cell.get_text(strip=True)
                try:
                    percentage = int(cell_text.replace('%', ''))
                except ValueError:
                    percentage = 0

            # Extract download links from task description (column 1 - Опис задачі)
            documents = []
            if len(cells) > 1:
                description_cell = cells[1]
                description_text = description_cell.get_text()

                # First, look for <a> tags
                links = description_cell.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    link_text = link.get_text(strip=True) or "Document"

                    # Make URL absolute if it's relative
                    if href.startswith('/'):
                        href = f"https://calendar.nupp.edu.ua{href}"
                    elif not href.startswith('http'):
                        href = f"https://calendar.nupp.edu.ua/{href}"

                    documents.append({
                        'text': link_text,
                        'url': href
                    })

                # Then, look for plain text URLs that are actual documents (http/https links)
                import re
                # Fix spaced URLs in text first before matching
                description_text = re.sub(r'https?:\s*//\s*', 'https://', description_text)
                description_text = re.sub(r'(\w+)\. +(\w+)', r'\1.\2', description_text)

                # Only match URLs that end with document extensions (required, not optional)
                url_pattern = r'https?://[^\s<>"\'\)]+\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf)(?:\?[^\s<>"\'\)]*)?'
                plain_urls = re.findall(url_pattern, description_text, flags=re.IGNORECASE)

                for url in plain_urls:
                    # Avoid duplicates
                    if not any(doc['url'] == url for doc in documents):
                        # Extract filename from URL
                        filename = url.split('/')[-1] or "Document"

                        documents.append({
                            'text': filename,
                            'url': url
                        })

            # Filter by Ukrainian status terms (including different encodings)
            valid_statuses = ['Прострочена', 'Отстаній день', 'Отстанній день', 'Поточна']
            if status in valid_statuses:
                return {
                    'status': status,
                    'task_name': task_name,
                    'task_description': task_description,  # Full description from Опис задачі
                    'dates': dates,
                    'percentage': percentage,
                    'documents': documents,
                    'task_id': task_id
                }
            else:
                return None

        except Exception as e:
            print(f"Error parsing task row: {e}")
            return None

    def parse_tasks_html(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        tasks = []

        # Find the task container
        task_container = soup.find('div', id='task')
        if task_container:
            # Parse tasks from the main container
            table = task_container.find('table')
            if table:
                tbody = table.find('tbody')
                if tbody:
                    rows = tbody.find_all('tr')
                    for row in rows:
                        task = self.parse_task_row(row)
                        if task:
                            tasks.append(task)
        else:
            # Look for other possible containers
            all_divs = soup.find_all('div')
            task_divs = [div for div in all_divs if div.get('id', '').lower().find('task') != -1 or div.get('class', [''])[0].lower().find('task') != -1]
            for i, div in enumerate(task_divs[:3]):  # Show first 3
                div_id = div.get('id', 'NO_ID')
                div_class = div.get('class', ['NO_CLASS'])
                print(f"  - Div {i+1}: id='{div_id}', class={div_class}")

        return tasks

class TaskMonitorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.session = None
        self.worker = None
        # Initialize task tracker
        self.task_tracker = TaskTracker()
        # Initialize settings for credential storage
        self.settings = QSettings('NUPP', 'TaskMonitor')
        # Flag to prevent showing confirm dialogs during table population
        self._populating_table = False

        # Check for auto-login
        self.initUI()
        self.check_auto_login()

    def encrypt_password(self, password):
        """Simple password encryption for storage"""
        # Create a simple hash-based encryption
        key = "NUPPTaskMonitor2024"  # This should be more secure in production
        encoded = []
        for i, char in enumerate(password):
            key_char = key[i % len(key)]
            encoded.append(chr(ord(char) ^ ord(key_char)))
        return base64.b64encode(''.join(encoded).encode()).decode()

    def decrypt_password(self, encrypted_password):
        """Decrypt password from storage"""
        key = "NUPPTaskMonitor2024"  # This should be more secure in production
        try:
            decoded = base64.b64decode(encrypted_password.encode()).decode()
            decrypted = []
            for i, char in enumerate(decoded):
                key_char = key[i % len(key)]
                decrypted.append(chr(ord(char) ^ ord(key_char)))
            return ''.join(decrypted)
        except:
            return ""

    def save_credentials(self, username, password, remember_me):
        """Save credentials to settings"""
        self.settings.setValue('remember_me', remember_me)
        if remember_me:
            # Only save if user wants to remember
            self.settings.setValue('username', username)
            if password:
                encrypted_password = self.encrypt_password(password)
                self.settings.setValue('password', encrypted_password)
        else:
            # Clear saved credentials
            self.settings.remove('username')
            self.settings.remove('password')
        self.settings.sync()

    def load_credentials(self):
        """Load credentials from settings"""
        remember_me = self.settings.value('remember_me', False, type=bool)
        if remember_me:
            username = self.settings.value('username', '', type=str)
            encrypted_password = self.settings.value('password', '', type=str)
            password = self.decrypt_password(encrypted_password) if encrypted_password else ''
            return username, password, True
        return '', '', False

    def initUI(self):
        self.setWindowTitle("Монітор Завдань - Календар НУПП")
        self.setGeometry(100, 100, 1000, 700)

        # Create menu bar
        self.create_menu_bar()

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)

        # Create tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Login tab
        self.login_tab = self.create_login_tab()
        self.tabs.addTab(self.login_tab, "Вхід")

        # Tasks tab
        self.tasks_tab = self.create_tasks_tab()
        self.tabs.addTab(self.tasks_tab, "Завдання")

        # Initially disable tasks tab
        self.tabs.setTabEnabled(1, False)

        # Status bar
        self.statusBar().showMessage("Готово")

    def create_menu_bar(self):
        """Create the application menu bar"""
        menubar = self.menuBar()

        # Help menu
        help_menu = menubar.addMenu("Довідка")

        # About action
        about_action = QAction("Про програму", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

        # Settings menu
        settings_menu = menubar.addMenu("Налаштування")

        # Change password action
        change_password_action = QAction("Змінити пароль", self)
        change_password_action.triggered.connect(self.change_password)
        settings_menu.addAction(change_password_action)

    def show_about_dialog(self):
        """Show the About dialog"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton

        dialog = QDialog(self)
        dialog.setWindowTitle("Про програму")
        dialog.setFixedSize(400, 250)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        # Application name
        title_label = QLabel("Монітор Завдань - Календар НУПП")
        title_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

        # Description
        description_label = QLabel(
            "Програма для моніторингу завдань з календаря НУПП.\n\n"
            "Основні функції:\n"
            "• Перегляд активних завдань\n"
            "• Оновлення прогресу виконання\n"
            "• Автоматичне архівування виконаних завдань\n"
            "• Завантаження документів\n"
            "• Поділитись інформацією про завдання"
        )
        description_label.setWordWrap(True)
        description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(description_label)

        # Author and copyright
        author_label = QLabel("Автор: Петренко Тарас Сергійович")
        author_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(author_label)

        copyright_label = QLabel("© 2024 Всі права захищено")
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(copyright_label)

        # Close button
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        close_button = QPushButton("Закрити")
        close_button.clicked.connect(dialog.close)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)

        dialog.exec()

    def change_password(self):
        """Handle password change from menu"""
        change_dialog = ChangePasswordDialog()

        if change_dialog.exec() == QDialog.DialogCode.Accepted:
            current_password, new_password, _ = change_dialog.get_passwords()

            password_manager = PasswordManager()
            if password_manager.change_password(current_password, new_password):
                QMessageBox.information(self, "Успіх", "Пароль успішно змінено!")
            else:
                QMessageBox.critical(self, "Помилка", "Поточний пароль неправильний!")

    def create_login_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Title
        title = QLabel("Монітор Завдань - Календар НУПП")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(title)

        # Login form
        form_layout = QVBoxLayout()

        # Username
        username_label = QLabel("Ім'я користувача:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Введіть ваше ім'я користувача")
        form_layout.addWidget(username_label)
        form_layout.addWidget(self.username_input)

        # Password
        password_label = QLabel("Пароль:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Введіть ваш пароль")
        form_layout.addWidget(password_label)
        form_layout.addWidget(self.password_input)

        # Remember me checkbox
        self.remember_checkbox = QCheckBox("Запам'ятати дані")
        form_layout.addWidget(self.remember_checkbox)

        layout.addLayout(form_layout)

        # Connect button
        self.connect_button = QPushButton("Підключитися")
        self.connect_button.clicked.connect(self.on_connect_clicked)
        self.connect_button.setFont(QFont("Arial", 12))
        layout.addWidget(self.connect_button)

        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

        layout.addStretch()

        # Load saved credentials on startup
        self.load_saved_credentials()

        return tab

    def load_saved_credentials(self):
        """Load saved credentials and populate the form"""
        username, password, remember_me = self.load_credentials()

        if username:
            self.username_input.setText(username)

        if password:
            self.password_input.setText(password)

        self.remember_checkbox.setChecked(remember_me)

        # Set cursor to username field if no saved credentials, otherwise password
        if not username and not password:
            self.username_input.setFocus()
        elif username and not password:
            self.password_input.setFocus()

    def check_auto_login(self):
        """Check if auto-login should be triggered"""
        username, password, remember_me = self.load_credentials()

        # Auto-login if all conditions are met:
        # 1. Remember me is checked
        # 2. Both username and password are available
        # 3. Password is not empty
        if remember_me and username and password and password.strip():
            # Set status message
            self.status_label.setText("Auto-login in progress...")
            self.statusBar().showMessage("Automatically logging in...")

            # Trigger login after a short delay to allow UI to fully load
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(1000, lambda: self.perform_auto_login(username, password))

    def perform_auto_login(self, username, password):
        """Perform automatic login with saved credentials"""

        # Disable button during login attempt
        self.connect_button.setEnabled(False)
        self.status_label.setText("Connecting...")
        self.statusBar().showMessage("Attempting to login...")

        # Create worker for auto login
        self.worker = LoginWorker(username, password, self.task_tracker)

        # Connect signals
        self.worker.login_success.connect(self.on_login_success)
        self.worker.login_failed.connect(self.on_login_failed)
        self.worker.data_received.connect(self.display_tasks)
        self.worker.new_tasks_found.connect(self.on_new_tasks_found)
        self.worker.tasks_auto_archived.connect(self.on_tasks_auto_archived)

        # Start worker thread
        self.worker.start()

    def create_tasks_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Title
        title = QLabel("Панель Завдань")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # Table for tasks (with 4 columns - download links are in task description)
        self.tasks_table = QTableWidget()
        self.tasks_table.setColumnCount(4)
        self.tasks_table.setHorizontalHeaderLabels(["Статус", "Назва Завдання", "Дати", "Виконання %"])

        # Adjust column widths
        header = self.tasks_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        # Enable double-click for downloading documents
        self.tasks_table.cellDoubleClicked.connect(self.on_task_double_clicked)

        # Disable editing - percentage updates only through details window
        self.tasks_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        layout.addWidget(self.tasks_table)

        # Toolbar for actions
        toolbar = QToolBar("Дії")

        # Refresh button
        refresh_action = QAction("Оновити", self)
        refresh_action.triggered.connect(self.refresh_tasks)
        toolbar.addAction(refresh_action)

        toolbar.addSeparator()

        # Archive button
        archive_action = QAction("Переглянути Архів", self)
        archive_action.triggered.connect(self.show_archive)
        toolbar.addAction(archive_action)

        layout.addWidget(toolbar)

        # Progress bar for downloads
        self.download_progress = QProgressBar()
        self.download_progress.setVisible(False)
        layout.addWidget(self.download_progress)

        return tab

    def on_connect_clicked(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        remember_me = self.remember_checkbox.isChecked()

        if not username or not password:
            QMessageBox.warning(self, "Попередження", "Будь ласка, введіть ім'я користувача та пароль")
            return

        # Save credentials if remember me is checked
        if remember_me:
            self.save_credentials(username, password, True)
        else:
            # Clear saved credentials
            self.save_credentials('', '', False)

        # Disable button during login attempt
        self.connect_button.setEnabled(False)
        self.status_label.setText("Connecting...")
        self.statusBar().showMessage("Attempting to login...")

        # Create worker for real login
        self.worker = LoginWorker(username, password, self.task_tracker)

        # Connect signals
        self.worker.login_success.connect(self.on_login_success)
        self.worker.login_failed.connect(self.on_login_failed)
        self.worker.data_received.connect(self.display_tasks)
        self.worker.new_tasks_found.connect(self.on_new_tasks_found)
        self.worker.tasks_auto_archived.connect(self.on_tasks_auto_archived)

        # Start worker thread
        self.worker.start()

    def on_login_success(self, data):
        self.status_label.setText("Вхід успішний!")
        self.statusBar().showMessage("Успішно підключено")
        self.connect_button.setEnabled(True)

        # Store the authenticated session from worker
        self.session = self.worker.session

        # Enable tasks tab
        self.tabs.setTabEnabled(1, True)
        self.tabs.setCurrentIndex(1)  # Switch to tasks tab

    def on_login_failed(self, error_message):
        self.status_label.setText(f"Login failed: {error_message}")
        self.statusBar().showMessage("Підключення не вдалося")
        self.connect_button.setEnabled(True)

        # Show error message
        QMessageBox.critical(self, "Помилка Входу", error_message)

    def on_new_tasks_found(self, new_tasks):
        """Handle new tasks found - show details for each new task"""
        if not new_tasks:
            return

        # Show a summary message first
        task_count = len(new_tasks)
        if task_count == 1:
            QMessageBox.information(self, "Знайдено Нове Завдання",
                                   f"Знайдено 1 нове завдання. Відкриваю деталі...")
        else:
            QMessageBox.information(self, "Знайдено Нові Завдання",
                                   f"Знайдено {task_count} нових завдань. Відкриваю деталі...")

        # Open details window for each new task sequentially
        for task in new_tasks:
            details_window = TaskDetailsWindow(task, self.session, self)
            details_window.exec()

    def on_tasks_auto_archived(self, archived_count):
        """Handle tasks that were automatically archived due to being overdue or completed"""
        if archived_count > 0:
            QMessageBox.information(
                self, "Завдання Автоматично Архівовані",
                f"{archived_count} завдань було автоматично архівовано.\n\n"
                f"Причини архівації:\n"
                f"• Прострочені (понад 60 днів)\n"
                f"• Виконані на 100%\n\n"
                f"Ви можете переглянути всі архівовані завдання, натиснувши 'Переглянути Архів' на панелі інструментів."
            )

    def display_tasks(self, tasks):
        # Clear existing tasks
        self.tasks_table.setRowCount(0)

        if not tasks:
            QMessageBox.information(self, "Інформація", "Завдань, що відповідають критеріям, не знайдено")
            return

        # Filter out archived tasks
        active_tasks = []
        if self.task_tracker:
            for task in tasks:
                task_key = self.task_tracker.get_task_key(task)
                # Only include tasks that are not archived
                if task_key not in self.task_tracker.recently_archived_tasks:
                    # Check if task is in archive with overdue reason
                    is_archived_overdue = False
                    for archive_key, archive_data in self.task_tracker.archived_tasks.items():
                        if (archive_key.startswith(task_key + '_') and
                            archive_data.get('archive_reason') == 'overdue_more_than_60_days'):
                            is_archived_overdue = True
                            break

                    if not is_archived_overdue:
                        active_tasks.append(task)
        else:
            # If no task tracker, show all tasks (fallback)
            active_tasks = tasks

        if not active_tasks:
            QMessageBox.information(self, "Інформація", "Активних завдань не знайдено (усі завдання можуть бути в архіві)")
            return

        # Store current active tasks for download functionality
        self._current_tasks = active_tasks

        # Set flag to prevent confirm dialogs during population
        self._populating_table = True

        # Populate table
        self.tasks_table.setRowCount(len(active_tasks))

        for row, task in enumerate(active_tasks):
            # Status
            status_item = QTableWidgetItem(task['status'])
            self.tasks_table.setItem(row, 0, status_item)

            # Task Name (using the actual task name from column 0, not the description)
            task_name_display = task['task_name']  # Use the actual task name from column 0

            documents = task.get('documents', [])
            if documents:
                task_name_display += f"\n📄 {len(documents)} документ(ів) доступно"

            name_item = QTableWidgetItem(task_name_display)

            # Create tooltip with task name and document info
            tooltip_text = f"Завдання: {task['task_name']}"
            if documents:
                tooltip_text += f"\n\nДокументи: {', '.join([doc['text'] for doc in documents])}"
            name_item.setToolTip(tooltip_text)
            self.tasks_table.setItem(row, 1, name_item)

            # Dates
            dates_item = QTableWidgetItem(task['dates'])
            self.tasks_table.setItem(row, 2, dates_item)

            # Percentage (editable)
            percentage_item = QTableWidgetItem(f"{task['percentage']}")
            percentage_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            percentage_item.setFlags(percentage_item.flags() | Qt.ItemFlag.ItemIsEditable)
            percentage_item.setData(Qt.ItemDataRole.UserRole, task.get('task_id'))  # Store task ID
            self.tasks_table.setItem(row, 3, percentage_item)

            # Apply row highlighting based on status
            self.highlight_row_by_status(row, task['status'], task)

        # Reset flag after table population is complete
        self._populating_table = False

    def on_task_double_clicked(self, row, column):
        """Handle double-click on a task row to open detailed task window"""
        if not hasattr(self, '_current_tasks') or row >= len(self._current_tasks):
            return

        task = self._current_tasks[row]

        # Open detailed task window
        details_window = TaskDetailsWindow(task, self.session, self)
        details_window.exec()

    def on_task_double_click_old(self, row, column):
        """Handle double-click on a task row to download documents"""
        if not hasattr(self, '_current_tasks') or row >= len(self._current_tasks):
            return

        task = self._current_tasks[row]
        documents = task.get('documents', [])

        if documents:
            self.download_documents_for_task(task['task_name'], documents)
        else:
            QMessageBox.information(self, "Документи Відсутні",
                                   f"Документи не знайдено для завдання:\n{task['task_name']}")

    def highlight_row_by_status(self, row, status, task_data=None):
        """Apply color coding and font styling to table rows based on task status"""
        if status == "Прострочена":
            # Check if this overdue task is approaching 60-day archive threshold
            if task_data and self.task_tracker:
                days_overdue = self.get_days_overdue(task_data)
                if days_overdue >= 45:  # Approaching 60-day archive (45+ days overdue)
                    # Dark red with warning pattern for tasks approaching archive
                    archive_warning_color = QColor(255, 150, 150)  # Darker red
                    archive_font = QFont("Arial", 10, QFont.Weight.Bold)

                    for col in range(self.tasks_table.columnCount()):
                        item = self.tasks_table.item(row, col)
                        if item:
                            item.setBackground(archive_warning_color)
                            item.setFont(archive_font)
                            item.setForeground(QColor(0, 0, 0))  # Explicit black text

                            # Add tooltip warning about impending archive
                            if col == 0:  # Only add to status column
                                tooltip = f"⚠️ ARCHIVE WARNING: Task will be auto-archived in {60 - days_overdue} days\n(Overdue by {days_overdue} days)"
                                item.setToolTip(tooltip)
                    return  # Skip the regular overdue styling

            # Regular overdue styling (less than 45 days overdue)
            overdue_color = QColor(255, 200, 200)
            overdue_font = QFont("Arial", 10, QFont.Weight.Bold)

            for col in range(self.tasks_table.columnCount()):
                item = self.tasks_table.item(row, col)
                if item:
                    item.setBackground(overdue_color)
                    item.setFont(overdue_font)
                    item.setForeground(QColor(0, 0, 0))  # Explicit black text

        elif status in ["Отстаній день", "Отстанній день"]:
            # Darker orange for last day tasks with semi-bold font (better contrast)
            last_day_color = QColor(255, 220, 180)
            last_day_font = QFont("Arial", 10, QFont.Weight.Medium)

            for col in range(self.tasks_table.columnCount()):
                item = self.tasks_table.item(row, col)
                if item:
                    item.setBackground(last_day_color)
                    item.setFont(last_day_font)
                    item.setForeground(QColor(0, 0, 0))  # Explicit black text

        elif status == "Поточна":
            # Light green for current tasks with normal font (good contrast)
            current_color = QColor(230, 255, 230)
            current_font = QFont("Arial", 10, QFont.Weight.Normal)

            for col in range(self.tasks_table.columnCount()):
                item = self.tasks_table.item(row, col)
                if item:
                    item.setBackground(current_color)
                    item.setFont(current_font)
                    item.setForeground(QColor(0, 0, 0))  # Explicit black text

    def get_days_overdue(self, task):
        """Calculate how many days a task is overdue"""
        dates = task.get('dates', '')

        if not dates or '-' not in dates:
            return 0

        try:
            # Parse dates (format: "YYYY-MM-DD - YYYY-MM-DD")
            date_parts = dates.split(' - ')
            if len(date_parts) >= 2:
                end_date_str = date_parts[1].strip()
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
                today = datetime.now()

                # Calculate days overdue
                days_overdue = (today - end_date).days
                return max(0, days_overdue)  # Don't return negative days
        except Exception as e:
            print(f"Error calculating days overdue: {e}")
            return 0

        return 0

    def refresh_tasks(self):
        if not self.worker:
            QMessageBox.warning(self, "Warning", "Please login first")
            return

        self.statusBar().showMessage("Refreshing tasks...")
        # Re-run the worker to get fresh data
        self.worker.start()

    def download_document_for_row(self):
        """Download document for a specific task row"""
        button = self.sender()
        task_index = button.property("task_index")
        task_name = button.property("task_name")

        # Get the task from current data
        if hasattr(self, '_current_tasks') and task_index < len(self._current_tasks):
            task = self._current_tasks[task_index]
            documents = task.get('documents', [])

            if documents:
                self.download_documents_for_task(task_name, documents)
            else:
                QMessageBox.information(self, "Документи Відсутні",
                                   f"Документи не знайдено для завдання: {task_name}")
        else:
            QMessageBox.warning(self, "Error", "Task data not available")

    def download_documents_for_task(self, task_name, documents):
        """Download all documents for a specific task"""
        if not documents:
            return

        # Let user choose download location
        download_dir = QFileDialog.getExistingDirectory(
            self,
            f"Оберіть папку для завантаження документів: {task_name}",
            "",
            QFileDialog.Option.ShowDirsOnly
        )

        if not download_dir:
            return

        # Show progress bar
        self.download_progress.setVisible(True)
        self.download_progress.setMaximum(len(documents))
        self.download_progress.setValue(0)

        successful_downloads = 0
        failed_downloads = 0

        for i, doc in enumerate(documents):
            try:
                # Update progress
                self.download_progress.setValue(i)
                self.statusBar().showMessage(f"Downloading {doc['text']}...")

                # Download the document
                response = self.session.get(doc['url'], timeout=30)

                if response.status_code == 200:
                    # Extract filename from URL or use document text
                    url_path = urllib.parse.urlparse(doc['url']).path
                    if url_path:
                        filename = os.path.basename(url_path)
                    else:
                        filename = f"{doc['text']}.pdf"  # Default to PDF

                    # Clean filename
                    filename = "".join(c for c in filename if c.isalnum() or c in (' ', '-', '_', '.'))

                    file_path = os.path.join(download_dir, filename)

                    # Save file
                    with open(file_path, 'wb') as f:
                        f.write(response.content)

                    successful_downloads += 1
                else:
                    failed_downloads += 1

            except Exception as e:
                failed_downloads += 1

        # Hide progress bar
        self.download_progress.setVisible(False)

        # Show results
        total_docs = len(documents)
        if successful_downloads == total_docs:
            QMessageBox.information(self, "Завантаження Завершено",
                                       f"Успішно завантажено всі {total_docs} документи для:\n{task_name}")
        elif successful_downloads > 0:
            QMessageBox.warning(self, "Часткове Завантаження",
                                  f"Завантажено {successful_downloads} з {total_docs} документів для:\n{task_name}\n\n{failed_downloads} завантажень не вдалося.")
        else:
            QMessageBox.critical(self, "Завантаження Невдале",
                                 f"Не вдалося завантажити жоден документ для:\n{task_name}")

        self.statusBar().showMessage("Завантаження завершено")

    def download_all_documents(self):
        """Download all documents from all tasks"""
        if not hasattr(self, '_current_tasks') or not self._current_tasks:
            QMessageBox.warning(self, "Завдань Немає", "Будь ласка, спершу завантажте завдання")
            return

        all_documents = []
        total_files = 0

        for task in self._current_tasks:
            documents = task.get('documents', [])
            all_documents.extend(documents)
            total_files += len(documents)

        if total_files == 0:
            QMessageBox.information(self, "Документи Відсутні", "У жодному завданні не знайдено документів")
            return

        # Ask for confirmation
        reply = QMessageBox.question(self, "Підтвердити Завантаження",
                                 f"Завантажити {total_files} документів з усіх завдань?",
                                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                 QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            # Let user choose download location
            download_dir = QFileDialog.getExistingDirectory(
                self,
                "Оберіть папку для завантаження всіх документів",
                "",
                QFileDialog.Option.ShowDirsOnly
            )

            if download_dir:
                self.download_documents_collection("All Tasks", all_documents, download_dir)

    def download_documents_collection(self, collection_name, documents, download_dir):
        """Download a collection of documents with progress"""
        # Show progress bar
        self.download_progress.setVisible(True)
        self.download_progress.setMaximum(len(documents))
        self.download_progress.setValue(0)

        successful_downloads = 0

        for i, doc in enumerate(documents):
            try:
                # Update progress
                self.download_progress.setValue(i)
                self.statusBar().showMessage(f"Downloading {doc['text']} ({i+1}/{len(documents)})...")

                # Download the document
                response = self.session.get(doc['url'], timeout=30)

                if response.status_code == 200:
                    # Extract filename
                    url_path = urllib.parse.urlparse(doc['url']).path
                    if url_path:
                        filename = os.path.basename(url_path)
                    else:
                        filename = f"{doc['text']}.pdf"

                    # Clean filename
                    filename = "".join(c for c in filename if c.isalnum() or c in (' ', '-', '_', '.'))

                    file_path = os.path.join(download_dir, filename)

                    # Save file
                    with open(file_path, 'wb') as f:
                        f.write(response.content)

                    successful_downloads += 1
                else:
                    failed_downloads += 1

            except Exception as e:
                failed_downloads += 1

        # Hide progress bar
        self.download_progress.setVisible(False)

        # Show results
        if successful_downloads == len(documents):
            QMessageBox.information(self, "Завантаження Завершено",
                                       f"Успішно завантажено {successful_downloads} документів для {collection_name}")
        else:
            QMessageBox.warning(self, "Часткове Завантаження",
                                  f"Завантажено {successful_downloads} з {len(documents)} документів для {collection_name}")

        self.statusBar().showMessage("Завантаження завершено")

    def show_archive(self):
        """Show task archive window"""
        archive_window = ArchiveWindow(self.task_tracker, self)
        archive_window.exec()

    def closeEvent(self, event):
        # Clean up worker thread
        if self.worker and self.worker.isRunning():
            self.worker.quit()
            self.worker.wait()
        event.accept()

class ArchiveWindow(QDialog):
    """Window to display archived tasks"""

    def __init__(self, task_tracker, parent=None):
        super().__init__(parent)
        self.task_tracker = task_tracker
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Архів Завдань")
        self.setGeometry(200, 200, 1000, 600)
        self.setModal(True)

        # Main layout
        main_layout = QVBoxLayout(self)

        # Header with statistics
        self.create_header(main_layout)

        # Archive table
        self.create_archive_table(main_layout)

        # Buttons
        self.create_buttons(main_layout)

        # Load archive data
        self.load_archive_data()

    def create_header(self, layout):
        """Create header with statistics"""
        header_group = QGroupBox("Статистика Архіву")
        header_layout = QHBoxLayout()

        # Current tasks count
        current_count = self.task_tracker.get_current_task_count()
        current_label = QLabel(f"Поточні Завдання: {current_count}")
        current_label.setStyleSheet("font-weight: bold; color: green;")
        header_layout.addWidget(current_label)

        header_layout.addWidget(QLabel("|"))

        # Archived tasks count
        archive_count = self.task_tracker.get_archive_count()
        archive_label = QLabel(f"Архівовані Завдання: {archive_count}")
        archive_label.setStyleSheet("font-weight: bold; color: blue;")
        header_layout.addWidget(archive_label)

        header_layout.addStretch()

        header_group.setLayout(header_layout)
        layout.addWidget(header_group)

    def create_archive_table(self, layout):
        """Create archive table"""
        # Table for archived tasks
        self.archive_table = QTableWidget()
        self.archive_table.setColumnCount(6)
        self.archive_table.setHorizontalHeaderLabels([
            "Назва Завдання", "Опис", "Дати", "Статус", "Дата Архівації", "Причина Архівації"
        ])

        # Set column widths
        header = self.archive_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

        # Disable editing
        self.archive_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        # Enable double-click for viewing task details
        self.archive_table.cellDoubleClicked.connect(self.on_archive_task_double_clicked)

        layout.addWidget(self.archive_table)

    def create_buttons(self, layout):
        """Create action buttons"""
        button_layout = QHBoxLayout()

        # Clear archive button
        clear_button = QPushButton("Очистити Архів")
        clear_button.clicked.connect(self.clear_archive)
        clear_button.setStyleSheet("background-color: #ff6b6b; color: white;")
        button_layout.addWidget(clear_button)

        # Export archive button
        export_button = QPushButton("Експортувати Архів")
        export_button.clicked.connect(self.export_archive)
        button_layout.addWidget(export_button)

        button_layout.addStretch()

        # Close button
        close_button = QPushButton("Закрити")
        close_button.clicked.connect(self.close)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)

    def load_archive_data(self):
        """Load archived tasks into table"""
        archived_tasks = self.task_tracker.archived_tasks
        self.archive_table.setRowCount(len(archived_tasks))

        for row, (archive_key, archive_data) in enumerate(archived_tasks.items()):
            task = archive_data.get('task', {})
            archived_date = archive_data.get('archived_date', '')
            archive_reason = archive_data.get('archive_reason', '')

            # Parse archived date for better display
            try:
                if archived_date:
                    date_obj = datetime.fromisoformat(archived_date)
                    display_date = date_obj.strftime('%Y-%m-%d %H:%M')
                else:
                    display_date = 'Unknown'
            except:
                display_date = archived_date

            # Fill table
            self.archive_table.setItem(row, 0, QTableWidgetItem(task.get('task_name', 'Unknown')))
            self.archive_table.setItem(row, 1, QTableWidgetItem(task.get('task_description', '')))
            self.archive_table.setItem(row, 2, QTableWidgetItem(task.get('dates', '')))
            self.archive_table.setItem(row, 3, QTableWidgetItem(task.get('status', '')))
            self.archive_table.setItem(row, 4, QTableWidgetItem(display_date))
            # Translate archive reasons for display
            if archive_reason == 'overdue_more_than_60_days':
                archive_reason_text = 'Прострочено понад 60 днів'
            elif archive_reason == 'no_longer_active':
                archive_reason_text = 'Більше не активне'
            elif archive_reason == 'completed_100_percent':
                archive_reason_text = '✅ Виконано на 100 відсотків'
            else:
                archive_reason_text = archive_reason.replace('_', ' ').title()
            self.archive_table.setItem(row, 5, QTableWidgetItem(archive_reason_text))

        # Color code rows
        self.color_code_rows()

    def color_code_rows(self):
        """Color code rows based on archive reason"""
        for row in range(self.archive_table.rowCount()):
            reason_item = self.archive_table.item(row, 5)
            if reason_item:
                reason = reason_item.text().lower()
                if 'виконано на 100 відсотків' in reason or 'completed_100_percent' in reason:
                    color = QColor(200, 255, 200)  # Light green for completed tasks
                elif 'no_longer_active' in reason or 'більше не активне' in reason:
                    color = QColor(240, 240, 240)  # Light gray
                elif 'overdue_more_than_60_days' in reason or 'прострочено понад 60 днів' in reason:
                    color = QColor(255, 200, 200)  # Light red for overdue tasks
                else:
                    color = QColor(255, 248, 220)  # Light yellow for other reasons

                for col in range(self.archive_table.columnCount()):
                    item = self.archive_table.item(row, col)
                    if item:
                        item.setBackground(color)
                        # Explicitly set text color to black for better readability
                        item.setForeground(QColor(0, 0, 0))  # Black text

    def clear_archive(self):
        """Clear all archived tasks"""
        reply = QMessageBox.question(
            self, "Підтвердити Очищення Архіву",
            "Ви впевнені, що хочете очистити всі архівовані завдання? Цю дію неможливо скасувати.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.task_tracker.archived_tasks.clear()
            self.task_tracker.save_archive()
            self.archive_table.setRowCount(0)
            QMessageBox.information(self, "Архів Очищено", "Усі архівовані завдання було видалено.")

    def export_archive(self):
        """Export archived tasks to a file"""
        if not self.task_tracker.archived_tasks:
            QMessageBox.information(self, "Архів Відсутній", "Немає архівованих завдань для експорту.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Експортувати Архів",
            f"task_archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Файли (*.json)"
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.task_tracker.archived_tasks, f, ensure_ascii=False, indent=2)
                QMessageBox.information(self, "Експорт Завершено", f"Архів експортовано до {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Експорт Невдалий", f"Не вдалося експортувати архів: {str(e)}")

    def on_archive_task_double_clicked(self, row, column):
        """Handle double-click on archived task to view details"""
        if row >= self.archive_table.rowCount():
            return

        # Get archive key from the row data
        archive_keys = list(self.task_tracker.archived_tasks.keys())
        if row >= len(archive_keys):
            return

        archive_key = archive_keys[row]
        archive_data = self.task_tracker.archived_tasks[archive_key]
        task_data = archive_data.get('task', {})

        if not task_data:
            QMessageBox.warning(self, "No Task Data", "No task data available for this archived item.")
            return

        # Create a modified task details window for archived tasks
        details_window = ArchivedTaskDetailsWindow(task_data, archive_data, None, self.task_tracker, archive_key, self.refresh_archive_display)
        details_window.exec()

    def refresh_archive_display(self):
        """Refresh the archive table display"""
        # Update header statistics by finding the header group and updating its labels
        main_layout = self.layout()
        if main_layout and main_layout.count() > 0:
            header_widget = main_layout.itemAt(0).widget()
            if header_widget and isinstance(header_widget, QGroupBox):
                header_layout = header_widget.layout()
                if header_layout and header_layout.count() >= 4:
                    # Find and update the current and archived task count labels
                    current_count = self.task_tracker.get_current_task_count()
                    archive_count = self.task_tracker.get_archive_count()

                    # Update current tasks label (item at index 0 or 1)
                    for i in range(header_layout.count()):
                        item = header_layout.itemAt(i)
                        if item and item.widget():
                            label = item.widget()
                            if isinstance(label, QLabel) and "Current Tasks:" in label.text():
                                label.setText(f"Current Tasks: {current_count}")
                            elif isinstance(label, QLabel) and "Archived Tasks:" in label.text():
                                label.setText(f"Archived Tasks: {archive_count}")

        # Reload archive data
        self.load_archive_data()

class ArchivedTaskDetailsWindow(QDialog):
    """Task details window specifically for archived tasks"""

    def __init__(self, task_data, archive_data, session, task_tracker=None, archive_key=None, refresh_callback=None):
        super().__init__()
        self.task_data = task_data
        self.archive_data = archive_data
        self.session = session
        self.task_tracker = task_tracker
        self.archive_key = archive_key
        self.refresh_callback = refresh_callback
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Деталі Архівованого Завдання")
        self.setGeometry(150, 150, 900, 700)
        self.setModal(True)

        # Main layout
        main_layout = QVBoxLayout(self)

        # Archive info section
        self.create_archive_info_section(main_layout)

        # Task details section
        self.create_task_details_section(main_layout)

        # Document section
        self.create_document_section(main_layout)

        # Action buttons
        self.create_action_buttons(main_layout)

        # Initialize display
        self.update_display()

    def create_archive_info_section(self, layout):
        """Create archive information section"""
        archive_group = QGroupBox("Інформація про Архів")
        archive_layout = QGridLayout()

        # Archive reason
        archive_layout.addWidget(QLabel("Причина Архівації:"), 0, 0)
        archive_reason_raw = self.archive_data.get('archive_reason', '')
        # Translate archive reasons
        if archive_reason_raw == 'overdue_more_than_60_days':
            archive_reason = 'Прострочено понад 60 днів'
        elif archive_reason_raw == 'no_longer_active':
            archive_reason = 'Більше не активне'
        else:
            archive_reason = archive_reason_raw.replace('_', ' ').title()
        self.archive_reason_label = QLabel(archive_reason)
        self.archive_reason_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        archive_layout.addWidget(self.archive_reason_label, 0, 1)

        # Archive date
        archive_layout.addWidget(QLabel("Дата Архівації:"), 1, 0)
        archived_date = self.archive_data.get('archived_date', '')
        if archived_date:
            try:
                date_obj = datetime.fromisoformat(archived_date)
                display_date = date_obj.strftime('%Y-%m-%d %H:%M')
            except:
                display_date = archived_date
        else:
            display_date = 'Unknown'

        self.archive_date_label = QLabel(display_date)
        archive_layout.addWidget(self.archive_date_label, 1, 1)

        archive_group.setLayout(archive_layout)
        layout.addWidget(archive_group)

    def create_task_details_section(self, layout):
        """Create task details section"""
        details_group = QGroupBox("Інформація про Завдання")
        details_layout = QVBoxLayout()

        # Task name
        task_name_layout = QHBoxLayout()
        task_name_layout.addWidget(QLabel("Назва Завдання:"))
        self.task_name_label = QLabel("")
        self.task_name_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self.task_name_label.setWordWrap(True)
        task_name_layout.addWidget(self.task_name_label)
        details_layout.addLayout(task_name_layout)

        # Status
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Статус:"))
        self.status_label = QLabel("")
        self.status_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        status_layout.addWidget(self.status_label)
        details_layout.addLayout(status_layout)

        # Dates
        dates_layout = QHBoxLayout()
        dates_layout.addWidget(QLabel("Дати:"))
        self.dates_label = QLabel("")
        dates_layout.addWidget(self.dates_label)
        details_layout.addLayout(dates_layout)

        # Overdue information (will be shown if applicable)
        self.overdue_widget = QWidget()
        self.overdue_layout = QHBoxLayout(self.overdue_widget)
        self.overdue_layout.addWidget(QLabel("Інформація про прострочення:"))
        self.overdue_label = QLabel("")
        self.overdue_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        self.overdue_label.setStyleSheet("color: #d32f2f;")
        self.overdue_layout.addWidget(self.overdue_label)
        self.overdue_widget.setVisible(False)  # Hidden by default
        details_layout.addWidget(self.overdue_widget)

        # Description
        details_layout.addWidget(QLabel("Опис:"))
        self.description_text = QTextEdit()
        self.description_text.setReadOnly(True)
        details_layout.addWidget(self.description_text)

        details_group.setLayout(details_layout)
        layout.addWidget(details_group)

    def create_document_section(self, layout):
        """Create document section"""
        document_group = QGroupBox("Документи")
        document_layout = QVBoxLayout()

        # Document info label
        self.document_info_label = QLabel("Документи відсутні")
        self.document_info_label.setFont(QFont("Arial", 10))
        self.document_info_label.setWordWrap(True)
        document_layout.addWidget(self.document_info_label)

        # Buttons layout
        buttons_layout = QHBoxLayout()

        # Download button
        self.download_button = QPushButton("📄 Завантажити Документ(и)")
        self.download_button.setFont(QFont("Arial", 10))
        self.download_button.clicked.connect(self.download_documents)
        self.download_button.setEnabled(False)
        buttons_layout.addWidget(self.download_button)

        # Download and Share button
        self.download_share_button = QPushButton("📄 Завантажити та Поділитись")
        self.download_share_button.setFont(QFont("Arial", 10))
        self.download_share_button.clicked.connect(self.download_and_share_action)
        self.download_share_button.setEnabled(False)
        buttons_layout.addWidget(self.download_share_button)

        document_layout.addLayout(buttons_layout)

        # Progress bar for downloads
        self.download_progress = QProgressBar()
        self.download_progress.setVisible(False)
        document_layout.addWidget(self.download_progress)

        document_group.setLayout(document_layout)
        layout.addWidget(document_group)

    def create_action_buttons(self, layout):
        """Create action buttons"""
        button_layout = QHBoxLayout()

        # Archive information label
        if self.archive_data:
            archived_date = self.archive_data.get('archived_date', '')
            archive_reason = self.archive_data.get('archive_reason', '').replace('_', ' ').title()

            try:
                date_obj = datetime.fromisoformat(archived_date)
                display_date = date_obj.strftime('%Y-%m-%d %H:%M')
            except:
                display_date = archived_date or 'Unknown'

            archive_info = QLabel(f"📅 Заархівовано: {display_date} | 📝 Причина: {archive_reason}")
            archive_info.setWordWrap(True)
            button_layout.addWidget(archive_info)

        button_layout.addStretch()

        # Check if task can be restored
        can_restore = False
        if self.task_tracker and self.archive_key:
            can_restore, _ = self.task_tracker.can_restore_task(self.archive_key)

        # Restore task button (only for restorable tasks)
        if can_restore:
            restore_button = QPushButton("🔄 Відновити Завдання")
            restore_button.clicked.connect(self.restore_task)
            restore_button.setToolTip("Відновити це завдання до активного списку")
            button_layout.addWidget(restore_button)
        else:
            # Show why task cannot be restored
            if self.archive_data:
                archive_reason = self.archive_data.get('archive_reason', '')
                if archive_reason == 'overdue_more_than_60_days':
                    info_label = QLabel("🔒 Автоархівація (прострочено понад 60 днів)")
                    button_layout.addWidget(info_label)

        # Close button
        close_button = QPushButton("❌ Закрити")
        close_button.clicked.connect(self.close)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)

    def update_display(self):
        """Update display with task and archive data"""
        if not self.task_data:
            return

        # Update task name
        task_name = self.task_data.get('task_name', 'No Task Name')
        self.task_name_label.setText(task_name)

        # Update status
        status = self.task_data.get('status', 'Unknown')
        self.status_label.setText(status)

        # Update dates
        dates = self.task_data.get('dates', '')
        self.dates_label.setText(dates)

        # Update description
        task_description = self.task_data.get('task_description', '')
        if task_description and task_description.strip():
            # Remove download URLs from description display
            clean_description = self.clean_description(task_description)
            self.description_text.setPlainText(clean_description.strip())
        else:
            self.description_text.setPlainText("Опис відсутній")

        # Update documents
        documents = self.task_data.get('documents', [])
        if documents:
            doc_info = f"📎 {len(documents)} документ(ів) доступно:\n"
            for doc in documents:
                doc_info += f"• {doc.get('text', 'Документ')}\n"
            self.document_info_label.setText(doc_info.strip())
            self.download_button.setEnabled(True)
            self.download_share_button.setEnabled(True)
        else:
            self.document_info_label.setText("Документи відсутні")
            self.download_button.setEnabled(False)
            self.download_share_button.setEnabled(False)

        # Calculate and display overdue information
        self.calculate_overdue_info()

    def clean_description(self, description):
        """Remove only document download URLs while preserving and fixing important links like forms and websites"""
        clean_desc = description

        # Fix common broken link patterns first
        # Fix spaced URLs like "https: //example.com"
        link_repair_patterns = [
            # Fix spaced protocols
            (r'https?:\s*//\s*([^\s<>"\'\)]+)', r'https://\1'),  # "https: //example.com" → "https://example.com"
            (r'http:\s*//\s*([^\s<>"\'\)]+)', r'http://\1'),    # "http: //example.com" → "http://example.com"

            # Fix spaced domains - most specific first
            (r'(https?://)([a-zA-Z0-9.-]+)\. +([a-zA-Z]{2,})', r'\1\2.\3'),  # "https://site. com" → "https://site.com"
            (r'([a-zA-Z0-9-]+)\. +([a-zA-Z]{2,})', r'\1.\2'),  # "forms. gle" → "forms.gle"
            (r'\. +(\w)', r'.\1'),  # General fix for spaced dots

            # Fix spaced slashes in URLs
            (r'([a-zA-Z0-9.-]+)\s*/\s*([a-zA-Z0-9.-]+)', r'\1/\2'),  # "site / path" → "site/path"
        ]

        for pattern, replacement in link_repair_patterns:
            clean_desc = re.sub(pattern, replacement, clean_desc)

        # Define document download patterns to remove (after fixing links)
        document_patterns = [
            # Direct document file URLs
            r'https?://[^\s<>"\'\)]+\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf)(?:\?[^\s<>"\'\)]*)?',
            # Common document hosting services
            r'https?://(?:drive\.google\.com/file/d/[^\s<>"\'\)]+/view)',
            r'https?://(?:docs\.google\.com/document/d/[^\s<>"\'\)]+)',
            r'https?://(?:dropbox\.com/s/[^\s<>"\'\)]+)',
            r'https?://(?:onedrive\.live\.com/[^\s<>"\'\)]+)',
            # Calendar file download patterns
            r'https?://(?:calendar\.nupp\.edu\.ua)/[^\s<>"\'\)]*\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx)',
            # File download indicators
            r'\[Завантажити файл\]|\[Download file\]',
            r'\[Прикріплений файл\]|\[Attached file\]',
        ]

        # Remove document download links
        for pattern in document_patterns:
            clean_desc = re.sub(pattern, '', clean_desc, flags=re.IGNORECASE)

        # Clean up extra whitespace and orphaned punctuation
        clean_desc = re.sub(r'\s+', ' ', clean_desc)  # Replace multiple spaces
        clean_desc = re.sub(r'\s*([.,;:])\s*', r'\1 ', clean_desc)  # Fix spacing around punctuation
        clean_desc = re.sub(r'\s*\n\s*', ' ', clean_desc)  # Replace newlines with spaces
        clean_desc = clean_desc.strip()

        return clean_desc

    def calculate_overdue_info(self):
        """Calculate overdue information for the task"""
        dates = self.task_data.get('dates', '')
        status = self.task_data.get('status', '')

        if not dates or '-' not in dates or status != 'Прострочена':
            self.overdue_widget.setVisible(False)
            return

        try:
            # Parse dates (format: "YYYY-MM-DD - YYYY-MM-DD")
            date_parts = dates.split(' - ')
            if len(date_parts) >= 2:
                end_date_str = date_parts[1].strip()
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
                today = datetime.now()

                # Calculate days overdue
                days_overdue = (today - end_date).days
                if days_overdue > 0:
                    # Format the overdue information
                    if days_overdue == 1:
                        overdue_text = f"1 день прострочено (термін: {end_date.strftime('%Y-%m-%d')})"
                    elif days_overdue < 60:
                        overdue_text = f"{days_overdue} днів прострочено (термін: {end_date.strftime('%Y-%m-%d')})"
                    else:
                        overdue_text = f"{days_overdue} днів прострочено (архівовано після 60 днів, термін: {end_date.strftime('%Y-%m-%d')})"

                    self.overdue_label.setText(overdue_text)
                    self.overdue_widget.setVisible(True)
                else:
                    self.overdue_widget.setVisible(False)
            else:
                self.overdue_widget.setVisible(False)
        except Exception as e:
            print(f"Error calculating overdue info: {e}")
            self.overdue_widget.setVisible(False)

    def extract_order_info(self, text):
        """Extract order/decision information from task description"""
        # Pattern to match "Наказ №X від DD.MM.YYYY"
        order_pattern = r'Наказ\s*№\s*(\d+)\s*від\s*(\d{2}\.\d{2}\.\d{4})'
        match = re.search(order_pattern, text)

        if match:
            order_num = match.group(1)
            order_date = match.group(2)
            return f"Наказ №{order_num} від {order_date}"

        # Pattern to match "Рішення ректорату від DD.MM.YYYY"
        decision_pattern = r'Рішення\s+ректорату\s+від\s*(\d{2}\.\d{2}\.\d{4})'
        decision_match = re.search(decision_pattern, text)

        if decision_match:
            decision_date = decision_match.group(1)
            return f"Рішення ректорату від {decision_date}"

        # Pattern to match "Розпорядження №X від DD.MM.YYYY"
        order_pattern_alt = r'Розпорядження\s*№\s*(\d+)\s*від\s*(\d{2}\.\d{2}\.\d{4})'
        match_alt = re.search(order_pattern_alt, text)

        if match_alt:
            order_num = match_alt.group(1)
            order_date = match_alt.group(2)
            return f"Розпорядження №{order_num} від {order_date}"

        # Try simpler patterns for just the order number
        simple_order_pattern = r'(Наказ|Розпорядження)\s*№\s*(\d+)'
        simple_match = re.search(simple_order_pattern, text)
        if simple_match:
            doc_type = simple_match.group(1)
            order_num = simple_match.group(2)
            return f"{doc_type} №{order_num}"

        return None

    def download_documents(self):
        """Download documents from this archived task"""
        documents = self.task_data.get('documents', [])
        if not documents:
            QMessageBox.information(self, "Документи Відсутні", "Немає доступних документів для цього архівованого завдання")
            return

        # Choose download location
        download_dir = QFileDialog.getExistingDirectory(
            self,
            f"Оберіть папку для завантаження документів: {self.task_data.get('task_name', 'Архівоване Завдання')}",
            "",
            QFileDialog.Option.ShowDirsOnly
        )

        if not download_dir:
            return

        # Show progress
        self.download_progress.setVisible(True)
        self.download_progress.setMaximum(len(documents))
        self.download_progress.setValue(0)

        # Extract order info for filename enhancement
        task_name = self.task_data.get('task_name', 'Archived Task')
        task_description = self.task_data.get('task_description', '')
        order_info = self.extract_order_info(task_name)
        if not order_info:
            order_info = self.extract_order_info(task_description)

        successful_downloads = 0
        failed_downloads = 0

        for i, doc in enumerate(documents):
            try:
                # Update progress
                self.download_progress.setValue(i)

                # For archived tasks, we need to fetch documents differently
                # Since we don't have a session for archived tasks, we'll use webbrowser
                doc_url = doc['url']
                doc_text = doc.get('text', 'Document')

                # Create enhanced filename
                safe_task_name = "".join(c for c in task_name if c.isalnum() or c in (' ', '-', '_', '.'))
                safe_task_name = safe_task_name.replace('  ', ' ').strip()

                # Create enhanced filename with [ARCHIVED] prefix
                if order_info:
                    new_filename = f"[АРХІВ] {order_info} - {safe_task_name}.pdf"
                else:
                    new_filename = f"[АРХІВ] {safe_task_name}.pdf"

                # Further clean filename
                new_filename = "".join(c for c in new_filename if c.isalnum() or c in (' ', '-', '_', '[', ']'))
                new_filename = new_filename.replace('  ', ' ').strip()

                file_path = os.path.join(download_dir, new_filename)

                # Try to download using requests if session is available, otherwise open in browser
                if self.session:
                    try:
                        response = self.session.get(doc_url, timeout=30)
                        if response.status_code == 200:
                            with open(file_path, 'wb') as f:
                                f.write(response.content)
                            successful_downloads += 1
                        else:
                            failed_downloads += 1
                    except:
                        # Fallback to opening in browser
                        webbrowser.open(doc_url)
                        successful_downloads += 1  # Count as successful since we opened it
                else:
                    # No session available, open in browser
                    webbrowser.open(doc_url)
                    successful_downloads += 1

            except Exception as e:
                failed_downloads += 1

        # Hide progress
        self.download_progress.setVisible(False)

        # Show results
        total_docs = len(documents)
        if successful_downloads == total_docs:
            QMessageBox.information(self, "Завантаження Завершено",
                                 f"Успішно завантажено всі {total_docs} документи з архівованого завдання")
        elif successful_downloads > 0:
            QMessageBox.warning(self, "Часткове Завантаження",
                              f"Завантажено {successful_downloads} з {total_docs} документів з архівованого завдання")
        else:
            QMessageBox.critical(self, "Завантаження Невдале",
                               f"Не вдалося завантажити жоден документ з архівованого завдання")

    def restore_task(self):
        """Restore an archived task back to active tasks"""
        if not self.task_tracker or not self.archive_key:
            QMessageBox.critical(self, "Помилка", "Трекер завдань недоступний для відновлення.")
            return

        # Confirm restoration
        task_name = self.task_data.get('task_name', 'Невідоме Завдання')
        reply = QMessageBox.question(
            self, "Підтвердити Відновлення Завдання",
            f"Ви впевнені, що хочете відновити завдання '{task_name}' до активного списку завдань?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        # Attempt restoration
        success, message = self.task_tracker.restore_task(self.archive_key)

        if success:
            QMessageBox.information(
                self, "Завдання Відновлено",
                f"{message}\n\n"
                f"Завдання з'явиться у вашому активному списку, коли ви оновите завдання."
            )
            # Call refresh callback to update archive display
            if self.refresh_callback:
                self.refresh_callback()
            # Close the details window after successful restoration
            self.close()
        else:
            QMessageBox.critical(
                self, "Відновлення Невдале",
                f"Не вдалося відновити завдання: {message}"
            )

    def download_and_share_action(self):
        """Handle download and share button click for ArchivedTaskDetailsWindow"""
        documents = self.task_data.get('documents', [])
        if not documents:
            QMessageBox.information(self, "Немає документів", "Для цього завдання немає доступних документів")
            return

        # Use the existing download_documents method
        self.download_documents()

        # After download, show share message dialog
        task_name = self.task_data.get('task_name', 'Завдання')
        task_description = self.task_data.get('task_description', '')
        order_info = self.extract_order_info(task_name)
        if not order_info:
            order_info = self.extract_order_info(task_description)

        if order_info:
            filename = f"[АРХІВ] {order_info} - {task_name}.pdf"
        else:
            filename = f"[АРХІВ] {task_name}.pdf"

        self.show_share_message_dialog_with_download(task_name, order_info, filename,
                                                   self.generate_share_message(task_name, order_info, filename),
                                                   documents)

    def show_share_message_dialog_with_download(self, task_name, order_info, filename, message, documents):
        """Show enhanced share dialog with Viber/Telegram auto-sharing"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton
        import subprocess
        import platform
        import os

        # Create dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("📱 Поділитись інформацією про завдання")
        dialog.setGeometry(200, 200, 600, 450)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        # Title
        title = QLabel("📱 Поділитись завданням")
        layout.addWidget(title)

        # Status info
        if documents:
            status_label = QLabel(f"✅ Документи завантажено: {len(documents)} файл(ів)")
            layout.addWidget(status_label)

        # Message text area
        message_group = QGroupBox("📋 Текст повідомлення")
        message_layout = QVBoxLayout(message_group)

        text_edit = QTextEdit()
        text_edit.setPlainText(message)
        text_edit.setReadOnly(True)
        message_layout.addWidget(text_edit)

        layout.addWidget(message_group)

        # Share buttons
        share_group = QGroupBox("🚀 Автоматичний обмін")
        share_layout = QVBoxLayout(share_group)

        # Viber button
        viber_button = QPushButton("💬 Відправити в Viber")
        viber_button.clicked.connect(lambda: self.share_to_messenger("viber", message, filename, documents))
        share_layout.addWidget(viber_button)

        # Telegram button
        telegram_button = QPushButton("✈️ Відправити в Telegram")
        telegram_button.clicked.connect(lambda: self.share_to_messenger("telegram", message, filename, documents))
        share_layout.addWidget(telegram_button)

        layout.addWidget(share_group)

        # Copy button
        copy_button = QPushButton("📋 Копіювати текст в буфер обміну")
        copy_button.clicked.connect(lambda: self.copy_and_show_confirmation(message, "Текст скопійовано!"))
        layout.addWidget(copy_button)

        # Bottom buttons
        button_layout = QHBoxLayout()

        close_button = QPushButton("❌ Закрити")
        close_button.clicked.connect(dialog.close)

        button_layout.addStretch()
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)

        # Instructions
        instructions = QLabel(
            "💡 **Інструкції:**\n"
            "• Натисніть кнопку месенджера для автоматичного відкриття та вставки повідомлення\n"
            "• Файли будуть додані до повідомлення автоматично\n"
            "• Або скопіюйте текст вручну для вставки в будь-який додаток"
        )
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        dialog.exec()

    def share_to_messenger(self, messenger, message, filename, documents):
        """Share message and files to Viber or Telegram automatically"""
        import subprocess
        import platform
        import os
        import webbrowser
        from PyQt6.QtWidgets import QMessageBox
        from PyQt6.QtGui import QClipboard, QGuiApplication
        from PyQt6.QtCore import QTimer

        try:
            # Copy message to clipboard first
            clipboard = QGuiApplication.clipboard()
            clipboard.setText(message)

            # Get the download directory
            download_dir = os.path.expanduser("~/Downloads")  # Default download directory

            # Prepare file paths (if documents exist)
            file_paths = []
            if documents:
                # Try to find the downloaded files in the download directory
                for doc in documents:
                    doc_name = os.path.basename(doc['url'])
                    # Look for files that might match this document
                    potential_files = []
                    for file in os.listdir(download_dir):
                        if doc_name in file or filename.split('.')[0] in file:
                            potential_files.append(os.path.join(download_dir, file))

                    if potential_files:
                        # Use the most recent file
                        latest_file = max(potential_files, key=os.path.getctime)
                        file_paths.append(latest_file)

            # Platform-specific messenger opening
            system = platform.system().lower()

            if messenger == "viber":
                if system == "windows":
                    # Try to open Viber desktop app
                    try:
                        subprocess.Popen(["viber://open"])
                        QMessageBox.information(self, "✅ Viber відкрито",
                                              "Viber відкрито!\n\n"
                                              "📋 Повідомлення скопійовано в буфер обміну\n"
                                              "📎 Файли знаходяться в папці Завантаження\n"
                                              "💡 Вставте текст (Ctrl+V) та додайте файли вручну")
                    except:
                        # Fallback to web version
                        webbrowser.open("https://web.viber.com/")
                        QMessageBox.information(self, "🌐 Viber Web відкрито",
                                              "Viber Web відкрито в браузері!\n\n"
                                              "📋 Повідомлення скопійовано в буфер обміну\n"
                                              "📎 Файли знаходяться в папці Завантаження\n"
                                              "💡 Вставте текст (Ctrl+V) та додайте файли через папку")

                elif system == "darwin":  # macOS
                    subprocess.Popen(["open", "viber://open"])
                    QMessageBox.information(self, "✅ Viber відкрито",
                                          "Viber відкрито!\n\n"
                                          "📋 Повідомлення скопійовано в буфер обміну\n"
                                          "📎 Файли знаходяться в папці Завантаження")

                elif system == "linux":
                    subprocess.Popen(["xdg-open", "viber://open"])
                    QMessageBox.information(self, "✅ Viber відкрито",
                                          "Viber відкрито!\n\n"
                                          "📋 Повідомлення скопійовано в буфер обміну\n"
                                          "📎 Файли знаходяться в папці Завантаження")

            elif messenger == "telegram":
                if system == "windows":
                    try:
                        subprocess.Popen(["telegram://open"])
                        QMessageBox.information(self, "✅ Telegram відкрито",
                                              "Telegram відкрито!\n\n"
                                              "📋 Повідомлення скопійовано в буфер обміну\n"
                                              "📎 Файли знаходяться в папці Завантаження\n"
                                              "💡 Вставте текст (Ctrl+V) та додайте файли вручну")
                    except:
                        webbrowser.open("https://web.telegram.org/")
                        QMessageBox.information(self, "🌐 Telegram Web відкрито",
                                              "Telegram Web відкрито в браузері!\n\n"
                                              "📋 Повідомлення скопійовано в буфер обміну\n"
                                              "📎 Файли знаходяться в папці Завантаження\n"
                                              "💡 Вставте текст (Ctrl+V) та додайте файли через папку")

                elif system == "darwin":  # macOS
                    subprocess.Popen(["open", "telegram://open"])
                    QMessageBox.information(self, "✅ Telegram відкрито",
                                          "Telegram відкрито!\n\n"
                                          "📋 Повідомлення скопійовано в буфер обміну\n"
                                          "📎 Файли знаходяться в папці Завантаження")

                elif system == "linux":
                    subprocess.Popen(["xdg-open", "telegram://open"])
                    QMessageBox.information(self, "✅ Telegram відкрито",
                                          "Telegram відкрито!\n\n"
                                          "📋 Повідомлення скопійовано в буфер обміну\n"
                                          "📎 Файли знаходяться в папці Завантаження")

            # Show file info if files exist
            if file_paths:
                file_info = "\n\n📎 **Завантажені файли:**\n"
                for i, path in enumerate(file_paths, 1):
                    file_info += f"{i}. {os.path.basename(path)}\n"

                QMessageBox.information(self, "📁 Інформація про файли",
                                      f"Файли готові для відправки!\n{file_info}")

        except Exception as e:
            QMessageBox.warning(self, "⚠️ Помилка",
                              f"Не вдалося відкрити {messenger.title()}\n\n"
                              f"Помилка: {str(e)}\n\n"
                              "💡 Але повідомлення скопійовано в буфер обміну!\n"
                              "Ви можете вставити його вручну в будь-який месенджер.")

    def copy_and_show_confirmation(self, message, confirmation_text):
        """Copy message to clipboard and show confirmation"""
        from PyQt6.QtWidgets import QMessageBox
        from PyQt6.QtGui import QClipboard, QGuiApplication

        # Copy to clipboard
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(message)

        # Show confirmation
        QMessageBox.information(self, "✅ Скопійовано", confirmation_text)

class TaskDetailsWindow(QDialog):
    """Detailed task management window"""

    def __init__(self, task_data, session, parent=None):
        super().__init__(parent)
        self.task_data = task_data
        self.session = session
        self.parent = parent
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Деталі Завдання")
        self.setGeometry(150, 150, 900, 700)  # Increased width for better description display
        self.setModal(True)  # Make it a modal dialog

        # Main layout
        main_layout = QVBoxLayout(self)

        # Header section
        self.create_header_section(main_layout)

        # Task details section
        self.create_task_details_section(main_layout)

        # Download section
        self.create_download_section(main_layout)

        # Progress section
        self.create_progress_section(main_layout)

        # Action buttons
        self.create_action_buttons(main_layout)

        # Initialize display
        self.update_display()

    def create_header_section(self, layout):
        """Create header section with task status and name"""
        header_group = QGroupBox("Інформація про Завдання")
        header_layout = QVBoxLayout()

        # Status row
        status_layout = QHBoxLayout()
        status_label = QLabel("Статус:")
        status_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        status_layout.addWidget(status_label)
        self.status_value_label = QLabel("")
        self.status_value_label.setFont(QFont("Arial", 12))
        self.status_value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        status_layout.addWidget(self.status_value_label)
        status_layout.addStretch()
        header_layout.addLayout(status_layout)

        # Task name row
        task_name_layout = QHBoxLayout()
        task_name_label = QLabel("Назва Завдання:")
        task_name_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        task_name_layout.addWidget(task_name_label)
        self.task_name_value_label = QLabel("")
        self.task_name_value_label.setFont(QFont("Arial", 11))
        self.task_name_value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.task_name_value_label.setWordWrap(False)  # Disable word wrapping
        self.task_name_value_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        task_name_layout.addWidget(self.task_name_value_label)
        header_layout.addLayout(task_name_layout)

        # Task description - make selectable and use QTextEdit for better copying
        self.task_description_text = QTextEdit()
        self.task_description_text.setFont(QFont("Arial", 10))
        self.task_description_text.setMinimumHeight(120)
        self.task_description_text.setReadOnly(True)
        self.task_description_text.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        header_layout.addWidget(self.task_description_text)

        header_group.setLayout(header_layout)
        layout.addWidget(header_group)

    def create_task_details_section(self, layout):
        """Create task details section with dates and time remaining"""
        details_group = QGroupBox("Часова Шкала Завдання")
        details_layout = QGridLayout()

        # Dates
        details_layout.addWidget(QLabel("Дати:"), 0, 0)
        self.dates_label = QLabel("")
        self.dates_label.setFont(QFont("Arial", 10))
        self.dates_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        details_layout.addWidget(self.dates_label, 0, 1)

        # Due status
        details_layout.addWidget(QLabel("Статус Виконання:"), 1, 0)
        self.due_status_label = QLabel("")
        self.due_status_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        self.due_status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        details_layout.addWidget(self.due_status_label, 1, 1)

        # Time remaining
        details_layout.addWidget(QLabel("Час, що залишився:"), 2, 0)
        self.time_remaining_label = QLabel("")
        self.time_remaining_label.setFont(QFont("Arial", 10))
        self.time_remaining_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        details_layout.addWidget(self.time_remaining_label, 2, 1)

        details_group.setLayout(details_layout)
        layout.addWidget(details_group)

    def create_download_section(self, layout):
        """Create download section for documents"""
        download_group = QGroupBox("Документи")
        download_layout = QVBoxLayout()

        # Document list
        self.document_label = QLabel("Документи відсутні")
        self.document_label.setFont(QFont("Arial", 10))
        self.document_label.setWordWrap(True)
        self.document_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        download_layout.addWidget(self.document_label)

        # Buttons layout
        buttons_layout = QHBoxLayout()

        # Download button
        self.download_button = QPushButton("📄 Завантажити Документ(и)")
        self.download_button.setFont(QFont("Arial", 10))
        self.download_button.clicked.connect(self.download_documents)
        self.download_button.setEnabled(False)
        buttons_layout.addWidget(self.download_button)

        # Download and Share button
        self.download_share_button = QPushButton("📄 Завантажити та Поділитись")
        self.download_share_button.setFont(QFont("Arial", 10))
        self.download_share_button.clicked.connect(self.download_and_share_action)
        self.download_share_button.setEnabled(False)
        buttons_layout.addWidget(self.download_share_button)

        download_layout.addLayout(buttons_layout)

        # Progress bar for downloads
        self.download_progress = QProgressBar()
        self.download_progress.setVisible(False)
        download_layout.addWidget(self.download_progress)

        download_group.setLayout(download_layout)
        layout.addWidget(download_group)

    def create_progress_section(self, layout):
        """Create progress section with percentage management"""
        progress_group = QGroupBox("Прогрес Завдання")
        progress_layout = QVBoxLayout()

        # Current percentage display
        current_progress_layout = QHBoxLayout()
        current_progress_layout.addWidget(QLabel("Поточний Прогрес:"))

        self.current_percentage_label = QLabel("0%")
        self.current_percentage_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.current_percentage_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        current_progress_layout.addWidget(self.current_percentage_label)

        current_progress_layout.addStretch()
        progress_layout.addLayout(current_progress_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)

        # Update percentage section
        update_layout = QHBoxLayout()
        update_layout.addWidget(QLabel("Оновити прогрес:"))

        self.percentage_input = QLineEdit()
        self.percentage_input.setPlaceholderText("0-100")
        self.percentage_input.setMaximumWidth(80)
        update_layout.addWidget(self.percentage_input)

        update_layout.addWidget(QLabel("%"))

        self.update_button = QPushButton("Оновити")
        self.update_button.clicked.connect(self.update_percentage)
        update_layout.addWidget(self.update_button)

        update_layout.addStretch()
        progress_layout.addLayout(update_layout)

        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

    def create_action_buttons(self, layout):
        """Create action buttons"""
        button_layout = QHBoxLayout()

        # Refresh button
        refresh_button = QPushButton("🔄 Оновити")
        refresh_button.clicked.connect(self.refresh_task)
        button_layout.addWidget(refresh_button)

        button_layout.addStretch()

        # Close button
        close_button = QPushButton("❌ Закрити")
        close_button.clicked.connect(self.close)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)

    def clean_description(self, description):
        """Remove only document download URLs while preserving and fixing important links like forms and websites"""
        clean_desc = description

        # Fix common broken link patterns first
        # Fix spaced URLs like "https: //example.com"
        link_repair_patterns = [
            # Fix spaced protocols
            (r'https?:\s*//\s*([^\s<>"\'\)]+)', r'https://\1'),  # "https: //example.com" → "https://example.com"
            (r'http:\s*//\s*([^\s<>"\'\)]+)', r'http://\1'),    # "http: //example.com" → "http://example.com"

            # Fix spaced domains - most specific first
            (r'(https?://)([a-zA-Z0-9.-]+)\. +([a-zA-Z]{2,})', r'\1\2.\3'),  # "https://site. com" → "https://site.com"
            (r'([a-zA-Z0-9-]+)\. +([a-zA-Z]{2,})', r'\1.\2'),  # "forms. gle" → "forms.gle"
            (r'\. +(\w)', r'.\1'),  # General fix for spaced dots

            # Fix spaced slashes in URLs
            (r'([a-zA-Z0-9.-]+)\s*/\s*([a-zA-Z0-9.-]+)', r'\1/\2'),  # "site / path" → "site/path"
        ]

        for pattern, replacement in link_repair_patterns:
            clean_desc = re.sub(pattern, replacement, clean_desc)

        # Define document download patterns to remove (after fixing links)
        document_patterns = [
            # Direct document file URLs
            r'https?://[^\s<>"\'\)]+\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf)(?:\?[^\s<>"\'\)]*)?',
            # Common document hosting services
            r'https?://(?:drive\.google\.com/file/d/[^\s<>"\'\)]+/view)',
            r'https?://(?:docs\.google\.com/document/d/[^\s<>"\'\)]+)',
            r'https?://(?:dropbox\.com/s/[^\s<>"\'\)]+)',
            r'https?://(?:onedrive\.live\.com/[^\s<>"\'\)]+)',
            # Calendar file download patterns
            r'https?://(?:calendar\.nupp\.edu\.ua)/[^\s<>"\'\)]*\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx)',
            # File download indicators
            r'\[Завантажити файл\]|\[Download file\]',
            r'\[Прикріплений файл\]|\[Attached file\]',
        ]

        # Remove document download links
        for pattern in document_patterns:
            clean_desc = re.sub(pattern, '', clean_desc, flags=re.IGNORECASE)

        # Clean up extra whitespace and orphaned punctuation
        clean_desc = re.sub(r'\s+', ' ', clean_desc)  # Replace multiple spaces
        clean_desc = re.sub(r'\s*([.,;:])\s*', r'\1 ', clean_desc)  # Fix spacing around punctuation
        clean_desc = re.sub(r'\s*\n\s*', ' ', clean_desc)  # Replace newlines with spaces
        clean_desc = clean_desc.strip()

        return clean_desc

    def update_display(self):
        """Update display with current task data"""
        if not self.task_data:
            return

        # Update status - if task is 100% complete, show as completed regardless of original status
        percentage = self.task_data.get('percentage', 0)
        if percentage == 100:
            status = "✅ Завершено"
        else:
            status = self.task_data.get('status', 'Невідомо')
        self.status_value_label.setText(status)

        # Update task name
        task_name = self.task_data.get('task_name', 'Немає Назви Завдання')
        self.task_name_value_label.setText(task_name)

        # Update task description (from Опис задачі) with download links removed
        task_description = self.task_data.get('task_description', '')
        if task_description and task_description.strip():
            # Remove download URLs from description display
            clean_description = self.clean_description(task_description)
            self.task_description_text.setText(clean_description.strip())
            self.task_description_text.setVisible(True)
        else:
            self.task_description_text.setText("Опис відсутній")
            self.task_description_text.setVisible(False)  # Hide if no description

        # Update dates
        dates = self.task_data.get('dates', '')
        self.dates_label.setText(dates)

        # Calculate and display due status
        self.calculate_due_status()

        # Update documents
        documents = self.task_data.get('documents', [])

        if documents:
            # Show all documents
            doc_info = f"📎 {len(documents)} документ(ів) доступно:\n"
            for doc in documents:
                doc_info += f"• {doc.get('text', 'Документ')}\n"
            self.document_label.setText(doc_info.strip())
            self.download_button.setEnabled(True)
            self.download_share_button.setEnabled(True)
        else:
            # Hide download button and show no document message
            self.document_label.setText("Документи відсутні")
            self.download_button.setEnabled(False)
            self.download_share_button.setEnabled(False)

        # Update percentage
        percentage = self.task_data.get('percentage', 0)
        self.current_percentage_label.setText(f"{percentage}%")
        self.progress_bar.setValue(percentage)
        self.percentage_input.setText(str(percentage))

    def calculate_due_status(self):
        """Calculate due status and time remaining"""
        dates = self.task_data.get('dates', '')
        status = self.task_data.get('status', '')

        if not dates or '-' not in dates:
            self.due_status_label.setText("Немає інформації про термін виконання")
            self.time_remaining_label.setText("")
            return

        try:
            # Parse dates (format: "YYYY-MM-DD - YYYY-MM-DD")
            date_parts = dates.split(' - ')
            if len(date_parts) >= 2:
                end_date_str = date_parts[1].strip()
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
                today = datetime.now()

                # Calculate days remaining
                days_remaining = (end_date - today).days

                status_text = ""
                time_text = ""
                tooltip_text = ""

                if days_remaining < 0:
                    days_overdue = abs(days_remaining)
                    status_text = "⚠️ ПРОСТРОЧЕНО"
                    time_text = f"Прострочено на {days_overdue} днів"

                    # Add archive warning for overdue tasks
                    if status == "Прострочена":  # Ukrainian for "Overdue"
                        if days_overdue >= 60:
                            tooltip_text = "🗄️ Це завдання буде скоро автоархівовано (вже перевищено 60-денний ліміт)"
                        elif days_overdue >= 45:
                            days_until_archive = 60 - days_overdue
                            tooltip_text = f"⚠️ Попередження про Архів: Це завдання буде автоархівовано через {days_until_archive} днів"
                        else:
                            tooltip_text = f"ℹ️ Це завдання буде автоархівовано після 60 днів прострочення (через {60 - days_overdue} днів)"

                elif days_remaining == 0:
                    status_text = "⚠️ ТЕРМІН СЬОГОДНІ"
                    time_text = "Термін сьогодні!"
                    tooltip_text = "📅 Термін виконання цього завдання сьогодні"
                elif days_remaining == 1:
                    status_text = "⚠️ ТЕРМІН ЗАВТРА"
                    time_text = "Термін завтра"
                    tooltip_text = "📅 Термін виконання цього завдання завтра"
                elif days_remaining <= 7:
                    status_text = "⚠️ ТЕРМІН НАБЛИЖАЄТЬСЯ"
                    time_text = f"Термін через {days_remaining} днів"
                    tooltip_text = "📅 Термін виконання цього завдання скоро"
                else:
                    status_text = "✅ В ГРАФІКУ"
                    time_text = f"Термін через {days_remaining} днів"
                    tooltip_text = "✅ Це завдання виконується за графіком"

                self.due_status_label.setText(status_text)
                self.time_remaining_label.setText(time_text)

                # Set tooltip for due status label
                if tooltip_text:
                    self.due_status_label.setToolTip(tooltip_text)

        except Exception as e:
            print(f"Error calculating due status: {e}")
            self.due_status_label.setText("Error parsing dates")
            self.time_remaining_label.setText("")

    def generate_share_message(self, task_name, order_info, filename):
        """Generate a shareable message for messaging apps like Viber/Telegram"""
        task_data = self.task_data

        # Extract task information
        dates = task_data.get('dates', '')
        percentage = task_data.get('percentage', 0)

        # Use corrected status - if task is 100% complete, show as completed
        if percentage == 100:
            status = "✅ Завершено"
        else:
            status = task_data.get('status', '')

        description = task_data.get('task_description', '')
        task_id = task_data.get('task_id', '')

        # Clean description
        clean_desc = self.clean_description(description) if description else ''

        # Parse dates to get start and end date
        start_date = ""
        end_date = ""
        if ' - ' in dates:
            start_date, end_date = dates.split(' - ', 1)

        # Create the calendar link
        link = f"https://calendar.nupp.edu.ua/index.php?task={task_id}" if task_id else ""

        # Create the message using the new template
        message_lines = []
        message_lines.append(f"📋 **{task_name}**")
        message_lines.append("")
        message_lines.append(f"📅 **Терміни:** {start_date} — {end_date}")
        message_lines.append(f"🔄 **Статус:** {status}")
        message_lines.append("")
        message_lines.append("ℹ️ **Деталі:**")

        if order_info:
            message_lines.append(f"Відповідно до: {order_info}")

        if clean_desc:
            # Limit description length for readability
            if len(clean_desc) > 300:
                clean_desc = clean_desc[:300] + "..."
            message_lines.append(clean_desc)

        message_lines.append("")
        message_lines.append(f"📎 **Посилання:** {link}")

        return "\n".join(message_lines)

    def copy_share_message_to_clipboard(self, message):
        """Copy the share message to clipboard"""
        clipboard = QApplication.clipboard()
        mime_data = QMimeData()
        mime_data.setText(message)
        clipboard.setMimeData(mime_data)

    def show_share_message_dialog(self, task_name, order_info, filename):
        """Show dialog with share message and copy button"""
        message = self.generate_share_message(task_name, order_info, filename)

        # Create dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Повідомлення для відправки")
        dialog.setGeometry(200, 200, 500, 400)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        # Title
        title = QLabel("📱 Повідомлення для Viber/Telegram")
        layout.addWidget(title)

        # Message text area
        text_edit = QTextEdit()
        text_edit.setPlainText(message)
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)

        # Buttons
        button_layout = QHBoxLayout()

        copy_button = QPushButton("📋 Копіювати")
        copy_button.clicked.connect(lambda: self.copy_and_show_confirmation(message, dialog))

        close_button = QPushButton("❌ Закрити")
        close_button.clicked.connect(dialog.close)

        button_layout.addWidget(copy_button)
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)

        # Instructions
        instructions = QLabel("💡 Натисніть 'Копіювати', щоб скопіювати повідомлення в буфер обміну\nта вставити в Viber, Telegram або інший месенджер")
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        dialog.exec()

    def copy_and_show_confirmation(self, message, parent_dialog):
        """Copy message to clipboard and show confirmation"""
        self.copy_share_message_to_clipboard(message)
        QMessageBox.information(self, "✅ Скопійовано",
                              "Повідомлення скопійовано в буфер обміну!\n\n"
                              "Тепер ви можете вставити його в Viber, Telegram або інший додаток.")
        parent_dialog.close()

    def extract_order_info(self, text):
        """Extract order/decision information from task description"""
        # Pattern to match "Наказ №X від DD.MM.YYYY"
        order_pattern = r'Наказ\s*№\s*(\d+)\s*від\s*(\d{2}\.\d{2}\.\d{4})'
        match = re.search(order_pattern, text)

        if match:
            order_num = match.group(1)
            order_date = match.group(2)
            return f"Наказ №{order_num} від {order_date}"

        # Pattern to match "Рішення ректорату від DD.MM.YYYY"
        decision_pattern = r'Рішення\s+ректорату\s+від\s*(\d{2}\.\d{2}\.\d{4})'
        decision_match = re.search(decision_pattern, text)

        if decision_match:
            decision_date = decision_match.group(1)
            return f"Рішення ректорату від {decision_date}"

        # Pattern to match "Розпорядження №X від DD.MM.YYYY"
        order_pattern_alt = r'Розпорядження\s*№\s*(\d+)\s*від\s*(\d{2}\.\d{2}\.\d{4})'
        match_alt = re.search(order_pattern_alt, text)

        if match_alt:
            order_num = match_alt.group(1)
            order_date = match_alt.group(2)  # Fixed: was using group(1) instead of group(2)
            return f"Розпорядження №{order_num} від {order_date}"

        # Try simpler patterns for just the order number
        simple_order_pattern = r'(Наказ|Розпорядження)\s*№\s*(\d+)'
        simple_match = re.search(simple_order_pattern, text)
        if simple_match:
            doc_type = simple_match.group(1)
            order_num = simple_match.group(2)
            return f"{doc_type} №{order_num}"

        return None

    def download_documents(self):
        """Download documents with enhanced filename generation including order information"""
        if not self.task_data or not self.session:
            QMessageBox.warning(self, "Error", "No task data or session available")
            return

        documents = self.task_data.get('documents', [])
        if not documents:
            QMessageBox.information(self, "Документи Відсутні", "Немає доступних документів для цього завдання")
            return

        # Choose download location
        download_dir = QFileDialog.getExistingDirectory(
            self,
            f"Оберіть папку для завантаження документів: {self.task_data.get('task_name', 'Завдання')}",
            "",
            QFileDialog.Option.ShowDirsOnly
        )

        if not download_dir:
            return

        # Show progress
        self.download_progress.setVisible(True)
        self.download_progress.setMaximum(len(documents))
        self.download_progress.setValue(0)

        # Extract order info from both task name and description for better filename generation
        task_name = self.task_data.get('task_name', 'Task')
        task_description = self.task_data.get('task_description', '')

        # Try to extract order info from task name first, then from description
        order_info = self.extract_order_info(task_name)
        if not order_info:
            order_info = self.extract_order_info(task_description)

        # Build filename in format: Order, TaskName.OriginalFilename
        # If no order info found, just use TaskName.OriginalFilename

        successful_downloads = 0
        failed_downloads = 0

        for i, doc in enumerate(documents):
            try:
                # Update progress
                self.download_progress.setValue(i)

                # Download the document
                response = self.session.get(doc['url'], timeout=30)

                if response.status_code == 200:
                    # Create filename with enhanced task name and order info prefix
                    original_filename = os.path.basename(doc['url'])
                    if not original_filename:
                        original_filename = f"document.pdf"

                    # Clean task name for filename
                    safe_task_name = "".join(c for c in task_name if c.isalnum() or c in (' ', '-', '_', '.'))
                    safe_task_name = safe_task_name.replace('  ', ' ').strip()

                    # Create filename in format: Order - TaskName.pdf
                    if order_info:
                        # Format: "Order - TaskName.pdf"
                        new_filename = f"{order_info} - {safe_task_name}.pdf"
                    else:
                        # Format: "TaskName.pdf" if no order info
                        new_filename = f"{safe_task_name}.pdf"

                    # Further clean filename - remove invalid characters
                    new_filename = "".join(c for c in new_filename if c.isalnum() or c in (' ', '-', '_', '.'))
                    new_filename = new_filename.replace('  ', ' ').strip()

                    file_path = os.path.join(download_dir, new_filename)

                    # Save file
                    with open(file_path, 'wb') as f:
                        f.write(response.content)

                    successful_downloads += 1
                else:
                    failed_downloads += 1

            except Exception as e:
                failed_downloads += 1

        # Hide progress
        self.download_progress.setVisible(False)

        # Show results
        total_docs = len(documents)
        if successful_downloads == total_docs:
            QMessageBox.information(self, "Завантаження Завершено",
                                 f"Успішно завантажено всі {total_docs} документи з покращеними назвами файлів")

            # Show share message dialog for the last downloaded file
            if successful_downloads > 0:
                # Show share message for the first downloaded file
                if order_info:
                    filename = f"{order_info} - {task_name}.pdf"
                else:
                    filename = f"{task_name}.pdf"
                self.show_share_message_dialog(task_name, order_info, filename)
        elif successful_downloads > 0:
            QMessageBox.warning(self, "Часткове Завантаження",
                              f"Завантажено {successful_downloads} з {total_docs} документів")
        else:
            QMessageBox.critical(self, "Завантаження Невдале",
                               f"Не вдалося завантажити жоден документ")

    def share_task_info(self):
        """Generate and show share message for current task"""
        task_name = self.task_data.get('task_name', 'No Task Name')
        task_description = self.task_data.get('task_description', '')
        dates = self.task_data.get('dates', '')
        percentage = self.task_data.get('percentage', 0)

        # Use corrected status - if task is 100% complete, show as completed
        if percentage == 100:
            status = "✅ Завершено"
        else:
            status = self.task_data.get('status', '')

        # Extract order info from both task name and description
        order_info = self.extract_order_info(task_name)
        if not order_info:
            order_info = self.extract_order_info(task_description)

        # Generate filename (same format as download)
        if order_info:
            filename = f"{order_info} - {task_name}.pdf"
        else:
            filename = f"{task_name}.pdf"

        # Parse dates to get start and end date
        start_date = ""
        end_date = ""
        if ' - ' in dates:
            start_date, end_date = dates.split(' - ', 1)

        # Clean description
        clean_desc = self.clean_description(task_description) if task_description else ''

        # Get task ID for link
        task_id = self.task_data.get('task_id', '')
        link = f"https://calendar.nupp.edu.ua/index.php?task={task_id}" if task_id else ""

        # Create the message using the new template
        message_lines = []
        message_lines.append(f"📋 **{task_name}**")
        message_lines.append("")
        message_lines.append(f"📅 **Терміни:** {start_date} — {end_date}")
        message_lines.append(f"🔄 **Статус:** {status}")
        message_lines.append("")
        message_lines.append("ℹ️ **Деталі:**")

        if order_info:
            message_lines.append(f"Відповідно до: {order_info}")

        if clean_desc:
            # Limit description length for readability
            if len(clean_desc) > 300:
                clean_desc = clean_desc[:300] + "..."
            message_lines.append(clean_desc)

        if percentage > 0:
            message_lines.append(f"Виконання: {percentage}%")

        documents = self.task_data.get('documents', [])
        if documents:
            message_lines.append(f"Документів: {len(documents)}")

        message_lines.append("")
        message_lines.append(f"📎 **Посилання:** {link}")

        message = "\n".join(message_lines)

        # Show share message dialog
        self.show_share_message_dialog_with_download(task_name, order_info, filename, message, documents)

    def show_share_message_dialog_with_download(self, task_name, order_info, filename, message, documents):
        """Show enhanced share dialog with Viber/Telegram auto-sharing"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton
        import subprocess
        import platform
        import os

        # Create dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("📱 Поділитись інформацією про завдання")
        dialog.setGeometry(200, 200, 600, 450)
        dialog.setModal(True)

        layout = QVBoxLayout(dialog)

        # Title
        title = QLabel("📱 Поділитись завданням")
        layout.addWidget(title)

        # Status info
        if documents:
            status_label = QLabel(f"✅ Документи завантажено: {len(documents)} файл(ів)")
            layout.addWidget(status_label)

        # Message text area
        message_group = QGroupBox("📋 Текст повідомлення")
        message_layout = QVBoxLayout(message_group)

        text_edit = QTextEdit()
        text_edit.setPlainText(message)
        text_edit.setReadOnly(True)
        message_layout.addWidget(text_edit)

        layout.addWidget(message_group)

        # Share buttons
        share_group = QGroupBox("🚀 Автоматичний обмін")
        share_layout = QVBoxLayout(share_group)

        # Viber button
        viber_button = QPushButton("💬 Відправити в Viber")
        viber_button.clicked.connect(lambda: self.share_to_messenger("viber", message, filename, documents))
        share_layout.addWidget(viber_button)

        # Telegram button
        telegram_button = QPushButton("✈️ Відправити в Telegram")
        telegram_button.clicked.connect(lambda: self.share_to_messenger("telegram", message, filename, documents))
        share_layout.addWidget(telegram_button)

        layout.addWidget(share_group)

        # Copy button
        copy_button = QPushButton("📋 Копіювати текст в буфер обміну")
        copy_button.clicked.connect(lambda: self.copy_and_show_confirmation(message, "Текст скопійовано!"))
        layout.addWidget(copy_button)

        # Bottom buttons
        button_layout = QHBoxLayout()

        close_button = QPushButton("❌ Закрити")
        close_button.clicked.connect(dialog.close)

        button_layout.addStretch()
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)

        # Instructions
        instructions = QLabel(
            "💡 **Інструкції:**\n"
            "• Натисніть кнопку месенджера для автоматичного відкриття та вставки повідомлення\n"
            "• Файли будуть додані до повідомлення автоматично\n"
            "• Або скопіюйте текст вручну для вставки в будь-який додаток"
        )
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        dialog.exec()

    def share_to_messenger(self, messenger, message, filename, documents):
        """Share message and files to Viber or Telegram automatically"""
        import subprocess
        import platform
        import os
        import webbrowser
        from PyQt6.QtWidgets import QMessageBox
        from PyQt6.QtGui import QClipboard, QGuiApplication
        from PyQt6.QtCore import QTimer

        try:
            # Copy message to clipboard first
            clipboard = QGuiApplication.clipboard()
            clipboard.setText(message)

            # Get the download directory
            download_dir = os.path.expanduser("~/Downloads")  # Default download directory

            # Prepare file paths (if documents exist)
            file_paths = []
            if documents:
                # Try to find the downloaded files in the download directory
                for doc in documents:
                    doc_name = os.path.basename(doc['url'])
                    # Look for files that might match this document
                    potential_files = []
                    for file in os.listdir(download_dir):
                        if doc_name in file or filename.split('.')[0] in file:
                            potential_files.append(os.path.join(download_dir, file))

                    if potential_files:
                        # Use the most recent file
                        latest_file = max(potential_files, key=os.path.getctime)
                        file_paths.append(latest_file)

            # Platform-specific messenger opening
            system = platform.system().lower()

            if messenger == "viber":
                if system == "windows":
                    # Try to open Viber desktop app
                    try:
                        subprocess.Popen(["viber://open"])
                        QMessageBox.information(self, "✅ Viber відкрито",
                                              "Viber відкрито!\n\n"
                                              "📋 Повідомлення скопійовано в буфер обміну\n"
                                              "📎 Файли знаходяться в папці Завантаження\n"
                                              "💡 Вставте текст (Ctrl+V) та додайте файли вручну")
                    except:
                        # Fallback to web version
                        webbrowser.open("https://web.viber.com/")
                        QMessageBox.information(self, "🌐 Viber Web відкрито",
                                              "Viber Web відкрито в браузері!\n\n"
                                              "📋 Повідомлення скопійовано в буфер обміну\n"
                                              "📎 Файли знаходяться в папці Завантаження\n"
                                              "💡 Вставте текст (Ctrl+V) та додайте файли через папку")

                elif system == "darwin":  # macOS
                    subprocess.Popen(["open", "viber://open"])
                    QMessageBox.information(self, "✅ Viber відкрито",
                                          "Viber відкрито!\n\n"
                                          "📋 Повідомлення скопійовано в буфер обміну\n"
                                          "📎 Файли знаходяться в папці Завантаження")

                elif system == "linux":
                    subprocess.Popen(["xdg-open", "viber://open"])
                    QMessageBox.information(self, "✅ Viber відкрито",
                                          "Viber відкрито!\n\n"
                                          "📋 Повідомлення скопійовано в буфер обміну\n"
                                          "📎 Файли знаходяться в папці Завантаження")

            elif messenger == "telegram":
                if system == "windows":
                    try:
                        subprocess.Popen(["telegram://open"])
                        QMessageBox.information(self, "✅ Telegram відкрито",
                                              "Telegram відкрито!\n\n"
                                              "📋 Повідомлення скопійовано в буфер обміну\n"
                                              "📎 Файли знаходяться в папці Завантаження\n"
                                              "💡 Вставте текст (Ctrl+V) та додайте файли вручну")
                    except:
                        webbrowser.open("https://web.telegram.org/")
                        QMessageBox.information(self, "🌐 Telegram Web відкрито",
                                              "Telegram Web відкрито в браузері!\n\n"
                                              "📋 Повідомлення скопійовано в буфер обміну\n"
                                              "📎 Файли знаходяться в папці Завантаження\n"
                                              "💡 Вставте текст (Ctrl+V) та додайте файли через папку")

                elif system == "darwin":  # macOS
                    subprocess.Popen(["open", "telegram://open"])
                    QMessageBox.information(self, "✅ Telegram відкрито",
                                          "Telegram відкрито!\n\n"
                                          "📋 Повідомлення скопійовано в буфер обміну\n"
                                          "📎 Файли знаходяться в папці Завантаження")

                elif system == "linux":
                    subprocess.Popen(["xdg-open", "telegram://open"])
                    QMessageBox.information(self, "✅ Telegram відкрито",
                                          "Telegram відкрито!\n\n"
                                          "📋 Повідомлення скопійовано в буфер обміну\n"
                                          "📎 Файли знаходяться в папці Завантаження")

            # Show file info if files exist
            if file_paths:
                file_info = "\n\n📎 **Завантажені файли:**\n"
                for i, path in enumerate(file_paths, 1):
                    file_info += f"{i}. {os.path.basename(path)}\n"

                QMessageBox.information(self, "📁 Інформація про файли",
                                      f"Файли готові для відправки!\n{file_info}")

        except Exception as e:
            QMessageBox.warning(self, "⚠️ Помилка",
                              f"Не вдалося відкрити {messenger.title()}\n\n"
                              f"Помилка: {str(e)}\n\n"
                              "💡 Але повідомлення скопійовано в буфер обміну!\n"
                              "Ви можете вставити його вручну в будь-який месенджер.")

    def download_and_share(self, parent_dialog):
        """Download document and then show share message"""
        documents = self.task_data.get('documents', [])
        if not documents:
            QMessageBox.information(self, "Немає документів", "Для цього завдання немає доступних документів")
            return

        # Use the existing download_documents method
        self.download_documents()

        # After download, show the original share message dialog
        task_name = self.task_data.get('task_name', 'No Task Name')
        task_description = self.task_data.get('task_description', '')
        order_info = self.extract_order_info(task_name)
        if not order_info:
            order_info = self.extract_order_info(task_description)

        if order_info:
            filename = f"{order_info} - {task_name}.pdf"
        else:
            filename = f"{task_name}.pdf"

        share_message = self.generate_share_message(task_name, order_info, filename)
        self.show_share_message_dialog(task_name, order_info, filename)

        parent_dialog.close()

    def refresh_task(self):
        """Refresh task data (would require re-fetching from server)"""
        QMessageBox.information(self, "Refresh", "Task refresh functionality requires reconnection to server")

    def download_documents(self):
        """Download documents from this task"""
        if not self.task_data or not self.session:
            QMessageBox.warning(self, "Error", "No session available for downloading")
            return

        documents = self.task_data.get('documents', [])
        if not documents:
            QMessageBox.information(self, "Документи Відсутні", "Немає доступних документів для цього завдання")
            return

        # Choose download location
        download_dir = QFileDialog.getExistingDirectory(
            self,
            f"Оберіть папку для завантаження документів: {self.task_data.get('task_name', 'Завдання')}",
            "",
            QFileDialog.Option.ShowDirsOnly
        )

        if not download_dir:
            return

        # Show progress
        self.download_progress.setVisible(True)
        self.download_progress.setMaximum(len(documents))
        self.download_progress.setValue(0)

        # Extract order info for filename enhancement
        task_name = self.task_data.get('task_name', 'Task')
        task_description = self.task_data.get('task_description', '')
        order_info = self.extract_order_info(task_name)
        if not order_info:
            order_info = self.extract_order_info(task_description)

        successful_downloads = 0
        failed_downloads = 0

        for i, doc in enumerate(documents):
            try:
                # Update progress
                self.download_progress.setValue(i)

                # Download the document
                response = self.session.get(doc['url'], timeout=30)

                if response.status_code == 200:
                    # Create enhanced filename
                    original_filename = os.path.basename(doc['url'])
                    if not original_filename:
                        original_filename = f"document.pdf"

                    # Clean task name for filename
                    safe_task_name = "".join(c for c in task_name if c.isalnum() or c in (' ', '-', '_', '.'))
                    safe_task_name = safe_task_name.replace('  ', ' ').strip()

                    # Create enhanced filename
                    if order_info:
                        new_filename = f"{order_info} - {safe_task_name}.pdf"
                    else:
                        new_filename = f"{safe_task_name}.pdf"

                    # Further clean filename
                    new_filename = "".join(c for c in new_filename if c.isalnum() or c in (' ', '-', '_', '.'))
                    new_filename = new_filename.replace('  ', ' ').strip()

                    file_path = os.path.join(download_dir, new_filename)

                    # Save file
                    with open(file_path, 'wb') as f:
                        f.write(response.content)

                    successful_downloads += 1
                else:
                    failed_downloads += 1

            except Exception as e:
                failed_downloads += 1

        # Hide progress
        self.download_progress.setVisible(False)

        # Show results
        total_docs = len(documents)
        if successful_downloads == total_docs:
            QMessageBox.information(self, "Завантаження Завершено",
                                 f"Успішно завантажено документи")
        elif successful_downloads > 0:
            QMessageBox.warning(self, "Часткове Завантаження",
                              f"Завантажено {successful_downloads} з {total_docs} документів")
        else:
            QMessageBox.critical(self, "Завантаження Невдале",
                               f"Не вдалося завантажити жоден документ")

    def update_percentage(self):
        """Update task percentage"""
        current_percentage = self.task_data.get('percentage', 0)

        # Check if task is already completed to 100%
        if current_percentage == 100:
            QMessageBox.information(self, "Завдання Виконано",
                                  "Це завдання вже виконано на 100%. Неможливо змінити прогрес.")
            return

        new_value = self.percentage_input.text().strip()

        if not new_value:
            QMessageBox.warning(self, "Помилка Вводу", "Будь ласка, введіть відсоток виконання")
            return

        try:
            percentage = int(new_value)
            if percentage < 0:
                percentage = 0
            elif percentage > 100:
                percentage = 100

            self.current_percentage_label.setText(f"Оновлення прогресу до {percentage}%...")
            self.progress_bar.setValue(percentage)

            # Get the task ID and update parameter name
            task_id = self.task_data.get('task_id', '')
            if not task_id:
                QMessageBox.critical(self, "Помилка", "ID завдання не знайдено")
                return

            # Make the AJAX request to update percentage
            try:
                response = self.session.post(
                    'https://calendar.nupp.edu.ua/ajax.php',
                    data={
                        'type': '1',
                        'idtask': task_id,
                        'procent': percentage
                    },
                    timeout=10
                )

                if response.status_code == 200:
                    # Update the local task data
                    self.task_data['percentage'] = percentage
                    self.current_percentage_label.setText(f"{percentage}%")
                    self.progress_bar.setValue(percentage)
                    self.percentage_input.setText(str(percentage))

                    # If parent callback exists, refresh the main table
                    if hasattr(self, 'parent') and self.parent:
                        self.parent.refresh_tasks()

                    QMessageBox.information(self, "Успіх", f"Прогрес завдання оновлено до {percentage}%")
                else:
                    QMessageBox.warning(self, "Попередження",
                                      f"Не вдалося оновити прогрес. Код відповіді: {response.status_code}")

            except Exception as e:
                QMessageBox.warning(self, "Мережева Помилка", f"Не вдалося оновити прогрес: {str(e)}")

        except ValueError:
            QMessageBox.critical(self, "Помилка Вводу", "Будь ласка, введіть коректне число від 0 до 100")

    def download_and_share_action(self):
        """Handle download and share button click for TaskDetailsWindow"""
        documents = self.task_data.get('documents', [])
        if not documents:
            QMessageBox.information(self, "Немає документів", "Для цього завдання немає доступних документів")
            return

        # Use the existing download_documents method
        self.download_documents()

        # After download, show share message dialog
        task_name = self.task_data.get('task_name', 'Завдання')
        task_description = self.task_data.get('task_description', '')
        order_info = self.extract_order_info(task_name)
        if not order_info:
            order_info = self.extract_order_info(task_description)

        if order_info:
            filename = f"{order_info} - {task_name}.pdf"
        else:
            filename = f"{task_name}.pdf"

        self.show_share_message_dialog_with_download(task_name, order_info, filename,
                                                   self.generate_share_message(task_name, order_info, filename),
                                                   documents)

    def close(self):
        """Close the dialog"""
        self.accept()

class PasswordManager:
    """Manages password storage and verification"""

    def __init__(self):
        self.settings = QSettings("TaskMonitor", "Password")
        self.master_key = self._get_or_create_master_key()

    def _get_or_create_master_key(self):
        """Get or create a master key for encryption"""
        # Create hidden directory in user's home folder
        key_dir = os.path.expanduser("~/.task_monitor")
        os.makedirs(key_dir, exist_ok=True)
        key_file = os.path.join(key_dir, ".encryption_key")

        try:
            with open(key_file, 'rb') as f:
                key = f.read()
        except FileNotFoundError:
            # Create a new key
            password = b"task_monitor_default_key_2024"  # This should be changed in production
            salt = b"task_monitor_salt_2024"
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))

            # Save the key with restricted permissions (owner read/write only)
            with open(key_file, 'wb') as f:
                f.write(key)

            # Set file permissions to owner read/write only (600)
            try:
                os.chmod(key_file, 0o600)
            except OSError:
                # chmod not available on Windows, but file will still be in hidden directory
                pass

        return key

    def is_password_set(self):
        """Check if password has been set"""
        return self.settings.value("password_hash") is not None

    def hash_password(self, password):
        """Create a secure hash of the password"""
        return hashlib.sha256(password.encode()).hexdigest()

    def set_password(self, password):
        """Set the application password"""
        password_hash = self.hash_password(password)
        self.settings.setValue("password_hash", password_hash)

    def verify_password(self, password):
        """Verify the entered password"""
        if not self.is_password_set():
            return False
        stored_hash = self.settings.value("password_hash")
        entered_hash = self.hash_password(password)
        return stored_hash == entered_hash

    def change_password(self, old_password, new_password):
        """Change the password"""
        if self.verify_password(old_password):
            self.set_password(new_password)
            return True
        return False

class FirstTimePasswordDialog(QDialog):
    """Dialog for setting password on first launch"""

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("🔐 Налаштування паролю")
        self.setFixedSize(350, 200)
        self.setModal(True)
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)

        layout = QVBoxLayout(self)

        # Title
        title_label = QLabel("Вітаємо! Встановіть пароль для доступу до програми")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        title_label.setWordWrap(True)
        layout.addWidget(title_label)

        # Password input with show button
        password_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Введіть новий пароль")
        password_layout.addWidget(self.password_input)

        self.show_password_button = QToolButton()
        self.show_password_button.setText("👁️")
        self.show_password_button.setCheckable(True)
        self.show_password_button.setToolTip("Показати пароль")
        self.show_password_button.clicked.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.show_password_button)

        layout.addLayout(password_layout)

        # Confirm password input with show button
        confirm_password_layout = QHBoxLayout()
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_input.setPlaceholderText("Підтвердіть пароль")
        confirm_password_layout.addWidget(self.confirm_password_input)

        self.show_confirm_password_button = QToolButton()
        self.show_confirm_password_button.setText("👁️")
        self.show_confirm_password_button.setCheckable(True)
        self.show_confirm_password_button.setToolTip("Показати пароль")
        self.show_confirm_password_button.clicked.connect(self.toggle_confirm_password_visibility)
        confirm_password_layout.addWidget(self.show_confirm_password_button)

        layout.addLayout(confirm_password_layout)

        # Buttons
        button_layout = QHBoxLayout()

        ok_button = QPushButton("Встановити")
        ok_button.clicked.connect(self.accept)
        ok_button.setDefault(True)

        button_layout.addWidget(ok_button)

        layout.addLayout(button_layout)

        # Set password input focus
        self.password_input.setFocus()

    def get_passwords(self):
        """Return entered passwords"""
        return self.password_input.text(), self.confirm_password_input.text()

    def accept(self):
        """Override accept to validate passwords"""
        password, confirm_password = self.get_passwords()

        if not password:
            QMessageBox.warning(self, "Помилка", "Пароль не може бути порожнім!")
            return

        if len(password) < 4:
            QMessageBox.warning(self, "Помилка", "Пароль повинен містити щонайменше 4 символи!")
            return

        if password != confirm_password:
            QMessageBox.warning(self, "Помилка", "Паролі не збігаються!")
            return

        super().accept()

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_button.isChecked():
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_password_button.setText("🙈")
            self.show_password_button.setToolTip("Сховати пароль")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_password_button.setText("👁️")
            self.show_password_button.setToolTip("Показати пароль")

    def toggle_confirm_password_visibility(self):
        """Toggle confirm password visibility"""
        if self.show_confirm_password_button.isChecked():
            self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_confirm_password_button.setText("🙈")
            self.show_confirm_password_button.setToolTip("Сховати пароль")
        else:
            self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_confirm_password_button.setText("👁️")
            self.show_confirm_password_button.setToolTip("Показати пароль")

class ChangePasswordDialog(QDialog):
    """Dialog for changing the password"""

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("🔐 Зміна паролю")
        self.setFixedSize(350, 220)
        self.setModal(True)

        layout = QVBoxLayout(self)

        # Title
        title_label = QLabel("Зміна паролю доступу до програми")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(title_label)

        # Current password input with show button
        current_password_layout = QHBoxLayout()
        self.current_password_input = QLineEdit()
        self.current_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.current_password_input.setPlaceholderText("Поточний пароль")
        current_password_layout.addWidget(self.current_password_input)

        self.show_current_password_button = QToolButton()
        self.show_current_password_button.setText("👁️")
        self.show_current_password_button.setCheckable(True)
        self.show_current_password_button.setToolTip("Показати пароль")
        self.show_current_password_button.clicked.connect(self.toggle_current_password_visibility)
        current_password_layout.addWidget(self.show_current_password_button)

        layout.addLayout(current_password_layout)

        # New password input with show button
        new_password_layout = QHBoxLayout()
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password_input.setPlaceholderText("Новий пароль")
        new_password_layout.addWidget(self.new_password_input)

        self.show_new_password_button = QToolButton()
        self.show_new_password_button.setText("👁️")
        self.show_new_password_button.setCheckable(True)
        self.show_new_password_button.setToolTip("Показати пароль")
        self.show_new_password_button.clicked.connect(self.toggle_new_password_visibility)
        new_password_layout.addWidget(self.show_new_password_button)

        layout.addLayout(new_password_layout)

        # Confirm new password input with show button
        confirm_new_password_layout = QHBoxLayout()
        self.confirm_new_password_input = QLineEdit()
        self.confirm_new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_new_password_input.setPlaceholderText("Підтвердіть новий пароль")
        confirm_new_password_layout.addWidget(self.confirm_new_password_input)

        self.show_confirm_new_password_button = QToolButton()
        self.show_confirm_new_password_button.setText("👁️")
        self.show_confirm_new_password_button.setCheckable(True)
        self.show_confirm_new_password_button.setToolTip("Показати пароль")
        self.show_confirm_new_password_button.clicked.connect(self.toggle_confirm_new_password_visibility)
        confirm_new_password_layout.addWidget(self.show_confirm_new_password_button)

        layout.addLayout(confirm_new_password_layout)

        # Buttons
        button_layout = QHBoxLayout()

        ok_button = QPushButton("Змінити")
        ok_button.clicked.connect(self.accept)
        ok_button.setDefault(True)

        cancel_button = QPushButton("Скасувати")
        cancel_button.clicked.connect(self.reject)

        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

        # Set current password input focus
        self.current_password_input.setFocus()

    def get_passwords(self):
        """Return entered passwords"""
        return (self.current_password_input.text(),
                self.new_password_input.text(),
                self.confirm_new_password_input.text())

    def accept(self):
        """Override accept to validate passwords"""
        current_password, new_password, confirm_new_password = self.get_passwords()

        if not current_password or not new_password:
            QMessageBox.warning(self, "Помилка", "Усі поля повинні бути заповнені!")
            return

        if new_password != confirm_new_password:
            QMessageBox.warning(self, "Помилка", "Нові паролі не збігаються!")
            return

        if len(new_password) < 4:
            QMessageBox.warning(self, "Помилка", "Новий пароль повинен містити щонайменше 4 символи!")
            return

        super().accept()

    def toggle_current_password_visibility(self):
        """Toggle current password visibility"""
        if self.show_current_password_button.isChecked():
            self.current_password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_current_password_button.setText("🙈")
            self.show_current_password_button.setToolTip("Сховати пароль")
        else:
            self.current_password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_current_password_button.setText("👁️")
            self.show_current_password_button.setToolTip("Показати пароль")

    def toggle_new_password_visibility(self):
        """Toggle new password visibility"""
        if self.show_new_password_button.isChecked():
            self.new_password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_new_password_button.setText("🙈")
            self.show_new_password_button.setToolTip("Сховати пароль")
        else:
            self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_new_password_button.setText("👁️")
            self.show_new_password_button.setToolTip("Показати пароль")

    def toggle_confirm_new_password_visibility(self):
        """Toggle confirm new password visibility"""
        if self.show_confirm_new_password_button.isChecked():
            self.confirm_new_password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_confirm_new_password_button.setText("🙈")
            self.show_confirm_new_password_button.setToolTip("Сховати пароль")
        else:
            self.confirm_new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_confirm_new_password_button.setText("👁️")
            self.show_confirm_new_password_button.setToolTip("Показати пароль")

class PasswordDialog(QDialog):
    """Password dialog for application access"""

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("🔐 Доступ до програми")
        self.setFixedSize(300, 150)
        self.setModal(True)
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)

        layout = QVBoxLayout(self)

        # Title
        title_label = QLabel("Введіть пароль для доступу")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(title_label)

        # Password input with show button
        password_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Пароль")
        password_layout.addWidget(self.password_input)

        self.show_password_button = QToolButton()
        self.show_password_button.setText("👁️")
        self.show_password_button.setCheckable(True)
        self.show_password_button.setToolTip("Показати пароль")
        self.show_password_button.clicked.connect(self.toggle_password_visibility)
        password_layout.addWidget(self.show_password_button)

        layout.addLayout(password_layout)

        # Buttons
        button_layout = QHBoxLayout()

        ok_button = QPushButton("ОК")
        ok_button.clicked.connect(self.accept)
        ok_button.setDefault(True)

        cancel_button = QPushButton("Скасувати")
        cancel_button.clicked.connect(self.reject)

        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

        # Set password input focus
        self.password_input.setFocus()

    def get_password(self):
        """Return entered password"""
        return self.password_input.text()

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_button.isChecked():
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_password_button.setText("🙈")
            self.show_password_button.setToolTip("Сховати пароль")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_password_button.setText("👁️")
            self.show_password_button.setToolTip("Показати пароль")

def main():
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle('Fusion')

    # Initialize password manager
    password_manager = PasswordManager()

    # Check if password is set (first launch)
    if not password_manager.is_password_set():
        # First time setup - show password creation dialog
        first_time_dialog = FirstTimePasswordDialog()

        while True:
            if first_time_dialog.exec() == QDialog.DialogCode.Accepted:
                password, confirm_password = first_time_dialog.get_passwords()
                password_manager.set_password(password)
                QMessageBox.information(None, "Успіх",
                                       "Пароль успішно встановлено!\n\n"
                                       "Тепер ви можете використовувати цей пароль для доступу до програми.")
                break
            else:
                # User cancelled password setup
                sys.exit(0)
    else:
        # Password already set - show password entry dialog
        password_dialog = PasswordDialog()

        while True:
            if password_dialog.exec() == QDialog.DialogCode.Accepted:
                entered_password = password_dialog.get_password()

                if password_manager.verify_password(entered_password):
                    break  # Password correct, continue to main application
                else:
                    # Password incorrect, show error and ask again
                    QMessageBox.critical(None, "Помилка",
                                       "Неправильний пароль!\n\nСпробуйте ще раз.")
                    password_dialog.password_input.clear()
                    password_dialog.password_input.setFocus()
                    continue
            else:
                # User cancelled password entry
                sys.exit(0)

    # Show main application
    window = TaskMonitorApp()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()