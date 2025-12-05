# Task Monitor - NUPP Calendar Dashboard

A PyQt6 desktop application for monitoring tasks from the NUPP university calendar website.

## Features

- **Authentication**: Login with university credentials using secure session management
- **Task Filtering**: Displays only relevant tasks (Прострочена, Отстанній день, Поточна)
- **Visual Dashboard**: Color-coded task display based on status
- **Error Handling**: Robust error handling for connection issues

## Requirements

- Python 3.8+
- PyQt6
- requests
- beautifulsoup4
- lxml

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python task_monitor.py
```

## Usage

1. **Login Tab**:
   - Enter your university username and password
   - Click "Connect"
   - Application will authenticate and fetch tasks

2. **Tasks Tab**:
   - View filtered tasks in a table format
   - Tasks are highlighted by status:
     - **Red**: Прострочена (Overdue)
     - **Orange**: Отстанній день (Last Day)
     - **Green**: Поточна (Current)
   - Click "Refresh Tasks" to update data

### Test Parser

To test the parsing logic independently:
```bash
python test_parser.py
```

## Application Structure

- `task_monitor.py`: Main application file with GUI and authentication
- `test_parser.py`: Standalone HTML parser test script
- `requirements.txt`: Python dependencies
- `README.md`: This documentation file
- `start_app.bat`: Windows launcher script

## Parsing Logic

The application targets the "Задачі" section with the following extraction rules:

1. **Target Container**: `<div id="task">`
2. **Row Iteration**: Table rows in `<tbody>`
3. **Data Extraction**:
   - Task Name: 1st cell (td[0])
   - Dates: 3rd cell (td[2])
   - Status: 4th cell (td[3]) with id="status"
   - Percentage: 5th cell (td[4]) from `<input>` value attribute

## Authentication Flow

1. **Login URL**: `https://calendar.nupp.edu.ua/login.php`
2. **Session Management**: Uses `requests.Session()` to maintain cookies
3. **Post-Login Redirect**: Fetches tasks from `https://calendar.nupp.edu.ua/index.php`
4. **Success Detection**: Checks for logout/calendar indicators in response

## Status Filtering

Only tasks with these Ukrainian status terms are displayed:
- **Прострочена** (Overdue)
- **Отстанній день** (Last Day)
- **Поточна** (Current)

## Error Handling

- Network timeouts and connection errors
- Invalid credentials
- Missing or malformed HTML
- Thread-safe operations for GUI responsiveness

## Security

- Uses requests.Session for secure session management
- Passwords are handled securely in memory
- No credential storage in files or registry

## Troubleshooting

1. **Connection Issues**:
   - Check network connectivity to https://calendar.nupp.edu.ua
   - Verify university credentials are correct
   - Check if the website is accessible

2. **Parsing Issues**:
   - Run test_parser.py to verify parsing logic
   - Verify HTML structure matches expected format
   - Check if tasks are available on the website

3. **GUI Issues**:
   - Ensure PyQt6 is properly installed
   - Check Python version compatibility
   - Run the test_parser.py script first

## Development

The application is structured with clear separation of concerns:

- **LoginWorker**: Threaded authentication and data fetching
- **TaskMonitorApp**: Main GUI application
- **Parsing Logic**: Separate HTML parsing methods for testing

This design allows for easy testing and maintenance of individual components.