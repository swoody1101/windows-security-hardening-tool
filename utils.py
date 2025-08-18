import win32api
import win32con
import sys
import os


# 관리자 권한 확인 및 재실행
def run_as_admin():
    try:
        is_admin = win32api.GetFileAttributes(os.environ["SYSTEMROOT"]) != -1

        if not is_admin:
            win32api.ShellExecute(
                0,
                "runas",
                sys.executable,
                f'"{os.path.abspath(sys.argv[0])}"',
                None,
                win32con.SW_SHOWNORMAL,
            )
            sys.exit(0)
        else:
            print("관리자 권한으로 실행되었습니다.\n")

    except Exception as e:
        print(f"관리자 권한으로 재실행 실패: {e}")
        sys.exit(1)
