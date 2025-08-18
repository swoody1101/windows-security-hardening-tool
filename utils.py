import win32api
import win32con
import sys
import os
import subprocess


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


# 계정 리스트 검색
def get_user_list():
    try:
        result = subprocess.run(
            ["net", "user"],
            capture_output=True,
            text=True,
            check=True,
            encoding="cp949",
        )
        output_lines = result.stdout.strip().split("\n")

        # 필요한 부분만 파싱하여 계정 리스트 추출
        start_index = -1
        for i, line in enumerate(output_lines):
            if "-----" in line:
                start_index = i
                break

        if start_index == -1:
            return []

        user_list = []
        for line in output_lines[start_index + 1 :]:
            if not line.strip() or "명령을 잘 실행했습니다." in line:
                break
            user_list.extend(line.split())

        return user_list

    except subprocess.CalledProcessError as e:
        print(f"명령어 실행 오류: {e}")
        return []
    except Exception as e:
        print(f"사용자 리스트 가져오기 오류: {e}")
        return []
