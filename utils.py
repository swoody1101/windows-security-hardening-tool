import win32api
import win32con
import subprocess
import sys
import os
import re


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


# 계정 리스트 탐색
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


# 관리자 그룹 계정 탐색
def get_admin_list():
    try:
        result = subprocess.run(
            ["net", "localgroup", "administrators"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        output_lines = result.stdout.strip().split("\n")

        start_index = -1
        for i, line in enumerate(output_lines):
            if "-----" in line:
                start_index = i
                break

        if start_index == -1:
            return []

        admin_list = []
        for line in output_lines[start_index + 1 :]:
            if not line.strip() or "명령을 잘 실행했습니다." in line:
                break
            admin_list.extend(line.split())

        return admin_list

    except subprocess.CalledProcessError as e:
        print(f"명령어 실행 오류: {e}")
        return []
    except Exception as e:
        print(f"관리자 리스트 가져오기 오류: {e}")
        return []


# 공유 이름 목록 탐색
def get_share_name_list():
    try:
        result = subprocess.run(
            ["net", "share"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )

        output_lines = result.stdout.strip().splitlines()
        share_name_list = []

        for line in output_lines[2:]:
            if "-----" in line or "명령" in line:
                continue
            words = line.split()
            if words:
                share_name = words[0]
                share_name_list.append(share_name)

        return share_name_list

    except subprocess.CalledProcessError as e:
        print(f"명령어 실행 오류: {e}")
        return []
    except Exception as e:
        print(f"공유 이름 리스트 가져오기 오류: {e}")
        return []


# 특정 공유의 사용자 권한을 탐색 및 딕셔너리 형태로 반환
def get_share_permissions(share_name):
    permissions = {}
    path = ""
    try:
        result = subprocess.run(
            ["net", "share", share_name],
            capture_output=True,
            text=True,
            check=True,
            encoding="cp949",
        )
        lines = result.stdout.splitlines()

        permission_flag = False
        for line in lines:
            if "경로" in line:
                parts = line.split(maxsplit=1)
                if len(parts) > 1:
                    path = parts[1].strip()
                continue

            if "사용 권한" in line or permission_flag:
                if not permission_flag:
                    line = line.split("사용 권한", 1)[1]
                    permission_flag = True
                match = re.search(r"([\w\s-]+), (READ|CHANGE|FULL)", line)
                if match:
                    user_or_group = match.group(1).strip()
                    permission = match.group(2).strip()
                    permissions[user_or_group] = permission

        return permissions, path

    except subprocess.CalledProcessError as e:
        print(f"공유 권한 획득 오류: {e.stderr.strip()}\n")
