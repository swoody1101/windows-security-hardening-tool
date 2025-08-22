import subprocess
import os
import re


# SAM 파일의 접근 권한을 Administrator, System 그룹으로만 제한
def secure_sam_file_permissions():
    sam_file_path = os.path.join(os.environ["SystemRoot"], "system32", "config", "SAM")
    allowed_users = [
        "SYSTEM",
        "Administrators",
        "BUILTIN\\Administrators",
        "NT AUTHORITY\\SYSTEM",
        "C:\\WINDOWS\\system32\\config\\SAM NT AUTHORITY\\SYSTEM",
    ]
    users_to_remove = []

    try:
        result = subprocess.run(
            ["icacls", sam_file_path],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        for line in result.stdout.splitlines():
            match = re.search(r"([A-Za-z0-9\\ -_#]+):\(", line)
            if match:
                user = match.group(1).strip()
                if user not in allowed_users:
                    users_to_remove.append(user)

        if not users_to_remove:
            print(
                "SAM 파일에 제거할 권한이 없습니다. 이미 보안 설정이 완료된 상태입니다.\n"
            )
            return

        command_remove = ["icacls", sam_file_path, "/remove"]
        command_remove.extend(users_to_remove)
        subprocess.run(
            command_remove,
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print(f"SAM 파일 권한 설정이 완료되었습니다.\n")

    except subprocess.CalledProcessError as e:
        print("오류: 관리자 권한으로 실행했는지 확인하세요.")
        print(f"오류 메시지: {e.stderr.strip()}\n")
    except Exception as e:
        print(f"예상치 못한 오류가 발생했습니다: {e}\n")
