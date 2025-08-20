import subprocess

from utils import get_share_name_list, get_share_permissions


# 일반 폴더 Everyone 공유 권한 제거 및 저장된 권한 재부여 설정
def restore_share_permissions():
    share_name_list = get_share_name_list()

    # 내장 공유 권한 이름 제외
    built_in_share_names = [
        "C$",
        "D$",
        "IPC$",
        "ADMIN$",
    ]
    share_name_list_to_check = [
        name for name in share_name_list if name not in built_in_share_names
    ]

    if not share_name_list_to_check:
        print("특정 공유의 삭제할 Everyone 권한이 없습니다.\n")
        return

    for share_name in share_name_list_to_check:
        backup_permissions, resource_path = get_share_permissions(share_name)

        if "Everyone" in backup_permissions:
            del backup_permissions["Everyone"]
        else:
            continue

        try:
            subprocess.run(
                ["net", "share", share_name, "/delete"],
                check=True,
                capture_output=True,
                text=True,
                encoding="cp949",
            )
            print(f"'{share_name}' 공유의 Everyone 권한을 성공적으로 삭제했습니다.")

            if not backup_permissions:
                print(f"'{share_name}'공유의 복원할 기타 권한이 없습니다.")
            else:
                command = [
                    "net",
                    "share",
                    f"{share_name}={resource_path}",
                ]
                for user, permission in backup_permissions.items():
                    command.append(f"/grant:{user},{permission}")
                subprocess.run(
                    command,
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="cp949",
                )
                print(f"'{share_name}' 공유의 기타 권한을 성공적으로 복원했습니다.")

        except subprocess.CalledProcessError as e:
            print(f"권한 복원 실패: {share_name}")
            print(f"오류 메시지: {e.stderr}\n")

    print("일반 폴더 공유 권한 설정을 완료했습니다.\n")
