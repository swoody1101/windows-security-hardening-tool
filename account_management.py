import subprocess
import wmi

from utils import get_user_list


# Administrator 계정 이름을 JLKAdmin으로 변경
def rename_admin_account_wmi(new_name="JLKAdmin"):
    current_admin_name = "Administrator"

    try:
        c = wmi.WMI()
        accounts = c.Win32_UserAccount(Name=current_admin_name)
        if not accounts:
            print(
                f"계정 이름이 이미 '{current_admin_name}' 계정이 존재하지 않습니다.\n이미 이름이 변경되었을 수 있습니다.\n"
            )
            return

        admin_account = accounts[0]
        admin_account.Rename(Name=new_name)
        print(f"계정 이름이 성공적으로 '{new_name}'로 변경되었습니다.\n")
    except Exception as e:
        print(f"예상치 못한 오류 발생: {e}\n")


# Guest 계정을 비활성화
def disable_guest_account():
    print("Guest 계정 비활성화 상태를 확인하고 비활성화합니다.")
    try:
        subprocess.run(
            ["net", "user", "guest", "/active:no"],
            check=True,
            text=True,
            encoding="cp949",
            stdout=subprocess.DEVNULL,
        )
        print("Guest 계정이 성공적으로 비활성화되었습니다.\n")
    except subprocess.CalledProcessError as e:
        print(f"Guest 계정 비활성화 오류: {e.stderr.decode('cp949')}\n")
    except Exception as e:
        print(f"예상치 못한 오류 발생: {e}\n")


# 불필요한 계정 제거
def delete_unnecessary_users():
    user_list = get_user_list()

    # 내장 계정 및 변경된 관리자 계정 제외
    built_in_accounts = [
        "Administrator",
        "Guest",
        "DefaultAccount",
        "WDAGUtilityAccount",
        "JLKAdmin",
        "jlk",
    ]
    user_list_to_delete = [user for user in user_list if user not in built_in_accounts]

    if not user_list_to_delete:
        print("삭제할 불필요한 계정이 없습니다.\n")
        return

    print("불필요한 계정으로 감지된 계정 목록:")
    for user in user_list_to_delete:
        confirm = input("위 계정들을 모두 삭제하시겠습니까? (y/n): ").lower()
        if confirm == "y":
            try:
                subprocess.run(
                    ["net", "user", user, "/del"],
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="cp949",
                )
                print(f"'{user}' 계정이 성공적으로 삭제되었습니다.")
            except subprocess.CalledProcessError as e:
                print(
                    f"'{user}' 계정 삭제 오류: {e.stderr.decode('cp949', errors='ignore')}"
                )
            except Exception as e:
                print(f"오류 발생: {e}")
        else:
            print(f"'{user}' 계정 삭제를 취소했습니다.")

    print("불필요한 계정 삭제를 완료했습니다.\n")
