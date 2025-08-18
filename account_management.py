import subprocess
import wmi


# Administrator 계정 이름을 JLKAdmin으로 변경
def rename_admin_account_wmi(new_name="JLKAdmin"):
    current_admin_name = "Administrator"

    try:
        c = wmi.WMI()
        accounts = c.Win32_UserAccount(Name=current_admin_name)
        if not accounts:
            print(
                f"계정 이름이 이미 '{current_admin_name}' 계정이 존재하지 않습니다. 이미 이름이 변경되었을 수 있습니다."
            )
            return

        admin_account = accounts[0]
        admin_account.Rename(Name=new_name)
        print(f"계정 이름이 성공적으로 '{new_name}'로 변경되었습니다.\n")
    except Exception as e:
        print(f"예상치 못한 오류 발생: {e}")


# Guest 계정을 비활성화
def disable_guest_account():
    print("Guest 계정 비활성화 상태를 확인하고 비활성화합니다.")
    try:
        subprocess.run(
            ["net", "user", "guest", "/active:no"],
            check=True,
            text=True,
            encoding="cp949",
        )
        print("Guest 계정이 성공적으로 비활성화되었습니다.\n")
    except subprocess.CalledProcessError as e:
        print(f"Guest 계정 비활성화 오류: {e.stderr.decode('cp949')}")
    except Exception as e:
        print(f"예상치 못한 오류 발생: {e}")
