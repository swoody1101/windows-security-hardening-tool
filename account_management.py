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
    print(user_list_to_delete)
    for user in user_list_to_delete:
        confirm = input(f"'{user}' 계정을 삭제하시겠습니까? (y/n): ").lower()
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


# 계정 잠금 임계값 설정
def set_lockout_threshold():
    print("계정 잠금 임계값을 5로 설정합니다.")
    try:
        result = subprocess.run(
            ["net", "accounts", "/lockoutthreshold:5"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("계정 잠금 임계값이 '5'로 성공적으로 설정되었습니다.\n")
    except subprocess.CalledProcessError as e:
        print(f"계정 잠금 임계값 설정 오류: {e.stderr.strip()}")
        print(
            "오류 원인: 관리자 권한으로 실행되지 않았거나, 시스템 계정으로 실행할 수 없습니다.\n"
        )
    except FileNotFoundError:
        print("'net' 명령어를 찾을 수 없습니다. 시스템 PATH를 확인해 주세요.\n")
    except Exception as e:
        print(f"예기치 않은 오류가 발생했습니다: {e}\n")


# 패스워드 최대 사용 기간 설정
def set_max_password_age():
    print("패스워드 최대 사용 기간 설정을 시작합니다.")
    try:
        subprocess.run(
            ["net", "accounts", "/MAXPWAGE:90"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("패스워드 최대 사용 기간이 '90일'로 성공적으로 설정되었습니다.\n")
    except subprocess.CalledProcessError as e:
        print(f"패스워드 최대 사용 기간 설정 오류: {e.stderr.strip()}\n")
        print(
            "오류 원인: 관리자 권한으로 실행되지 않았거나, 명령에 문제가 있을 수 있습니다.\n"
        )
    except FileNotFoundError:
        print("'net' 명령어를 찾을 수 없습니다. 시스템 PATH를 확인해 주세요.\n")
    except Exception as e:
        print(f"예기치 않은 오류가 발생했습니다: {e}\n")


# 암호 사용 기간 제한 없음 비활성화 설정
def disable_password_never_expires():
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
    user_list = [user for user in user_list if user not in built_in_accounts]

    if not user_list:
        print("시스템에 사용자 계정이 존재하지 않습니다.\n")
        return

    for user in user_list:
        try:
            print(f"'{user} 계정의 암호사용 기간 제한 없음 설정을 비활성화합니다.")
            subprocess.run(
                [
                    "wmic",
                    "useraccount",
                    "where",
                    f"name='{user}'",
                    "set",
                    "passwordexpires=true",
                ],
                check=True,
                capture_output=True,
                text=True,
                encoding="cp949",
            )
            print(
                f"계정 '{user}'의 '암호 사용 기간 제한 없음' 설정이 비활성화되었습니다."
            )
        except subprocess.CalledProcessError as e:
            print(f"계정 '{user}'의 설정 변경 오류: {e.stderr.strip()}\n")
        except Exception as e:
            print(f"'{user}' 계정 처리 중 예기치 않은 오류 발생: {e}\n")

    print()

