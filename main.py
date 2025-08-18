from utils import run_as_admin
from account_management import (
    rename_admin_account_wmi,
    disable_guest_account,
    delete_unnecessary_users,
)

__project_name__ = "Windows Security Scanner"
__version__ = "0.0.0"
__author__ = "LEE SANG U"


def show_info():
    run_as_admin()

    print("---------------------------------")
    print(f"프로젝트명: {__project_name__}")
    print(f"버전: {__version__}")
    print(f"개발자: {__author__}")
    print("---------------------------------")

    print("1. 계정 관리")
    print("1.1. Administrator 계정 이름 변경")
    rename_admin_account_wmi()
    print("1.2. Guest 계정 비활성화")
    disable_guest_account()
    print("1.3. 불필요한 계정 제거")
    delete_unnecessary_users()

    print("\n------------------------------------------------")
    print("모든 보안 점검 및 수정 작업이 완료되었습니다.")
    input("프로그램을 끝내려면 아무 키나 누르세요...")


def main():
    show_info()
    print("프로그램이 시작되었습니다....\n")


if __name__ == "__main__":
    main()
