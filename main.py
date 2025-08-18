from .utils import run_as_admin
from .account_management import rename_admin_account_wmi

__project_name__ = "Windows Security Scanner"
__version__ = "0.0.0"
__author__ = "LEE SANG U"


def show_info():
    run_as_admin()

    """프로젝트 정보를 출력하는 함수"""
    print("---------------------------------")
    print(f"프로젝트명: {__project_name__}")
    print(f"버전: {__version__}")
    print(f"개발자: {__author__}")
    print("---------------------------------")

    print("계정 관리")
    print("1. Administrator 계정 이름 변경")
    rename_admin_account_wmi()


def main():
    show_info()
    print("프로그램이 시작되었습니다....\n")


if __name__ == "__main__":
    main()
