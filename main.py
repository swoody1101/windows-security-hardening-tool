from utils import run_as_admin
from managements.account_management import (
    rename_admin_account_wmi,
    disable_guest_account,
    delete_unnecessary_users,
    set_lockout_threshold,
    set_max_password_age,
    disable_password_never_expires,
    disable_reversible_encryption,
    revoke_unnecessary_admin_privileges,
)
from managements.service_management import (
    restore_share_permissions,
    disable_default_shares,
    set_netbios_options,
    disable_ftp_service,
    set_dns_zone_transfer,
)
from managements.log_management import (
    disable_remote_registry_service,
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
    print("1.3. 불필요한 사용자 계정 제거")
    delete_unnecessary_users()
    print("1.4. 계정 잠금 임계값 설정 (설정값: 5)")
    set_lockout_threshold()
    print("1.5. 패스워드 최대 사용 기간 설정 (설정값: 90)")
    set_max_password_age()
    print("1.6. 암호 사용 기간 제한 없음 설정 비활성화")
    disable_password_never_expires()
    print("1.7. 해독 가능한 암호화 설정 비활성화")
    disable_reversible_encryption()
    print("1.8. 불필요한 관리자 계정 관리자 권한 회수")
    revoke_unnecessary_admin_privileges()
    print()

    print("2. 서비스 관리")
    print("2.1. 공유 권한 및 사용자 그룹 설정")
    restore_share_permissions()
    print("2.2. 하드디스크 기본 공유 제거")
    disable_default_shares()
    print("2.3. NetBIOS 바인딩 구동 점검")
    set_netbios_options()
    print("2.4. FTP 서비스 구동 점검")
    disable_ftp_service()
    print("2.5. DNS Zone Transfer 설정")
    set_dns_zone_transfer()

    print("3. 패치 및 로그 관리")
    # print("3.1. 최신 서비스팩 적용")
    # print("3.2. 최신 Hot Fix 적용")
    # print("3.3. 백신 프로그램 업데이트")
    # print("3.4. 로그의 정기적 검토 및 보고")
    print("3.1. 레지스트리 원격 접근 비활성화")
    disable_remote_registry_service()

    print("------------------------------------------------")
    print("모든 보안 점검 및 수정 작업이 완료되었습니다.")
    input("프로그램을 끝내려면 아무 키나 누르세요...")


def main():
    show_info()
    print("프로그램이 시작되었습니다....\n")


if __name__ == "__main__":
    main()
