from utils import (
    run_as_admin,
    update_local_security_policy,
)
from managements.account_management import (
    rename_admin_account,
    disable_guest_account,
    delete_unnecessary_users,
    set_lockout_threshold,
    set_max_password_age,
    disable_password_never_expires,
    disable_reversible_encryption,
    revoke_unnecessary_admin_privileges,
    revoke_anonymous_everyone_access,
    enable_password_complexity,
    set_min_password_length,
    set_min_password_age,
    hide_last_username,
    restrict_local_logon_access
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
from managements.security_management import (
    secure_sam_file_permissions,
    configure_shutdown_policy,
    configure_remote_shutdown_privilege,
    configure_crash_on_audit_fail,
    restrict_anonymous_enumeration,
    check_autoadminlogon_status,
    configure_removable_media_policy,
)

__project_name__ = "Windows Security Hardening Tool"
__version__ = "1.0.0"
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
    rename_admin_account()
    print("1.2. Guest 계정 비활성화")
    disable_guest_account()
    print("1.3. 불필요한 사용자 계정 제거")
    delete_unnecessary_users()
    print("1.4. 불필요한 관리자 계정 관리자 권한 회수")
    revoke_unnecessary_admin_privileges()
    print("1.5. 익명 사용자의 Everyone 사용 권한 회수")
    revoke_anonymous_everyone_access()
    print("1.6. 계정 잠금 임계값 설정 (설정값: 5)")
    set_lockout_threshold()
    print("1.7. 패스워드 복잡성 설정 활성화")
    enable_password_complexity()
    print("1.8. 암호 사용 기간 제한 없음 설정 비활성화")
    disable_password_never_expires()
    print("1.9. 해독 가능한 암호화를 사용하여 암호 정책 설정 비활성화")
    disable_reversible_encryption()
    print("1.10. 패스워드 최소 암호 길이 설정 (설정값: 8)")
    set_min_password_length(8)
    print("1.11. 패스워드 최대 사용 기간 설정 (설정값: 90)")
    set_max_password_age()
    print("1.12. 패스워드 최소 사용 기간 설정(설정값: 1)")
    set_min_password_age()
    print("1.13. 마지막으로 로그온한 사용자 이름 표시 안 함 설정 활성화")
    hide_last_username()
    print("1.14. 불필요한 계정의 로컬 로그온 접근 제한 설정")
    restrict_local_logon_access()
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
    print()

    print("3. 패치 및 로그 관리")
    # print("3.1. 최신 서비스팩 적용")
    # print("3.2. 최신 Hot Fix 적용")
    # print("3.3. 백신 프로그램 업데이트")
    # print("3.4. 로그의 정기적 검토 및 보고")
    print("3.1. 레지스트리 원격 접근 비활성화")
    disable_remote_registry_service()
    print()

    print("4. 보안 관리")
    print("4.1. SAM 파일 접근 통제 설정")
    secure_sam_file_permissions()
    print("4.2. 로그인하지 않고 시스템 종료 설정 비활성화 ")
    configure_shutdown_policy()
    print("4.3. 원격 시스템에서 강제 시스템 종료 설정 비활성화")
    configure_remote_shutdown_privilege()
    print("4.4. 보안 감사를 로그할 수 없을 경우 종료 설정 비활성화")
    configure_crash_on_audit_fail()
    print("4.5. SAM 계정과 공유의 익명 열거 설정 비활성화")
    restrict_anonymous_enumeration()
    print("4.6. Autologon 설정 비활성화")
    check_autoadminlogon_status()
    print("4.7. 이동식 미디어 포맷 및 꺼내기 관리자 설정")
    configure_removable_media_policy()

    print("로컬 보안 정책 수정 사항을 반영합니다.")
    update_local_security_policy()
    print()

    print("------------------------------------------------")
    print("모든 보안 점검 및 수정 작업이 완료되었습니다.")
    input("프로그램을 끝내려면 아무 키나 누르세요...")


def main():
    show_info()
    print("프로그램이 시작되었습니다....\n")


if __name__ == "__main__":
    main()
