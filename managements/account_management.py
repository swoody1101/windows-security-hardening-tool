import subprocess
import winreg
import wmi
import os

from utils import (
    get_user_list,
    get_admin_list,
    cleanup_security_policy_files,
    export_security_settings,
)


# Administrator 계정 이름을 JLKAdmin으로 변경
def rename_admin_account(new_name="JLKAdmin"):
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
        print("삭제할 불필요한 사용자 계정이 없습니다.\n")
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
        subprocess.run(
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


# 해독 가능한 암호화 설정 비활성화
def disable_reversible_encryption():
    print("해독 가능한 암호화 설정 비활성화를 시작합니다.")

    desktop_path = os.path.join(os.path.join(os.environ["USERPROFILE"]), "Desktop")
    export_cfg_path = os.path.join(desktop_path, "cfg.txt")

    try:
        print(f"현재 보안 설정을 '{export_cfg_path}' 파일로 내보냅니다.")
        subprocess.run(
            ["secedit", "/export", "/cfg", export_cfg_path],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )

        print("파일에서 'ClearTextPassword' 설정을 '0'으로 변경합니다.")
        with open(export_cfg_path, "r", encoding="utf-16") as f:
            lines = f.readlines()
        found = False
        with open(export_cfg_path, "w", encoding="utf-8", errors="ignore") as f:
            for line in lines:
                if "ClearTextPassword" in line:
                    f.write("ClearTextPassword = 0\n")
                    found = True
                else:
                    f.write(line)
            if not found:
                if not any("[System Access]" in l for l in lines):
                    f.write("\n[System Access]\n")
                f.write("ClearTextPassword = 0\n")

        print("수정된 정책 파일을 시스템에 적용합니다.")
        subprocess.run(
            ["secedit", "/configure", "/db", "cfg.sdb", "/cfg", export_cfg_path],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("해독 가능한 암호화 설정이 성공적으로 비활성화되었습니다.\n")

    except subprocess.CalledProcessError as e:
        print(f"정책 적용 실패: {e.stderr.strip()}")
        print("오류 원인: 관리자 권한으로 실행되었는지 확인하십시오.\n")
    except FileNotFoundError as e:
        print(f"파일이 존재하지 않습니다: {e}\n")
    except Exception as e:
        print(f"예기치 않은 오류가 발생했습니다: {e}\n")

    finally:
        cleanup_security_policy_files(desktop_path, export_cfg_path)


# 관리자 그룹에 불필요한 계정 권한 회수
def revoke_unnecessary_admin_privileges():
    admin_list = get_admin_list()

    # 내장 계정 및 변경된 관리자 계정 제외
    safe_admin_accounts = [
        "Administrator",
        "JLKAdmin",
        "jlk",
    ]
    unnecessary_admin_users = [
        user for user in admin_list if user not in safe_admin_accounts
    ]

    if not unnecessary_admin_users:
        print("삭제할 불필요한 관리자 계정이 없습니다.\n")
        return

    print("불필요한 관리자 계정 목록:")
    print(unnecessary_admin_users)
    for admin in unnecessary_admin_users:
        confirm = input(
            f"'{admin}'계정의 관리자 권한을 삭제하시겠습니까? (y/n): "
        ).lower()
        if confirm == "y":
            try:
                subprocess.run(
                    ["net", "localgroup", "administrators", admin, "/del"],
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="cp949",
                )
                print(f"'{admin}'계정의 관리자 권한이 성공적으로 회수되었습니다.")
            except subprocess.CalledProcessError as e:
                print(
                    f"'{admin}' 관리자 권한 회수 오류: {e.stderr.decode('cp949', errors='ignore')}"
                )
            except Exception as e:
                print(f"오류 발생: {e}")
        else:
            print(f"'{admin}'의 관리자 권한 회수를 취소했습니다.")

    print("불필요한 관리자 권한 회수를 완료했습니다.\n")


# 익명 사용자의 Everyone 사용 권한 회수
def revoke_anonymous_everyone_access():
    print("익명 사용자의 Everyone 그룹 사용 권한을 회수합니다.")

    base_key_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
    try:
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            base_key_path,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        )

        print("레지스트리 EveryoneIncludesAnonymous 값을 0으로 설정합니다.")
        winreg.SetValueEx(reg_key, "EveryoneIncludesAnonymous", 0, winreg.REG_DWORD, 0)

        winreg.CloseKey(reg_key)
        print("익명 사용자의 Everyone 사용 권한이 성공적으로 회수되었습니다.\n")

    except subprocess.CalledProcessError as e:
        print(f"익명 사용자의 Everyone 사용 권한 회수 오류: {e.stderr.strip()}\n")
    except Exception as e:
        print(f"예상치 못한 오류 발생: {e}\n")


# 계정 잠금 기간 및 다음 시간 후 계정 잠금 수를 원래대로 설정 60분으로 설정
# 보안 정책 설정 LockoutBadCount 5, ResetLockoutCount = 60, LockoutDuration = 60
def set_lockout_duration(
    lockout_bad_count=5, reset_lockout_count=60, lockout_duration=60
):
    print("계정 잠금 기간을 60분으로 설정합니다.")
    try:
        subprocess.run(
            [
                "net",
                "accounts",
                f"/lockoutthreshold:{lockout_bad_count}",
                f"/lockoutwindow:{reset_lockout_count}",
                f"/lockoutduration:{lockout_duration}",
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("계정 잠금 기간이 '60분'로 성공적으로 설정되었습니다.\n")
    except subprocess.CalledProcessError as e:
        print(f"계정 잠금 기간 설정 오류: {e.stderr.strip()}\n")
        print(
            "오류 원인: 관리자 권한으로 실행되지 않았거나, 명령에 문제가 있을 수 있습니다.\n"
        )
    except FileNotFoundError:
        print("'net' 명령어를 찾을 수 없습니다. 시스템 PATH를 확인해 주세요.\n")
    except Exception as e:
        print(f"예기치 않은 오류가 발생했습니다: {e}\n")


# 패스워드 복잡성 설정 활성화
def enable_password_complexity():
    print("패스워드 복잡성 설정을 활성화합니다.")

    desktop_path = os.path.join(os.path.join(os.environ["USERPROFILE"]), "Desktop")
    export_cfg_path = os.path.join(desktop_path, "cfg.txt")

    try:
        export_security_settings(export_cfg_path)

        print("파일에서 'PasswordComplexity' 설정을 '1'로 변경합니다.")
        with open(export_cfg_path, "r", encoding="utf-16") as f:
            lines = f.readlines()
        found = False
        with open(export_cfg_path, "w", encoding="utf-8", errors="ignore") as f:
            for line in lines:
                if "PasswordComplexity" in line:
                    f.write("PasswordComplexity = 1\n")
                    found = True
                else:
                    f.write(line)
            if not found:
                if not any("[System Access]" in l for l in lines):
                    f.write("\n[System Access]\n")
                f.write("PasswordComplexity = 1\n")

        print("수정된 정책 파일을 시스템에 적용합니다.")
        subprocess.run(
            ["secedit", "/configure", "/db", "cfg.sdb", "/cfg", export_cfg_path],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("패스워드 복잡성 설정이 성공적으로 활성화되었습니다.\n")

    except subprocess.CalledProcessError as e:
        print(f"정책 적용 실패: {e.stderr.strip()}")
        print("오류 원인: 관리자 권한으로 실행되었는지 확인하십시오.\n")
    except FileNotFoundError as e:
        print(f"파일이 존재하지 않습니다: {e}\n")
    except Exception as e:
        print(f"예기치 않은 오류가 발생했습니다: {e}\n")

    finally:
        cleanup_security_policy_files(desktop_path, export_cfg_path)


# 패스워드 최소 암호 길이 설정
def set_min_password_length(length=8):
    print(f"패스워드 최소 암호 길이를 {length}로 설정합니다.")
    try:
        subprocess.run(
            ["net", "accounts", f"/minpwlen:{length}"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print(f"패스워드 최소 암호 길이가 '{length}'로 성공적으로 설정되었습니다.\n")
    except subprocess.CalledProcessError as e:
        print(f"패스워드 최소 암호 길이 설정 오류: {e.stderr.strip()}\n")
        print(
            "오류 원인: 관리자 권한으로 실행되지 않았거나, 명령에 문제가 있을 수 있습니다.\n"
        )
    except FileNotFoundError:
        print("'net' 명령어를 찾을 수 없습니다. 시스템 PATH를 확인해 주세요.\n")
    except Exception as e:
        print(f"예상치 못한 오류가 발생했습니다: {e}\n")


# 패스워드 최대 사용 기간 설정
def set_max_password_age(length=90):
    print("패스워드 최대 사용 기간 설정을 시작합니다.")
    try:
        subprocess.run(
            ["net", "accounts", f"/MAXPWAGE:{length}"],
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


# 패스워드 최소 사용 기간 설정
def set_min_password_age(length=1):
    print("패스워드 최소 사용 기간 설정을 시작합니다.")
    try:
        result = subprocess.run(
            ["net", "accounts", f"/MINPWAGE:{length}"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("패스워드 최소 사용 기간이 '1일'로 성공적으로 설정되었습니다.\n")

    except subprocess.CalledProcessError as e:
        print(f"패스워드 최소 사용 기간 설정 오류: {e.stderr.strip()}\n")
        print(
            "오류 원인: 관리자 권한으로 실행되지 않았거나, 명령에 문제가 있을 수 있습니다.\n"
        )
    except FileNotFoundError:
        print("'net' 명령어를 찾을 수 없습니다. 시스템 PATH를 확인해 주세요.\n")
    except Exception as e:
        print(f"예기치 않은 오류가 발생했습니다: {e}\n")


# 마지막으로 로그온한 사용자 이름 표시 안 함 설정 활성화
def hide_last_username():
    print("마지막으로 로그온한 사용자 이름 표시 안 함 설정을 활성화합니다.")

    base_key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            base_key_path,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        )

        print("레지스트리 DontDisplayLastUserName 값을 1로 설정합니다.")
        winreg.SetValueEx(reg_key, "DontDisplayLastUserName", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(reg_key)
        print(
            "마지막으로 로그온한 사용자 이름 표시 안 함 설정이 성공적으로 활성화되었습니다.\n"
        )

    except subprocess.CalledProcessError as e:
        print(
            f"마지막으로 로그온한 사용자 이름 표시 안 함 설정 오류: {e.stderr.strip()}\n"
        )
    except Exception as e:
        print(f"예상치 못한 오류 발생: {e}\n")


# 로컬 로그온 허용 정책에 Administrators, IUSR 외 다른 계정 및 그룹 제거
def restrict_local_logon_access():
    print("로컬 로그온 허용 정책을 통한 불필요한 계정 접근 제한을 시작합니다.")

    desktop_path = os.path.join(os.path.join(os.environ["USERPROFILE"]), "Desktop")
    export_cfg_path = os.path.join(desktop_path, "cfg.txt")

    try:
        print(f"현재 보안 설정을 '{export_cfg_path}' 파일로 내보냅니다.")
        export_security_settings(export_cfg_path)

        print("파일에서 'SeInteractiveLogonRight' 설정을 수정합니다.")
        with open(export_cfg_path, "r", encoding="utf-16") as f:
            lines = f.readlines()
        with open(export_cfg_path, "w", encoding="utf-8", errors="ignore") as f:
            for line in lines:
                if "SeInteractiveLogonRight" in line:
                    f.write("SeInteractiveLogonRight = *S-1-5-32-544\n")
                else:
                    f.write(line)

        print("수정된 정책 파일을 시스템에 적용합니다.")
        subprocess.run(
            ["secedit", "/configure", "/db", "cfg.sdb", "/cfg", export_cfg_path],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("로컬 로그온 허용 정책이 성공적으로 수정되었습니다.\n")

    except subprocess.CalledProcessError as e:
        print(f"정책 적용 실패: {e.stderr.strip()}")
        print("오류 원인: 관리자 권한으로 실행되었는지 확인하십시오.\n")
    except FileNotFoundError as e:
        print(f"파일이 존재하지 않습니다: {e}\n")
    except Exception as e:
        print(f"예기치 않은 오류가 발생했습니다: {e}\n")

    finally:
        cleanup_security_policy_files(desktop_path, export_cfg_path)


# 익명 SID/이름 변환 허용 해제 설정
# 보안 정책 설정 LSAAnoymousNameLookup 0
def revoke_anonymous_sid_name_translation():
    print("익명 SID/이름 변환 허용 해제 설정을 시작합니다.")

    desktop_path = os.path.join(os.path.join(os.environ["USERPROFILE"]), "Desktop")
    export_cfg_path = os.path.join(desktop_path, "cfg.txt")

    try:
        export_security_settings(export_cfg_path)

        print("파일에서 'LSAAnonymousNameLookup' 설정을 '0'으로 변경합니다.")
        with open(export_cfg_path, "r", encoding="utf-16") as f:
            lines = f.readlines()
        found = False
        section_found = False

        # secedit은 UTF-8 (BOM 없음) 또는 UTF-16으로 다시 읽을 수 있습니다.
        # 기존 코드의 방식을 따라 UTF-8로 씁니다.
        with open(export_cfg_path, "w", encoding="utf-8", errors="ignore") as f:
            for line in lines:
                if "[System Access]" in line:
                    section_found = True

                if "LSAAnonymousNameLookup" in line:
                    f.write("LSAAnonymousNameLookup = 0\n")
                    found = True
                else:
                    f.write(line)

            # [System Access] 섹션이나 설정값이 아예 없는 경우
            if not found:
                if not section_found:
                    f.write("\n[System Access]\n")
                f.write("LSAAnonymousNameLookup = 0\n")

        print("수정된 정책 파일을 시스템에 적용합니다.")
        subprocess.run(
            ["secedit", "/configure", "/db", "cfg.sdb", "/cfg", export_cfg_path],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("익명 SID/이름 변환 허용 해제 설정이 성공적으로 적용되었습니다.\n")

    except subprocess.CalledProcessError as e:
        print(f"정책 적용 실패: {e.stderr.strip()}")
        print("오류 원인: 관리자 권한으로 실행되었는지 확인하십시오.\n")
    except FileNotFoundError as e:
        print(f"파일이 존재하지 않습니다: {e}\n")
    except Exception as e:
        print(f"예기치 않은 오류가 발생했습니다: {e}\n")
    finally:
        cleanup_security_policy_files(desktop_path, export_cfg_path)


# 최근 암호 기억 설정 (설정값: 5)
def set_password_history_size(size=5):
    print(f"최근 암호 기억 설정을 {size}로 설정합니다.")
    try:
        subprocess.run(
            ["net", "accounts", f"/uniquepw:{size}"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print(f"최근 암호 기억 설정이 '{size}'로 성공적으로 설정되었습니다.\n")
    except subprocess.CalledProcessError as e:
        print(f"최근 암호 기억 설정 오류: {e.stderr.strip()}\n")
        print(
            "오류 원인: 관리자 권한으로 실행되지 않았거나, 명령에 문제가 있을 수 있습니다.\n"
        )
    except FileNotFoundError:
        print("'net' 명령어를 찾을 수 없습니다. 시스템 PATH를 확인해 주세요.\n")
    except Exception as e:
        print(f"예상치 못한 오류가 발생했습니다: {e}\n")


# 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 설정
def restrict_blank_password_logon():
    print("콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 설정을 시작합니다.")

    base_key_path = r"SYSTEM\CurrentControlSet\Control\Lsa"
    try:
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            base_key_path,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        )

        print("레지스트리 LimitBlankPasswordUse 값을 1로 설정합니다.")
        winreg.SetValueEx(reg_key, "LimitBlankPasswordUse", 0, winreg.REG_DWORD, 1)

        winreg.CloseKey(reg_key)
        print(
            "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 설정이 성공적으로 적용되었습니다.\n"
        )

    except subprocess.CalledProcessError as e:
        print(
            f"콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 설정 오류: {e.stderr.strip()}\n"
        )
    except Exception as e:
        print(f"예상치 못한 오류 발생: {e}\n")


# 원격터미널 접속 가능한 사용자 그룹 제한 설정
# Administrators, jlkAdmin, jlk 계정만 허용
def restrict_rdp_user_group():
    print("원격터미널 접속 가능한 사용자 그룹 제한 설정을 시작합니다.")

    desktop_path = os.path.join(os.path.join(os.environ["USERPROFILE"]), "Desktop")
    export_cfg_path = os.path.join(desktop_path, "cfg.txt")

    try:
        print(f"현재 보안 설정을 '{export_cfg_path}' 파일로 내보냅니다.")
        export_security_settings(export_cfg_path)

        print("파일에서 'SeRemoteInteractiveLogonRight' 설정을 수정합니다.")
        with open(export_cfg_path, "r", encoding="utf-16") as f:
            lines = f.readlines()
        with open(export_cfg_path, "w", encoding="utf-8", errors="ignore") as f:
            for line in lines:
                if "SeRemoteInteractiveLogonRight" in line:
                    f.write(
                        "SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-21-*-500,*S-1-5-21-*-1001\n"
                    )
                else:
                    f.write(line)

        print("수정된 정책 파일을 시스템에 적용합니다.")
        subprocess.run(
            ["secedit", "/configure", "/db", "cfg.sdb", "/cfg", export_cfg_path],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print(
            "원격터미널 접속 가능한 사용자 그룹 제한 설정이 성공적으로 수정되었습니다.\n"
        )

    except subprocess.CalledProcessError as e:
        print(f"정책 적용 실패: {e.stderr.strip()}")
        print("오류 원인: 관리자 권한으로 실행되었는지 확인하십시오.\n")
    except FileNotFoundError as e:
        print(f"파일이 존재하지 않습니다: {e}\n")
    except Exception as e:
        print(f"예기치 않은 오류가 발생했습니다: {e}\n")

    finally:
        cleanup_security_policy_files(desktop_path, export_cfg_path)


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
                    "powershell",
                    "-Command",
                    f"Set-LocalUser -Name '{user}' -PasswordNeverExpires $false",
                ],
                check=True,
                capture_output=True,
                text=True,
                encoding="cp949",
            )
            print(
                f"계정 '{user}'의 '암호 사용 기간 제한 없음' 설정이 비활성화되었습니다.\n"
            )
        except subprocess.CalledProcessError as e:
            print(f"계정 '{user}'의 설정 변경 오류: {e.stderr.strip()}\n")
        except Exception as e:
            print(f"'{user}' 계정 처리 중 예기치 않은 오류 발생: {e}\n")
