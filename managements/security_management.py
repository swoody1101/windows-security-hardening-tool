import subprocess
import os
import re
import winreg

from utils import cleanup_security_policy_files


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


# 로그인하지 않고 시스템 종료 비활성화 설정
def configure_shutdown_policy():
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    value_name = "shutdownwithoutlogon"

    try:
        reg_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        try:
            current_value, _ = winreg.QueryValueEx(reg_key, value_name)
            print(f"현재 '{value_name}' 값: {current_value}")
        except FileNotFoundError:
            current_value = None
            print(f"현재 '{value_name}' 값이 존재하지 않습니다.")

        if current_value is None or current_value != 0:
            print("정책이 '사용 안 함'으로 설정되어 있지 않아 값을 0으로 변경합니다.")
            winreg.SetValueEx(reg_key, value_name, 0, winreg.REG_DWORD, 0)
            print("정책이 성공적으로 '사용 안 함'으로 설정되었습니다.\n")
        else:
            print("정책이 이미 '사용 안 함'으로 설정되어 있어 양호한 상태입니다.\n")

    except Exception as e:
        print(f"정책 설정 중 오류가 발생했습니다: {e}\n")

    finally:
        if reg_key:
            winreg.CloseKey(reg_key)


# 원격 시스템에서 강제 시스템 종료 정책에 "Administrators"만 존재하도록 변경
def configure_remote_shutdown_privilege():
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

        print(
            "파일에서 'SeRemoteShutdownPrivilege' 설정을 '*S-1-5-32-544'으로 변경합니다."
        )
        with open(export_cfg_path, "r", encoding="utf-16") as f:
            lines = f.readlines()
        found = False
        with open(export_cfg_path, "w", encoding="utf-8", errors="ignore") as f:
            for line in lines:
                if "SeRemoteShutdownPrivilege" in line:
                    f.write("SeRemoteShutdownPrivilege = *S-1-5-32-544\n")
                    found = True
                else:
                    f.write(line)
            if not found:
                if not any("[Privilege Rights]" in l for l in lines):
                    f.write("\n[Privilege Rights]\n")
                f.write("SeRemoteShutdownPrivilege = *S-1-5-32-544\n")

        print("수정된 정책 파일을 시스템에 적용합니다.")
        subprocess.run(
            ["secedit", "/configure", "/db", "cfg.sdb", "/cfg", export_cfg_path],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print(
            "원격 시스템에서 강제 시스템 종료 설정이 성공적으로 비활성화되었습니다.\n"
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


# 보안 감사를 로그 할 수 없을 경우 시스템 종료 설정 비활성화
def configure_crash_on_audit_fail():
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

        print("파일에서 'CrashOnAuditFail' 설정을 '4,0'으로 변경합니다.")
        with open(export_cfg_path, "r", encoding="utf-16") as f:
            lines = f.readlines()
        found = False
        with open(export_cfg_path, "w", encoding="utf-8", errors="ignore") as f:
            for line in lines:
                if "CrashOnAuditFail" in line:
                    f.write(
                        "MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail = 4,0\n"
                    )
                    found = True
                else:
                    f.write(line)
            if not found:
                if not any("[Registry Values]" in l for l in lines):
                    f.write("\n[Registry Values]\n")
                f.write(
                    "MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail = 4,0\n"
                )

        print("수정된 정책 파일을 시스템에 적용합니다.")
        subprocess.run(
            ["secedit", "/configure", "/db", "cfg.sdb", "/cfg", export_cfg_path],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print(
            "보안 감사를 로그 할 수 없을 경우 즉시 종료 설정이 성공적으로 비활성화되었습니다.\n"
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


# SAM 계정 및 공유 열거를 제한하도록 restrictanonymous와 restrictanonymoussam 레지스트리 값을 1로 변경
def restrict_anonymous_enumeration():
    key_path = r"SYSTEM\CurrentControlSet\Control\Lsa"

    try:
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            key_path,
            0,
            winreg.KEY_READ | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        )

        print("restrictanonymous 값을 1로 설정합니다.")
        winreg.SetValueEx(reg_key, "restrictanonymous", 0, winreg.REG_DWORD, 1)

        print("restrictanonymoussam 값을 1로 설정합니다.")
        winreg.SetValueEx(reg_key, "restrictanonymoussam", 0, winreg.REG_DWORD, 1)

        winreg.CloseKey(reg_key)
        print("익명 열거 설정이 성공적으로 완료되었습니다.\n")

    except FileNotFoundError:
        print(f"오류: 레지스트리 키 '{key_path}'를 찾을 수 없습니다.\n")
    except Exception as e:
        print(f"레지스트리 값 변경 중 오류가 발생했습니다: {e}\n")


# Autologon 레지스트리가 존재할 경우 0으로 설정
def check_autoadminlogon_status():
    key_path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    value_name = "AutoAdminLogon"

    try:
        reg_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)

        try:
            current_value, _ = winreg.QueryValueEx(reg_key, value_name)
            print(f"현재 '{value_name}' 값: {current_value}")
        except FileNotFoundError:
            current_value = None
            print(f"현재 'AutoAdminLogon' 값이 존재하지 않아 비활성화 상태입니다.\n")

        if current_value == 1:
            print("'AutoAdminLogon' 값을 0으로 변경합니다.")
            winreg.SetValueEx(reg_key, value_name, 0, winreg.REG_DWORD, 0)
            print("'AutoAdminLogon'이 0으로 설정되었습니다.\n")
        elif current_value == 0:
            print("'AutoAdminLogon'이 이미 0으로 설정되어 있습니다.\n")

    except Exception as e:
        print(f"정책 설정 중 오류가 발생했습니다: {e}\n")

    finally:
        if "reg_key" in locals():
            winreg.CloseKey(reg_key)


# 이동식 미디어 포맷 및 꺼내기 보안 정책을 관리자로 설정
def configure_removable_media_policy():
    desktop_path = os.path.join(os.path.join(os.environ["USERPROFILE"]), "Desktop")
    export_cfg_path = os.path.join(desktop_path, "cfg.txt")

    try:
        print("AllocateDASD' 값을 설정하여 로그인 화면 접근을 차단합니다.")
        key_path_dasd = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        reg_key_dasd = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path_dasd)
        winreg.SetValueEx(reg_key_dasd, "AllocateDASD", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(reg_key_dasd)
        print("'AllocateDASD' 값이 성공적으로 0으로 설정되었습니다.")

        print("'RemovableMedia' 값을 설정하여 포맷 및 꺼내기 권한을 제한합니다.")
        key_path_rm = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        reg_key_rm = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path_rm)
        winreg.SetValueEx(reg_key_rm, "RemovableMedia", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(reg_key_rm)
        print(
            "이동식 미디어 포맷 및 꺼내기 허용 정책이 'Administrators'로 제한되었습니다."
        )

        print("모든 이동식 미디어 보안 정책 설정이 완료되었습니다.")

        subprocess.run(
            ["secedit", "/export", "/cfg", export_cfg_path],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        with open(export_cfg_path, "r", encoding="utf-16") as f:
            lines = f.readlines()
        found = False
        with open(export_cfg_path, "w", encoding="utf-8", errors="ignore") as f:
            for line in lines:
                if "RemovableMedia" in line:
                    f.write("RemovableMedia = 1\n")
                    found = True
                else:
                    f.write(line)
            if not found:
                if not any("[Registry Values]" in l for l in lines):
                    f.write("\n[System Access]\n")
                f.write("RemovableMedia = 1\n")

        print("수정된 정책 파일을 시스템에 적용합니다.\n")
        subprocess.run(
            ["secedit", "/configure", "/db", "cfg.sdb", "/cfg", export_cfg_path],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )

    except Exception as e:
        print(f"오류: 정책 설정 중 오류가 발생했습니다: {e}\n")

    finally:
        cleanup_security_policy_files(desktop_path, export_cfg_path)
