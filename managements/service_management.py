import subprocess
import winreg

from utils import get_share_name_list, get_share_permissions, is_windows_server


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


# IPC$를 제외한 하드디스크의 기본 공유 비활성화
def disable_default_shares():

    key_path = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

    try:
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            key_path,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        )
        winreg.SetValueEx(reg_key, "AutoShareServer", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(reg_key, "AutoShareWks", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(reg_key)
        print(
            "레지스트리 값(AutoShareServer, AutoShareWks)이 성공적으로 '0'으로 변경되었습니다."
        )

        shares_to_delete = ["C$", "D$", "E$"]
        print("기존의 기본 공유를 삭제합니다.")
        for share in shares_to_delete:
            try:
                subprocess.run(
                    ["net", "share", share, "/delete"],
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="cp949",
                    timeout=5,  # 명령어 타임아웃 설정
                )
                print(f"'{share}' 공유가 삭제되었습니다.")
            except subprocess.CalledProcessError:
                print(f"'{share}' 공유를 찾을 수 없거나 이미 삭제되었습니다.")
            except subprocess.TimeoutExpired:
                print(f"'{share}' 삭제 명령어 시간 초과. 다음 공유로 넘어갑니다.")

        print("관련 서비스를 재시작하여 변경사항을 적용합니다.")
        subprocess.run(
            ["powershell.exe", "-Command", "Stop-Service -Name LanmanServer -Force"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        subprocess.run(
            ["powershell.exe", "-Command", "Start-Service -Name LanmanServer"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("기본 공유가 성공적으로 비활성화되었습니다.")
        print("시스템을 재부팅하면 변경사항이 적용됩니다.\n")

    except FileNotFoundError:
        print(f"오류: 레지스트리 키 '{key_path}'를 찾을 수 없습니다.\n")

    except Exception as e:
        print(f"오류가 발생했습니다: {e}\n")


# NetbiosOptions 값을 2로 설정
def set_netbios_options():
    base_key_path = r"SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"

    try:
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            base_key_path,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        )

        winreg.SetValueEx(reg_key, "NetbiosOptions", 0, winreg.REG_DWORD, 2)

        winreg.CloseKey(reg_key)
        print(f"'etbiosOptions'를 '2'로 성공적으로 설정했습니다.\n")

    except FileNotFoundError:
        print(f"오류: 레지스트리 경로 '{base_key_path}'를 찾을 수 없습니다.\n")
    except Exception as e:
        print(f"NetbiosOptions 설정 중 오류가 발생했습니다: {e}\n")


# FTP 서비스 구동 확인 및 시작유형을 "사용 안 함"으로 설정
def disable_ftp_service():
    print("")
    print("FTP 서비스를 중지합니다.")
    try:
        subprocess.run(
            ["net", "stop", "ftpsvc"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("FTP 서비스가 성공적으로 중지되었습니다.")
    except subprocess.CalledProcessError as e:
        if "서비스 이름이 잘못되었습니다." in e.stderr.strip():
            print("FTP 서비스를 미사용 중입니다.\n")
            return
        else:
            print(f"FTP 서비스 중지 실패: {e.stderr.strip()}\n")
            return

    print("FTP 서비스의 시작 유형을 '사용 안 함'으로 설정합니다.")
    try:
        subprocess.run(
            ["sc", "config", "ftpsvc", "start=", "disabled"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("FTP 서비스의 시작 유형이 '사용 안 함'으로 설정되었습니다.\n")
    except subprocess.CalledProcessError as e:
        print(f"FTP 서비스 시작 유형 변경 실패: {e.stderr.strip()}\n")


# 모든 DNS 영역의 SecureSecondaries 값을 2로 설정
def set_dns_zone_transfer():
    base_key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones"

    if is_windows_server():
        print("현재 OS는 Windows Server입니다. DNS Zone Transfer 설정을 시작합니다.")
    else:
        print("현재 OS는 Windows Client입니다. 기능을 실행할 수 없습니다.\n")
        return

    try:
        # 'Zones' 기본 키를 열어 DNS 영역들을 탐색합니다.
        base_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            base_key_path,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )

        i = 0
        while True:
            try:
                # 다음 DNS 영역 이름(서브키)을 가져옵니다.
                zone_name = winreg.EnumKey(base_key, i)
                zone_key_path = f"{base_key_path}\\{zone_name}"

                # 값을 수정하기 위해 해당 영역 키를 엽니다.
                zone_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    zone_key_path,
                    0,
                    winreg.KEY_READ | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
                )

                # 현재 SecureSecondaries 값을 확인합니다.
                try:
                    current_value, _ = winreg.QueryValueEx(
                        zone_key, "SecureSecondaries"
                    )

                    if current_value != 2:
                        print(
                            f"'{zone_name}' 영역: SecureSecondaries 값이 {current_value}이므로 2로 변경합니다."
                        )
                        winreg.SetValueEx(
                            zone_key, "SecureSecondaries", 0, winreg.REG_DWORD, 2
                        )
                        print(f"'{zone_name}' 영역: 설정이 변경되었습니다.")
                    else:
                        print(
                            f"'{zone_name}' 영역: SecureSecondaries 값이 이미 2이므로 양호합니다."
                        )

                except FileNotFoundError:
                    # 'SecureSecondaries' 값이 없는 경우 새로 생성하고 2로 설정합니다.
                    print(
                        f"'{zone_name}' 영역: SecureSecondaries 값이 없어 새로 생성하고 2로 설정합니다."
                    )
                    winreg.SetValueEx(
                        zone_key, "SecureSecondaries", 0, winreg.REG_DWORD, 2
                    )
                    print(f"'{zone_name}' 영역: 설정이 변경되었습니다.")

                finally:
                    winreg.CloseKey(zone_key)

            except OSError:
                # 더 이상 서브키가 없으면 루프를 종료합니다.
                break
            except Exception as e:
                print(f"'{zone_name}' 영역 처리 중 오류 발생: {e}\n")
            finally:
                i += 1

        winreg.CloseKey(base_key)
        print("DNS Zone Transfer 설정을 종료합니다.\n")

    except FileNotFoundError:
        print(
            f"오류: 레지스트리 경로 '{base_key_path}'를 찾을 수 없습니다. DNS 서버 역할이 설치되지 않았을 수 있습니다.\n"
        )
    except Exception as e:
        print(f"예상치 못한 오류 발생: {e}\n")
