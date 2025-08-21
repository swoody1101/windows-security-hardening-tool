import winreg
import subprocess


# 원격 레지스트리 서비스(Remote Registry Service) 중지
def disable_remote_registry_service():
    print("원격 레지스트리 서비스를 중지합니다.")
    try:
        subprocess.run(
            ["net", "stop", "RemoteRegistry"],
            check=True,
            capture_output=True,
            text=True,
            encoding="cp949",
        )
        print("원격 레지스트리 서비스가 성공적으로 중지되었습니다.")
    except subprocess.CalledProcessError as e:
        if "서비스가 시작되지 않았습니다" in e.stderr:
            print("서비스가 이미 중지 상태입니다.")
        else:
            print(f"오류: 서비스 중지 실패: {e.stderr.strip()}")

    key_path = r"SYSTEM\CurrentControlSet\Services\RemoteRegistry"
    print("원격 레지스트리 서비스의 시작 유형을 '사용 안 함'으로 변경합니다.")
    try:
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            key_path,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        )

        winreg.SetValueEx(reg_key, "Start", 0, winreg.REG_DWORD, 4)

        winreg.CloseKey(reg_key)
        print(
            "원격 레지스트리의 Start 레지스트리 값이 '4'로 성공적으로 변경되었습니다.\n"
        )

    except FileNotFoundError:
        print(f"오류: 레지스트리 경로 '{key_path}'을 찾을 수 없습니다.\n")
        return
    except Exception as e:
        print(f"레지스트리 값 변경 중 오류가 발생했습니다: {e}\n")
        return
