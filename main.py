__version__ = "0.0.0"
__author__ = "LEE SANG U"
__project_name__ = "Windows Security Scanner"

def show_info():
    """프로젝트 정보를 출력하는 함수"""
    print("---------------------------------")
    print(f"프로젝트명: {__project_name__}")
    print(f"버전: {__version__}")
    print(f"개발자: {__author__}")
    print("---------------------------------")


def main():
    show_info()
    print("프로그램이 시작되었습니다....\n")


if __name__ == "__main__":
    main()
