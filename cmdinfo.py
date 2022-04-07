import pyuac

def main():
    import os

    ipconfig_info = []

    print('-------------ip config information-------------\n')

    ipconfig_info.append(os.system('ipconfig -all'))

    print('\n-------------new view information *this will take a minute*-------------\n')

    ipconfig_info.append(os.system('net view'))

    print('\n-------------net session information-------------\n')

    ipconfig_info.append(os.system('net session'))

    print('\n-------------netstat -naob information-------------\n')

    ipconfig_info.append(os.system('netstat -naob'))
    input()

if __name__ == "__main__":
    if not pyuac.isUserAdmin():
        print("Re-launching as admin!")
        pyuac.runAsAdmin()
    else:
        main()  # Already an admin here.
