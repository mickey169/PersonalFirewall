
import subprocess
import json
import ipaddress

RULE_NAME = "PersonalFirewall-TestBlock"
TEST_IP = "192.0.2.1"


def run_powershell(command):
    return subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            command
        ],
        capture_output=True,
        text=True,
        timeout=15
    )


def get_firewall_status():
    command = (
        "Get-NetFirewallProfile | "
        "Select-Object Name, Enabled | "
        "ConvertTo-Json -Compress"
    )

    try:
        result = run_powershell(command)

        if result.returncode != 0:
            print("Could not read firewall status.")
            print(result.stderr)
            return

        profiles = json.loads(result.stdout)

        if isinstance(profiles, dict):
            profiles = [profiles]

        print("\n=== WINDOWS FIREWALL STATUS ===")

        for profile in profiles:
            status = "ENABLED" if profile["Enabled"] else "DISABLED"
            print(f'{profile["Name"]}: {status}')

    except (OSError, subprocess.TimeoutExpired,
            json.JSONDecodeError, KeyError) as error:
        print("Status check failed:", error)


def block_ip(ip_address):
    try:
        address = str(ipaddress.ip_address(ip_address))

        if address != TEST_IP:
            print("For this first test, use:", TEST_IP)
            return

        check_command = (
            "$rule = Get-NetFirewallRule "
            "-DisplayName 'PersonalFirewall-TestBlock' "
            "-ErrorAction SilentlyContinue | "
            "Select-Object -First 1; "
            "if ($null -eq $rule) { "
            "Write-Output 'RULE_NOT_FOUND' "
            "} else { "
            "Write-Output 'RULE_FOUND' "
            "}"
        )

        check = run_powershell(check_command)

        if check.returncode != 0:
            print("Could not check existing rules.")
            print(check.stderr)
            return

        status = check.stdout.strip()

        if status == "RULE_FOUND":
            print("The test rule already exists.")
            return

        if status != "RULE_NOT_FOUND":
            print("Unexpected response:", repr(check.stdout))
            return

        create_command = (
            "New-NetFirewallRule "
            "-DisplayName 'PersonalFirewall-TestBlock' "
            "-Direction Outbound "
            "-Action Block "
            "-RemoteAddress " + address + " "
            "-Profile Any "
            "-ErrorAction Stop | "
            "Select-Object DisplayName, Enabled, Direction, Action "
            "| ConvertTo-Json -Compress"
        )

        result = run_powershell(create_command)

        if result.returncode == 0:
            print("\nRule created successfully:")
            print(result.stdout)
        else:
            print("Rule creation failed:")
            print(result.stderr)

    except ValueError:
        print("Invalid IP address.")
    except (OSError, subprocess.TimeoutExpired) as error:
        print("Operation failed:", error)

def remove_test_rule():
    """Remove only our named test rule."""

    command = (
        "Remove-NetFirewallRule "
        "-DisplayName 'PersonalFirewall-TestBlock' "
        "-ErrorAction Stop"
    )

    try:
        result = run_powershell(command)

        if result.returncode == 0:
            print("Test rule removed successfully.")
        else:
            print("Could not remove the test rule.")
            print(result.stderr)

    except (OSError, subprocess.TimeoutExpired) as error:
        print("Operation failed:", error)


if __name__ == "__main__":
    get_firewall_status()

    print("\n=== PERSONAL FIREWALL ===")
    print("Test IP:", TEST_IP)

    confirm = input("Create the test blocking rule? (yes/no): ")

    if confirm.strip().lower() == "yes":
        block_ip(TEST_IP)
    else:
        print("No firewall rule was created.")


if __name__ == "__main__":
    get_firewall_status()

    print("\n=== PERSONAL FIREWALL ===")
    print("1. Create test blocking rule")
    print("2. Remove test blocking rule")
    print("3. Exit")

    choice = input("Choose an option: ").strip()

    if choice == "1":
        block_ip(TEST_IP)
    elif choice == "2":
        confirm = input(
            "Remove PersonalFirewall-TestBlock? (yes/no): "
        )

        if confirm.strip().lower() == "yes":
            remove_test_rule()
        else:
            print("Removal cancelled.")
    elif choice == "3":
        print("Exiting Personal Firewall.")
    else:
        print("Invalid option.")

