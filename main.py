"""
Main program to establish connection to firwall and allow user to
manage PanOS
"""

from connect import connect_to_firewall
from operations import (
    upgrade_pan_os,
    get_network_logs,
    create_security_policy
)

if __name__ == "__main__":
    print("Welcome!\nEnter the requested information to proceed\n")
    fw = connect_to_firewall()
    while True:
        print("\nAvailable operations:")
        print("1. Upgrade\n2. Logs\n3. Security policy\n4. Exit")
        try:
            operation = int(input("Enter operation to perform [1 / 2 / 3 / 4]: "))
        except ValueError:
            print("⚠️ Invalid input. Please enter a number between 1 and 4.")
            continue

        if operation == 1:
            print("\n⌛ Initializing OS upgrade")
            upgrade_pan_os(fw)
        elif operation == 2:
            print("\n⌛ Fetching logs")
            get_network_logs(fw)
        elif operation == 3:
            print("\n⌛ Initializing secuirty policies")
            create_security_policy(fw)
        elif operation == 4:
            print("\nExiting. Goodbye 👋")
            break
        else:
            print("\n⚠️  Invalid choice. Please select a valid option.")
