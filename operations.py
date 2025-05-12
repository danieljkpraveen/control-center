import csv
from xml.etree import ElementTree as ET
from panos.updater import SoftwareUpdater
from panos.policies import SecurityRule
from tabulate import tabulate

################# OS Upgrade Function #################
def upgrade_pan_os(fw):
    print("Initializing software updater...")
    updater = SoftwareUpdater()
    fw.add(updater)

    # Check for available software updates
    print("Checking for available software updates...")
    updates = updater.check()

    # Filter out the version that's currently running
    upgrade_candidates = []
    for update in updates:
        if not update.current:
            upgrade_candidates.append(update)

    # Exit if no upgrade options are found
    if len(upgrade_candidates) == 0:
        print("No upgrade candidates available.")
        return

    # Display available upgrade versions
    print("\nAvailable PAN-OS Versions for Upgrade:")
    for update in upgrade_candidates:
        if update.downloaded:
            status = "Downloaded"
        else:
            status = "Not downloaded"
        print(f"- {update.version} ({status})")

    # Prompt user to select a version
    target_version = input("\nEnter the version to upgrade to: ").strip()

    # Find the selected version object
    target = None
    for update in upgrade_candidates:
        if update.version == target_version:
            target = update
            break

    # Exit if selected version is invalid
    if target is None:
        print(f"Version {target_version} not found among upgrade candidates.")
        return

    # Perform upgrade (download, install, reboot)
    print(f"\nUpgrading to PAN-OS {target_version} (download + install + reboot)...")
    updater.download_install_reboot(version=target_version, sync=True)
    print("Upgrade and reboot process initiated successfully.")


################# Fetch Logs Function #################
def get_network_logs(fw):
    # Available log types (from PAN-OS CLI documentation)
    valid_log_types = [
        "traffic", "threat", "url", "wildfire", "data",
        "config", "system", "hipmatch", "gpc", "iptag",
        "tunnel", "alarm", "auth", "user-id", "decryption", "unified"
    ]

    # Get user input
    print("Available log types:")
    for name in valid_log_types:
        print(f"- {name}")

    log_type_input = input("\nEnter log type ('all' to display all logs): ").strip().lower()
    log_limit_input = input("Enter number of logs to fetch: ")
    log_limit = int(log_limit_input) if log_limit_input.isdigit() else 10

    start_time = input("Start time (YYYY/MM/DD HH:MM:SS): ").strip()
    end_time = input("End time (YYYY/MM/DD HH:MM:SS): ").strip()

    # Determine which log types to fetch
    if log_type_input == "all":
        log_types = valid_log_types
    elif log_type_input in valid_log_types:
        log_types = [log_type_input]
    else:
        print(f"Invalid log type: {log_type_input}")
        return

    for log_type in log_types:
        print(f"\nFetching {log_type} logs...")

        cmd = (
            f"show log {log_type} direction equal forward "
            f"time {start_time} to {end_time} max {log_limit}"
        )

        try:
            xml_response = fw.op(cmd, cmd="show")
            root = ET.fromstring(xml_response)
            entries = root.findall(".//entry")

            if not entries:
                print("No log entries found.")
                continue

            # Dynamically extract field names using full loop
            field_names_set = set()
            for entry in entries:
                for elem in entry:
                    field_names_set.add(elem.tag)

            field_names = sorted(list(field_names_set))

            # Build table rows
            table = []
            for entry in entries:
                row = []
                for field in field_names:
                    value = entry.findtext(field, default="-")
                    row.append(value)
                table.append(row)

            # Display in terminal
            print(tabulate(table, headers=field_names, tablefmt="grid"))

            # Write to CSV file per log type
            filename = f"{log_type}_logs.csv"
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(field_names)
                writer.writerows(table)

            print(f"Logs exported to: {filename}")

        except Exception as e:
            print(f"Error fetching {log_type} logs: {e}")


################# Security Policy Function #################
def create_security_policy(fw):
    # Get user inputs for the rule
    rule_name = input("Enter rule name: ").strip()
    from_zone = input("Enter source zone: ").strip()
    to_zone = input("Enter destination zone: ").strip()
    source_ip = input("Enter source IP (or 'any'): ").strip() or "any"
    destination_ip = input("Enter destination IP (or 'any'): ").strip() or "any"
    application = input("Enter application (or 'any'): ").strip() or "any"
    service = input("Enter service (or 'application-default' or 'any'): ").strip() or "application-default"
    action = input("Enter action (allow/deny/drop): ").strip().lower()

    # Create rule object
    rule = SecurityRule(
        name=rule_name,
        fromzone=[from_zone],
        tozone=[to_zone],
        source=[source_ip],
        destination=[destination_ip],
        application=[application],
        service=[service],
        action=action
    )

    # Attach to firewall and apply
    fw.add(rule)

    try:
        rule.apply()  # or use rule.create() if preferred
        print(f"✅ Rule '{rule_name}' created successfully.")
    except Exception as e:
        print(f"❌ Failed to create rule: {e}")