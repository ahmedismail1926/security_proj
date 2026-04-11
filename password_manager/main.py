import sys
import getpass
import os
import json
from modules.elgamal_keygen import initialize_user
from modules.vault_manager import create_vault, add_credential, get_credential, update_credential, delete_credential
from modules.dh_export import export_vault, import_vault

def _extract_username_from_path(key_path: str) -> str:
    # Example: keys/bob/public_key.json -> bob
    parts = key_path.replace('\\', '/').split('/')
    if len(parts) >= 2:
        return parts[-2]
    return ""

def main():
    if len(sys.argv) < 2:
        print("Usage: main.py <command> [args]", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]

    try:
        if command == "init":
            if len(sys.argv) != 3:
                print("Usage: python main.py init <username>", file=sys.stderr)
                sys.exit(1)
            username = sys.argv[2]
            mp = getpass.getpass("Enter new master password: ")
            initialize_user(username)
            create_vault(username, mp)
            print(f"User '{username}' initialized and vault created.")

        elif command == "add":
            if len(sys.argv) != 3:
                print("Usage: python main.py add <username>", file=sys.stderr)
                sys.exit(1)
            username = sys.argv[2]
            mp = getpass.getpass("Enter master password: ")
            website = input("Website: ")
            user = input("Username: ")
            password = getpass.getpass("Password: ")
            add_credential(username, mp, website, user, password)
            print("Credential added successfully.")

        elif command == "get":
            if len(sys.argv) != 4:
                print("Usage: python main.py get <username> <website>", file=sys.stderr)
                sys.exit(1)
            username = sys.argv[2]
            website = sys.argv[3]
            mp = getpass.getpass("Enter master password: ")
            entry = get_credential(username, mp, website)
            if entry:
                print(f"Website: {entry.get('website')}")
                print(f"Username: {entry.get('username')}")
                print(f"Password: {entry.get('password')}")
            else:
                print("Not found.")

        elif command == "update":
            if len(sys.argv) != 4:
                print("Usage: python main.py update <username> <website>", file=sys.stderr)
                sys.exit(1)
            username = sys.argv[2]
            website = sys.argv[3]
            mp = getpass.getpass("Enter master password: ")
            new_user = input("New username: ")
            new_password = getpass.getpass("New password: ")
            update_credential(username, mp, website, new_user, new_password)
            print("Credential updated successfully.")

        elif command == "delete":
            if len(sys.argv) != 4:
                print("Usage: python main.py delete <username> <website>", file=sys.stderr)
                sys.exit(1)
            username = sys.argv[2]
            website = sys.argv[3]
            mp = getpass.getpass("Enter master password: ")
            delete_credential(username, mp, website)
            print("Credential deleted successfully.")

        elif command == "export":
            if len(sys.argv) != 5:
                print("Usage: python main.py export <sender_username> <recipient_public_key_path> <output_file>", file=sys.stderr)
                sys.exit(1)
            sender_username = sys.argv[2]
            recipient_pub_path = sys.argv[3]
            output_file = sys.argv[4]
            
            recipient_username = _extract_username_from_path(recipient_pub_path)
            mp = getpass.getpass("Enter master password: ")
            
            # Use filename without extension if passed with it
            export_filename = os.path.basename(output_file).replace('.json', '')
            export_vault(sender_username, mp, recipient_username, export_filename)
            print(f"Vault exported successfully to {output_file}.")

        elif command == "import":
            if len(sys.argv) != 5:
                print("Usage: python main.py import <recipient_username> <export_file> <sender_public_key_path>", file=sys.stderr)
                sys.exit(1)
            recipient_username = sys.argv[2]
            export_file = sys.argv[3]
            sender_pub_path = sys.argv[4]
            
            mp = getpass.getpass("Enter new or existing master password: ")
            
            export_filename = os.path.basename(export_file).replace('.json', '')
            import_vault(recipient_username, mp, export_filename)
            print(f"Vault imported successfully for user '{recipient_username}'.")

        else:
            print(f"Unknown command: {command}", file=sys.stderr)
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
