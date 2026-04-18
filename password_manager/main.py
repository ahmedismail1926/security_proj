import sys
import getpass
import os
import json
from modules.elgamal_keygen import initialize_user, export_public_key
from modules.vault_manager import create_vault, add_credential, get_credential, update_credential, delete_credential
from modules.dh_export import (
    export_step1,
    export_step2,
    export_finalize,
    import_finalize
)

def _extract_username_from_path(key_path: str) -> str:
    """Extract the username directory component from a key path.

    Example: keys/bob/public_key.json  →  'bob'
    """
    parts = key_path.replace('\\', '/').split('/')
    if len(parts) >= 2:
        return parts[-2]
    return ""


def main():
    if len(sys.argv) < 2:
        _usage()
        sys.exit(1)

    command = sys.argv[1]

    try:
        # ── init ──────────────────────────────────────────────────────────
        if command == "init":
            if len(sys.argv) != 3:
                print("Usage: python main.py init <username>", file=sys.stderr)
                sys.exit(1)
            username = sys.argv[2]
            mp = getpass.getpass("Enter new master password: ")
            initialize_user(username)
            create_vault(username, mp)
            print(f"User '{username}' initialized and vault created.")

        # ── export-key ────────────────────────────────────────────────────
        elif command == "export-key":
            if len(sys.argv) != 4:
                print("Usage: python main.py export-key <username> <output_path>",
                      file=sys.stderr)
                sys.exit(1)
            username    = sys.argv[2]
            output_path = sys.argv[3]
            export_public_key(username, output_path)
            print(f"Public key for '{username}' exported to {output_path}.")

        # ── add ───────────────────────────────────────────────────────────
        elif command == "add":
            if len(sys.argv) != 3:
                print("Usage: python main.py add <username>", file=sys.stderr)
                sys.exit(1)
            username = sys.argv[2]
            mp       = getpass.getpass("Enter master password: ")
            website  = input("Website: ")
            user     = input("Username: ")
            password = getpass.getpass("Password: ")
            add_credential(username, mp, website, user, password)
            print("Credential added successfully.")

        # ── get ───────────────────────────────────────────────────────────
        elif command == "get":
            if len(sys.argv) != 4:
                print("Usage: python main.py get <username> <website>",
                      file=sys.stderr)
                sys.exit(1)
            username = sys.argv[2]
            website  = sys.argv[3]
            mp       = getpass.getpass("Enter master password: ")
            entry    = get_credential(username, mp, website)
            if entry:
                print(f"Website:  {entry.get('website')}")
                print(f"Username: {entry.get('username')}")
                print(f"Password: {entry.get('password')}")
            else:
                print("Not found.")

        # ── update ────────────────────────────────────────────────────────
        elif command == "update":
            if len(sys.argv) != 4:
                print("Usage: python main.py update <username> <website>",
                      file=sys.stderr)
                sys.exit(1)
            username     = sys.argv[2]
            website      = sys.argv[3]
            mp           = getpass.getpass("Enter master password: ")
            new_user     = input("New username: ")
            new_password = getpass.getpass("New password: ")
            update_credential(username, mp, website, new_user, new_password)
            print("Credential updated successfully.")

        # ── delete ────────────────────────────────────────────────────────
        elif command == "delete":
            if len(sys.argv) != 4:
                print("Usage: python main.py delete <username> <website>",
                      file=sys.stderr)
                sys.exit(1)
            username = sys.argv[2]
            website  = sys.argv[3]
            mp       = getpass.getpass("Enter master password: ")
            delete_credential(username, mp, website)
            print("Credential deleted successfully.")


        elif command == "export-step1":
            if len(sys.argv) != 5:
                print("Usage: python main.py export-step1 <sender> <receiver> <filename>", file=sys.stderr)
                sys.exit(1)

            sender = sys.argv[2]
            receiver = sys.argv[3]
            filename = sys.argv[4]

            export_step1(sender, receiver, filename)
        elif command == "export-step2":
            if len(sys.argv) != 4:
                print("Usage: python main.py export-step2 <receiver> <filename>", file=sys.stderr)
                sys.exit(1)

            receiver = sys.argv[2]
            filename = sys.argv[3]

            export_step2(receiver, filename)
        elif command == "export-final":
            if len(sys.argv) != 4:
                print("Usage: python main.py export-final <sender> <filename>", file=sys.stderr)
                sys.exit(1)

            sender = sys.argv[2]
            filename = sys.argv[3]

            mp = getpass.getpass("Enter master password: ")

            export_finalize(sender, mp, filename)
        elif command == "import-final":
            if len(sys.argv) != 4:
                print("Usage: python main.py import-final <receiver> <filename>", file=sys.stderr)
                sys.exit(1)

            receiver = sys.argv[2]
            filename = sys.argv[3]

            mp = getpass.getpass("Enter master password for new vault: ")

            import_finalize(receiver, mp, filename)
        # ── export ────────────────────────────────────────────────────────
        # elif command == "export":
        #     # Usage: python main.py export <sender_username> <receiver_username> <output_file>
        #     #
        #     # The receiver's ElGamal public key must already exist locally
        #     # (placed there by the receiver via `export-key` or manual copy).
        #     if len(sys.argv) != 5:
        #         print(
        #             "Usage: python main.py export "
        #             "<sender_username> <receiver_username> <output_file>",
        #             file=sys.stderr
        #         )
        #         sys.exit(1)

        #     sender_username   = sys.argv[2]
        #     receiver_username = sys.argv[3]
        #     output_file       = sys.argv[4]

        #     mp = getpass.getpass("Enter master password: ")

        #     export_filename = os.path.basename(output_file).replace('.json', '')
        #     export_vault(sender_username, mp, receiver_username, export_filename)
        #     print(f"Vault exported successfully to exports/{export_filename}.json")

        # # ── import ────────────────────────────────────────────────────────
        # elif command == "import":
        #     # Usage: python main.py import <receiver_username> <export_file>
        #     #
        #     # The sender's username is embedded in the export file itself;
        #     # their ElGamal public key must exist locally for signature verification.
        #     if len(sys.argv) != 4:
        #         print(
        #             "Usage: python main.py import <receiver_username> <export_file>",
        #             file=sys.stderr
        #         )
        #         sys.exit(1)

        #     receiver_username = sys.argv[2]
        #     export_file       = sys.argv[3]

        #     mp = getpass.getpass("Enter master password for new vault: ")

        #     export_filename = os.path.basename(export_file).replace('.json', '')
        #     import_vault(receiver_username, mp, export_filename)
        #     print(f"Vault imported successfully for user '{receiver_username}'.")

        else:
            print(f"Unknown command: {command}", file=sys.stderr)
            _usage()
            sys.exit(1)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def _usage():
    print(
        "\nUsage: python main.py <command> [args]\n"
        "\nCommands:\n"
        "  init           <username>                           Initialize user and vault\n"
        "  export-key     <username> <output_path>             Export public key for sharing\n"
        "  add            <username>                           Add a credential\n"
        "  get            <username> <website>                 Retrieve a credential\n"
        "  update         <username> <website>                 Update a credential\n"
        "  delete         <username> <website>                 Delete a credential\n"
        "\n"
        "  # ── Secure DH Vault Export (Multi-step protocol) ──\n"
        "  export-step1   <sender> <receiver> <session_file>   Start DH exchange (sender → receiver)\n"
        "  export-step2   <receiver> <session_file>            Respond to DH exchange (receiver → sender)\n"
        "  export-final   <sender> <session_file>              Encrypt & sign vault (sender final step)\n"
        "  import-final   <receiver> <session_file>            Decrypt & import vault (receiver final step)\n",
        file=sys.stderr
    )
    
if __name__ == "__main__":
    main()