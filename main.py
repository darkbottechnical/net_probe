from modules.Probe import Probe
from modules.parsers.command_parsers import get_search_parser
from threading import Thread
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

net_range = "0.0.0.0/0"
aggression = 1
probe = None


session = PromptSession()

def main():
    global net_range, aggression, search_parser, session, probe
    with patch_stdout():
        while True:
            try:
                command = session.prompt(" > ")
                if command:
                    command = command.strip().lower().split()
                    if command[0] in ["exit", "quit"]:
                        if probe is not None:
                            probe.stop_event.set()
                        break

                    elif command[0] == "start":
                        if probe is not None:
                            print("[!] A probe is already running. Please stop it before starting a new one.")
                            continue
                        probe = Probe(n_range=net_range, aggrlv=aggression)
                        probe_thread = Thread(target=probe.start, daemon=True)
                        probe_thread.start()
                    
                    elif command[0] == "stop":
                        if probe is not None:
                            print("[+] Stopping the probe...")
                            probe.stop()
                            probe = None
                        else:
                            print("[!] No Probe is running.")
                
                    elif command[0] == "stream":
                        if probe is not None:
                            debug_state = probe.toggle_stream()
                            print(f"Stream log {'enabled' if debug_state else 'disabled'}.")
                        else:
                            print("[!] No Probe is running.")

                    elif command[0] in ["lsh", "listhosts"]:
                        if probe is not None:
                            probe.show()
                        else:
                            print("[!] No Probe is running.")

                    elif command[0] == "search":
                        if probe is None:
                            print("[!] No Probe is running. Please start a probe first.")
                            continue
                        try:
                            search_parser = get_search_parser()
                            args = search_parser.parse_args(command[1:])
                            probe.search(args)
                        except SystemExit:
                            continue

                    elif command[0] == "info":
                        if probe is None:
                            print("[!] No Probe is running.")
                            continue
                        try:
                            target_host = command[1]
                        except IndexError:
                            print("Usage: info <ip or mac address>")
                        else:
                            for host in probe.host_list:
                                if host.ip == target_host or host.mac == target_host:
                                    host.info(output=True)
                                    break

                    elif command[0] == "set":
                        try:
                            command[1]
                        except IndexError:
                            print("Usage: set <parameter> <value>\n  Use 'params' for a list of parameters.")
                            continue

                        if command[1] == "range":
                            try:
                                net_range = command[2]
                            except IndexError:
                                print("Usage: set <parameter> <value>\n  Use 'params' for a list of parameters.")
                        elif command[1] == "aggression":
                            try:
                                aggression = int(command[2])
                            except IndexError:
                                print("Usage: set <parameter> <value>\n  Use 'params' for a list of parameters.")
                                continue
                            except ValueError:
                                print("Invalid parameter value for 'aggression': Must be an integer")
                                continue
                        else:
                            print(f"No parameters found matching '{command[1]}'")
                    elif command[0] == "params":
                        print("range: n ip range in cidr notation to filter packets and hosts.\naggression: an integer representing the level of aggression.\n\t0-1: only run passive sniffing\n\t2: run mdns and nbns probes. \n\t3+: actively probe hosts.")
                    elif command[0] == "help":
                        print("Available commands:")
                        print("  start - Start the network probe")
                        print("  stop - Stop the network probe")
                        print("  stream - Toggle stream logging")
                        print("  lsh, listhosts - List discovered hosts")
                        print("  search - Search for hosts based on criteria")
                        print("  info <ip or mac address> - Get information about a specific host")
                        print("  set <parameter> <value> - Set parameters for the probe (e.g., range, aggression)")
                        print("  params - Show available parameters and their descriptions")
                        print("  help - Show this help message")
                        print("  exit, quit - Exit the program")
                    else:
                        print("Unknown command. Type 'help' for a list of commands.")
            except KeyboardInterrupt:
                try:
                    print("Are you sure you want to exit? (y/n) ")
                    confirm = session.prompt().strip().lower()
                    if confirm == 'y':
                        if probe is not None:
                            probe.stop_event.set()
                        print("\nExiting...")
                        break
                    else:
                        continue
                except KeyboardInterrupt:
                    probe.stop_event.set()
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    main()
