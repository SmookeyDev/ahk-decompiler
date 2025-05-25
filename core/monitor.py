"""
Process monitoring functionality for tracking child processes.
"""

import time
import psutil
from utils.constants import DEFAULT_CHILD_CHECK_INTERVAL


def monitor_child_processes(parent_pid, monitored_pids, stop_event, gui_callback=None):
    """
    Monitor and add child processes to the monitored list.
    
    Args:
        parent_pid (int): Parent process ID to monitor
        monitored_pids (set): Set of currently monitored PIDs
        stop_event (threading.Event): Event to signal when to stop monitoring
        gui_callback (callable, optional): Callback to update GUI
    """
    print(f"Starting child process monitoring for parent PID {parent_pid}")
    try:
        parent = psutil.Process(parent_pid)
        initial_children = set()
        monitoring_start_time = time.time()
        
        while not stop_event.is_set():
            try:
                children = parent.children(recursive=True)
                current_children = set(child.pid for child in children)
                
                # Look for new children
                new_children = current_children - initial_children
                
                for child in children:
                    if child.pid in new_children and child.pid not in monitored_pids:
                        try:
                            # Check if it's an executable file
                            child_name = child.name().lower()
                            if child_name.endswith('.exe'):
                                # Give the child process a moment to initialize
                                time.sleep(0.5)
                                
                                # Double check it still exists and is running
                                if psutil.pid_exists(child.pid):
                                    monitored_pids.add(child.pid)
                                    print(f"New child process detected: {child.name()} (PID: {child.pid})")
                                    
                                    # Log additional info about the child process
                                    try:
                                        child_info = psutil.Process(child.pid)
                                        print(f"  Child process details - Status: {child_info.status()}, Command: {' '.join(child_info.cmdline()[:2]) if child_info.cmdline() else 'N/A'}")
                                    except:
                                        pass
                                    
                                    # Update GUI if callback is provided
                                    if gui_callback:
                                        gui_callback()
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            print(f"Error accessing child process {child.pid}: {e}")
                            pass
                
                # Update the set of known children
                initial_children.update(current_children)
                
                # If we've been monitoring for a while and found children, 
                # check less frequently to reduce CPU usage
                elapsed_time = time.time() - monitoring_start_time
                if elapsed_time > 30 and monitored_pids:
                    check_interval = DEFAULT_CHILD_CHECK_INTERVAL * 2
                else:
                    check_interval = DEFAULT_CHILD_CHECK_INTERVAL
                    
                time.sleep(check_interval)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                print(f"Parent process {parent_pid} is no longer accessible")
                break
                
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"Error monitoring parent process {parent_pid}: {e}")
    
    print(f"Child process monitoring ended for parent PID {parent_pid}")


def get_process_info(pid):
    """
    Get process information for a given PID.
    
    Args:
        pid (int): Process ID
        
    Returns:
        dict: Process information or None if process doesn't exist
    """
    try:
        proc = psutil.Process(pid)
        return {
            'pid': pid,
            'name': proc.name(),
            'status': proc.status(),
            'exists': True
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {
            'pid': pid,
            'name': '<terminated>',
            'status': 'terminated',
            'exists': False
        }


def get_active_pids(monitored_pids):
    """
    Filter monitored PIDs to get only active ones.
    
    Args:
        monitored_pids (set): Set of monitored PIDs
        
    Returns:
        list: List of active PIDs
    """
    return [pid for pid in monitored_pids if psutil.pid_exists(pid)]


def terminate_process_safely(pid):
    """
    Safely terminate a process by PID.
    
    Args:
        pid (int): Process ID to terminate
        
    Returns:
        bool: True if terminated successfully, False otherwise
    """
    try:
        if psutil.pid_exists(pid):
            proc = psutil.Process(pid)
            proc.terminate()
            return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return False 