import os
import inspect

def is_function_in_stack(function_name):
    stack = inspect.stack()
    for frame_info in stack:
        if frame_info.function == function_name:
            return True
    return False

def is_server():
    return is_function_in_stack('handshakeServer')

def debug_save(filename, data):
    if not isinstance(data, (bytes, bytearray)):
        data = data.to_string() # for some private keys (may fail)

    saved_dir = "saved_server" if is_server() else "saved_client"
    if not os.path.exists(saved_dir):
        os.makedirs(saved_dir)

    modified_filename = os.path.join(saved_dir, filename)
    
    print(f"Saving data to {modified_filename}")
    with open(modified_filename, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

    return data
