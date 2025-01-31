import time
import psutil

# This whole thing is just to see how the machine reacts to the monitoring

def start_timer():
    return time.time()

def check_timer(start_time, function):
    current_time = time.time()
    duration = current_time - start_time
    
    cpu_usage = psutil.cpu_percent(interval=0.1)
    memory_info = psutil.virtual_memory()
    memory_used = memory_info.used / (1024 ** 2)
    memory_total = memory_info.total / (1024 ** 2)
    memory_percent = memory_info.percent

    print(f"{function} took {duration:.4f} seconds.")
    print(f"CPU: {cpu_usage:.2f}%")
    print(f"Memory: {memory_used:.2f} MB / {memory_total:.2f} MB ({memory_percent}%)")

    return duration