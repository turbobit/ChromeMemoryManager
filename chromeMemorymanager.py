import psutil
import time
import ctypes
import tkinter as tk
from threading import Thread
import pystray
from PIL import Image

# 크롬 프로세스 메모리 임계값 (예: 500MB)
MEMORY_THRESHOLD_MB = 500
running = False
monitoring_interval = 5  # 기본 모니터링 간격 (초 단위)

# 메모리 사용량 모니터링 함수
def monitor_chrome_memory():
    global running
    while running:
        # 모든 프로세스 목록을 가져옵니다.
        for process in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                # 프로세스 이름이 'chrome' 또는 'chrome.exe' 인 경우
                if 'chrome' in process.info['name'].lower():
                    memory_usage_mb = process.info['memory_info'].rss / 1024 / 1024
                    print(f"Chrome PID: {process.info['pid']} - Memory Usage: {memory_usage_mb:.2f} MB")

                    # 메모리 사용량이 임계값을 초과할 경우 메모리 정리 시도
                    if memory_usage_mb > MEMORY_THRESHOLD_MB:
                        print(f"Attempting to reduce memory usage for Chrome process (PID: {process.info['pid']})...")
                        process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, process.info['pid'])
                        if process_handle:
                            ctypes.windll.psapi.EmptyWorkingSet(process_handle)
                            ctypes.windll.kernel32.CloseHandle(process_handle)
                            print(f"Successfully reduced memory usage for Chrome process (PID: {process.info['pid']})")
                        else:
                            print(f"Failed to access Chrome process (PID: {process.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # 프로세스가 이미 종료되었거나 접근 권한이 없을 때 예외 처리
                pass
        
        # 메모리 상태 업데이트
        show_current_memory()
        
        # 지정된 주기 대기 후 다시 확인
        time.sleep(monitoring_interval)

def start_monitoring():
    global running
    running = True
    monitoring_status.set("Monitoring: ON")
    monitoring_thread = Thread(target=monitor_chrome_memory)
    monitoring_thread.daemon = True
    monitoring_thread.start()

def stop_monitoring():
    global running
    running = False
    monitoring_status.set("Monitoring: OFF")

def show_current_memory():
    # 이전 버튼들 제거
    for widget in memory_frame.winfo_children():
        widget.destroy()
    
    memory_info = []
    for process in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            if 'chrome' in process.info['name'].lower():
                memory_usage_mb = process.info['memory_info'].rss / 1024 / 1024
                pid = process.info['pid']
                memory_info.append((memory_usage_mb, pid))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # 메모리 사용량 기준으로 내림차순 정렬
    memory_info.sort(key=lambda x: x[0], reverse=True)

    # 정렬된 메시지 표시 및 버튼 재배치
    for memory_usage_mb, pid in memory_info:
        container = tk.Frame(memory_frame)
        container.pack(fill='x', padx=5, pady=2)
        label = tk.Label(container, text=f"Chrome PID: {pid} - Memory Usage: {memory_usage_mb:.2f} MB", anchor='w')
        label.pack(side=tk.LEFT, fill='x', expand=True)
        kill_button = tk.Button(container, text=f"Kill PID: {pid}", command=lambda p=pid: kill_chrome_process(p))
        kill_button.pack(side=tk.RIGHT)

def kill_chrome_process(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()  # 프로세스 종료
        print(f"Successfully terminated Chrome process (PID: {pid})")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        print(f"Failed to terminate Chrome process (PID: {pid})")
    show_current_memory()  # UI 업데이트

def clear_memory():
    for process in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            if 'chrome' in process.info['name'].lower():
                process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, process.info['pid'])
                if process_handle:
                    ctypes.windll.psapi.EmptyWorkingSet(process_handle)
                    ctypes.windll.kernel32.CloseHandle(process_handle)
                    print(f"Successfully reduced memory usage for Chrome process (PID: {process.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    show_current_memory()  # 메모리 정리 후 UI 업데이트

def set_monitoring_interval():
    global monitoring_interval
    try:
        monitoring_interval = int(interval_selector.get()) * 60  # 분 단위 입력을 초로 변환
        print(f"Monitoring interval set to {monitoring_interval} seconds")
    except ValueError:
        print("Invalid interval input")

def hide_gui_window():
    root.withdraw()
    print("Successfully hid the GUI window from Task Manager")
    tray_icon.visible = True

def show_gui_window(icon, item=None):
    root.deiconify()
    tray_icon.visible = False

def quit_app(icon, item):
    icon.stop()
    root.quit()

def on_tray_icon_double_click(icon, item):
    show_gui_window(icon)

def create_tray_icon():
    image = Image.new('RGB', (64, 64), color=(73, 109, 137))
    menu = pystray.Menu(
        pystray.MenuItem('Show', show_gui_window),
        pystray.MenuItem('Quit', quit_app)
    )
    global tray_icon
    tray_icon = pystray.Icon("chromeMemoryManager", image, menu=menu)
    tray_icon.title = "chromeMemoryManager"
    tray_icon.run()

# GUI 설정
def create_gui():
    global memory_text, monitoring_status, interval_selector, root, tray_icon, memory_frame
    root = tk.Tk()
    root.title("Chrome Memory Manager")

    button_frame = tk.Frame(root)
    button_frame.pack(pady=5)
    
    start_button = tk.Button(button_frame, text="Start Monitoring", command=start_monitoring)
    start_button.pack(side=tk.LEFT, padx=5)

    stop_button = tk.Button(button_frame, text="Stop Monitoring", command=stop_monitoring)
    stop_button.pack(side=tk.LEFT, padx=5)

    interval_selector = tk.Entry(button_frame)
    interval_selector.pack(side=tk.LEFT, padx=5)
    interval_selector.insert(0, "5")  # 기본값 5분

    set_interval_button = tk.Button(button_frame, text="Set Monitoring Interval (minutes)", command=set_monitoring_interval)
    set_interval_button.pack(side=tk.LEFT, padx=5)
    
    button_frame2 = tk.Frame(root)
    button_frame2.pack(pady=5)
    
    memory_button = tk.Button(button_frame2, text="Show Current Memory Usage", command=show_current_memory)
    memory_button.pack(side=tk.LEFT, padx=5)

    clear_button = tk.Button(button_frame2, text="Clear Memory", command=clear_memory)
    clear_button.pack(side=tk.LEFT, padx=5)

    hide_button = tk.Button(button_frame2, text="Hide GUI from Task Manager", command=hide_gui_window)
    hide_button.pack(side=tk.LEFT, padx=5)

    memory_frame = tk.Frame(root)
    memory_frame.pack(pady=10, fill='both', expand=True)

    monitoring_status = tk.StringVar()
    monitoring_status.set("Monitoring: OFF")
    status_label = tk.Label(root, textvariable=monitoring_status)
    status_label.pack(pady=10)

    # 트레이 아이콘 생성 스레드 시작
    tray_thread = Thread(target=create_tray_icon)
    tray_thread.daemon = True
    tray_thread.start()

    root.mainloop()

if __name__ == "__main__":
    create_gui()
