
Python:
import os
import hashlib
import time
import threading
import logging

# Güvenilir oyun dosyalarının listesi ve hash değerleri (SHA-256 hash kullanıldı)
trusted_files = {
    "game.exe": "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2",  # Örnek SHA-256 hash değeri
    "data.bin": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # Örnek SHA-256 hash değeri
}

# Yasaklı kullanıcıların listesi
banned_users = []

# Loglama yapılandırması
logging.basicConfig(filename="file_integrity_check.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def hash_file(file_path):
    """Dosyanın SHA-256 hash değerini hesaplar."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as file:
            chunk = 0
            while chunk != b'':
                chunk = file.read(1024)
                sha256.update(chunk)
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {str(e)}")
        return None
    return sha256.hexdigest()

def check_integrity():
    """Dosya bütünlüğünü kontrol eder."""
    for file_name, trusted_hash in trusted_files.items():
        if os.path.exists(file_name):
            file_hash = hash_file(file_name)
            if file_hash != trusted_hash:
                logging.warning(f"Warning: {file_name} has been modified!")
                print(f"Warning: {file_name} has been modified!")
                return False
        else:
            logging.warning(f"Warning: {file_name} is missing!")
            print(f"Warning: {file_name} is missing!")
            return False
    logging.info("All files are intact.")
    print("All files are intact.")
    return True

def ban_user(user_id):
    """Kullanıcıyı yasaklar."""
    if user_id not in banned_users:
        banned_users.append(user_id)
        logging.info(f"User {user_id} has been banned.")
        print(f"User {user_id} has been banned.")

def monitor_files(interval=10, user_id=None):
    """Dosyaları düzenli aralıklarla kontrol eder ve hile tespit edilirse kullanıcıyı yasaklar."""
    while True:
        if not check_integrity() and user_id is not None:
            ban_user(user_id)
            logging.warning(f"Potential cheating detected for user {user_id}!")
            print("Potential cheating detected!")
        time.sleep(interval)

def start_monitoring(user_id, interval=10):
    """Dosya izleme iş parçacığını başlatır."""
    monitoring_thread = threading.Thread(target=monitor_files, args=(interval, user_id))
    monitoring_thread.daemon = True  # Ana işlem sona erse bile izleme işlemi devam eder
    monitoring_thread.start()

if __name__ == "__main__":
    user_id_to_monitor = "user123"  # Bu, izlenecek kullanıcının kimliğidir
    start_monitoring(user_id=user_id_to_monitor)

    # Ana program çalışmaya devam edebilir, diğer işlemler buraya eklenebilir.
    while True:
        time.sleep(60)  # Ana işlem boşta kalabilir, başka işler yapılabilir.
