"""
Главный файл для запуска инструмента анализа логов безопасности
Предоставляет выбор между консольным и графическим режимом
"""

import sys
import os
from console_app import start_console

def clear_screen():
    """Очистка экрана консоли"""
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    clear_screen()
    
    print("=" * 60)
    print("   ИНСТРУМЕНТ АНАЛИЗА ЛОГОВ БЕЗОПАСНОСТИ")
    print("=" * 60)
    print("\nВыберите режим работы:")
    print("1. Консольный режим")
    print("2. Выход")
    
    while True:
        choice = input("\nВаш выбор (1-2): ").strip()

        if choice == "1":
            print("\nЗапуск консольного режима...")
            start_console()
            break
            
        elif choice == "2":
            print("\nВыход из программы.")
            sys.exit(0)
            
        else:
            print("Неверный выбор. Пожалуйста, введите 1 или 2.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nПрограмма прервана пользователем.")
        sys.exit(0)
    except Exception as e:
        print(f"\nОшибка при запуске: {e}")
        sys.exit(1)