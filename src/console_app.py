"""
Консольное приложение анализатора логов
"""

import os
import sqlite3
from datetime import datetime

from log_analyzer import SecurityLogTool
from database import DatabaseManager

def clear_screen():
    """Очистка экрана консоли"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Вывод заголовка"""
    clear_screen()
    print("=" * 70)
    print("        КОНСОЛЬНЫЙ АНАЛИЗАТОР ЛОГОВ БЕЗОПАСНОСТИ")
    print("=" * 70)
    print()

def show_menu():
    """Отображение главного меню"""
    print("\nГЛАВНОЕ МЕНЮ:")
    print("1. Анализировать файл логов")
    print("2. Показать последние оповещения")
    print("3. Показать статистику")
    print("4. Проверить базу данных")
    print("5. Экспорт алертов в JSON")
    print("6. Очистка старых данных")
    print("7. Резервное копирование БД")
    print("0. Выход")

def analyze_file(tool):
    """Обработка файла логов"""
    print("\n--- АНАЛИЗ ФАЙЛА ЛОГОВ ---")
    
    filepath = input("Введите путь к файлу логов: ").strip()
    if not os.path.exists(filepath):
        print("Ошибка: файл не найден!")
        return
    
    print("\nВыберите формат логов:")
    print("1. Автоопределение")
    print("2. Nginx/Apache")
    print("3. JSON")
    print("4. Syslog")
    
    format_map = {'1': 'auto', '2': 'nginx', '3': 'json', '4': 'syslog'}
    while True:
        choice = input("Ваш выбор (1-4): ").strip()
        if choice in format_map:
            log_format = format_map[choice]
            break
        print("Неверный выбор!")
    
    print(f"\nНачата обработка файла...")
    
    success = tool.process_file(filepath, log_format)
    
    if success:
        print("✓ Обработка завершена успешно!")
        
        # Получаем статистику
        stats = tool.get_statistics()
        alerts_count = len(tool.analyzer.alerts)
        
        print(f"\n СТАТИСТИКА:")
        print(f"  Обработано записей: {stats['processed']}")
        print(f"  Обнаружено алертов: {alerts_count}")
        print(f"  Сохранено в БД: {stats['db_saved']}")
        
        # Типы алертов
        if alerts_count > 0:
            alert_types = {}
            for alert in tool.analyzer.alerts:
                rule_type = alert.get('rule', 'unknown')
                alert_types[rule_type] = alert_types.get(rule_type, 0) + 1
            
            print(f"\n ТИПЫ ОБНАРУЖЕННЫХ УГРОЗ:")
            for rule_type, count in alert_types.items():
                print(f"  {rule_type}: {count}")
            
            # Предложить показать алерты
            show = input("\nПоказать обнаруженные алерты? (y/n): ").lower()
            if show == 'y':
                tool.print_alerts()
    else:
        print("✗ Ошибка при обработке файла!")

def check_database(tool):
    """Проверка соединения с базой данных"""
    print("\n--- ПРОВЕРКА БАЗЫ ДАННЫХ ---")
    
    try:
        # Проверяем существование файла БД
        db_path = tool.config_loader.get_database_config()["path"]
        
        print(f"Путь к БД: {db_path}")
        print(f"Файл существует: {'✓' if os.path.exists(db_path) else '✗'}")
        
        if os.path.exists(db_path):
            size = os.path.getsize(db_path)
            print(f"Размер файла: {size:,} байт ({size/1024:.1f} КБ)")
        
        # Пытаемся подключиться к БД
        print("\nПопытка подключения к БД...")
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            print(f"Найдено таблиц: {len(tables)}")
            for table in tables:
                print(f"  - {table[0]}")
            
            # Проверяем количество записей в таблицах
            for table_name in ['logs', 'alerts']:
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                count = cursor.fetchone()[0]
                print(f"  Записей в '{table_name}': {count:,}")
            
            conn.close()
            print("\n✓ Подключение к БД успешно")
            
        except sqlite3.Error as e:
            print(f"✗ Ошибка SQLite: {e}")
            
    except Exception as e:
        print(f"✗ Общая ошибка: {e}")

def show_recent_alerts(tool):
    """Показать последние оповещения"""
    print("\n--- ПОСЛЕДНИЕ ОПОВЕЩЕНИЯ ---")
    
    alerts = tool.analyzer.alerts
    
    if not alerts:
        print("Нет оповещений в текущей сессии.")
        return
    
    print(f"Оповещений в текущей сессии: {len(alerts)}")
    print("-" * 50)
    
    for i, alert in enumerate(alerts[:10], 1):  
        print(f"{i}. [{alert.get('severity', 'UNKNOWN')}] {alert.get('rule', 'unknown')}")
        print(f"   Время: {alert.get('timestamp', 'unknown')}")
        print(f"   Источник: {alert.get('source_ip', 'unknown')}")
        print(f"   Описание: {alert.get('description', '')}")
        print()

def show_statistics(tool):
    """Показать статистику"""
    print("\n--- СТАТИСТИКА ---")
    
    try:
        # Статистика из анализатора (память)
        stats = tool.analyzer.stats
        print(f"\n СТАТИСТИКА ОБРАБОТКИ:")
        print(f"  Всего обработано записей: {stats.get('total_entries', 0):,}")
        print(f"  Обнаружено алертов: {stats.get('alerts_generated', 0):,}")
        
        # Статистика по типам алертов из памяти
        alert_counts = {}
        for key, value in stats.items():
            if key.endswith('_count'):
                rule_name = key.replace('_count', '')
                alert_counts[rule_name] = value
        
        if alert_counts:
            print(f"\n АЛЕРТЫ ПО ТИПАМ (память):")
            for rule_name, count in alert_counts.items():
                print(f"  {rule_name}: {count:,}")
        
        # Статистика из базы данных
        try:
            print(f"\n СТАТИСТИКА ИЗ БАЗЫ ДАННЫХ:")
            
            if not os.path.exists("logs.db"):
                print(" База данных не найдена.")
                return
            
            db_stats = tool.analyzer.database.get_statistics(days=7)
            
            print(f"  Всего записей логов в БД: {db_stats.get('total_logs', 0):,}")
            print(f"  Всего алертов в БД: {db_stats.get('total_alerts', 0):,}")
            
            # По уровню опасности
            if db_stats.get('alert_stats'):
                print(f"\n  АЛЕРТЫ ПО КРИТИЧНОСТИ:")
                for alert_stat in db_stats['alert_stats']:
                    print(f"    {alert_stat['severity']}: {alert_stat['count']:,}")
            
            if db_stats.get('rule_stats'):
                print(f"\n  АЛЕРТЫ ПО ПРАВИЛАМ:")
                for rule_stat in db_stats['rule_stats']:
                    print(f"    {rule_stat['rule_name']}: {rule_stat['count']:,}")
            
            # Сколько было проанализировано за 7 последних дней
            if db_stats.get('daily_stats'):
                print(f"\n  АКТИВНОСТЬ ЗА ПОСЛЕДНИЕ 7 ДНЕЙ:")
                for day_stat in db_stats['daily_stats'][:7]:  # Показать последние 7 дней
                    print(f"    {day_stat['day']}: {day_stat['log_count']:,} логов")
            
            print(f"\n  ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ:")
            
            # Размер файла БД
            if os.path.exists("logs.db"):
                size = os.path.getsize("logs.db")
                if size < 1024:
                    size_str = f"{size} Б"
                elif size < 1024 * 1024:
                    size_str = f"{size/1024:.1f} КБ"
                else:
                    size_str = f"{size/(1024*1024):.1f} МБ"
                print(f"    Размер файла БД: {size_str}")
            
            # Количество бэкапов бд
            backups_dir = "backups/"
            if os.path.exists(backups_dir):
                backup_files = [f for f in os.listdir(backups_dir) if f.endswith('.db')]
                print(f"    Резервных копий: {len(backup_files)}")
            
        except Exception as db_e:
            print(f"\n✗ Не удалось получить статистику из БД: {db_e}")
            print("\n  Попробуйте перезапустить программу.")
            
    except Exception as e:
        print(f"\n Ошибка при получении статистики: {e}")
        import traceback
        traceback.print_exc()

def export_alerts(tool):
    """Экспорт алертов в JSON"""
    print("\n--- ЭКСПОРТ АЛЕРТОВ ---")
    
    # Создаем название если таковое не будет указано
    default_file = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_file = input(f"Имя файла [{default_file}]: ").strip()
    
    if not output_file:
        output_file = default_file
    
    try:
        DatabaseManager.export_alerts_to_json(output_file)
    except Exception as e:
        print(f"✗ Ошибка экспорта: {e}") 

def start_console():
    """Запуск консольного приложения"""
    print_header()
    
    print("Инициализация системы...")
    try:
        tool = SecurityLogTool()
        print("✓ Система готова к работе")
    except Exception as e:
        print(f"✗ Ошибка инициализации: {e}")
        input("\nНажмите Enter для выхода...")
        return
    
    while True:
        show_menu()
        
        try:
            choice = input("\nВаш выбор (0-6): ").strip()
            if choice == "1":
                analyze_file(tool)
            elif choice == "2":
                show_recent_alerts(tool)
            elif choice == "3":
                show_statistics(tool)
            elif choice == "4":
                check_database(tool)
            elif choice == "5":
                DatabaseManager.export_alerts_to_json(tool)
            elif choice == "6":
                tool.analyzer.database.backup_database()
            elif choice == "0":
                print("\nВыход из программы...")
                break
            
            input("\nНажмите Enter для продолжения...")
            print_header()
            
        except KeyboardInterrupt:
            print("\n\nПрограмма прервана.")
            break
        except Exception as e:
            print(f"\nОшибка: {e}")
            input("\nНажмите Enter для продолжения...")



if __name__ == "__main__":
    start_console()