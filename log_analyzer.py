"""
Модуль анализа логов
"""

import re
import json
import logging
import os
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
from typing import Dict, Any, Optional

from database import DatabaseManager, LogEntry, Alert

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_tool.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ConfigLoader:
    """Загрузчик конфигурации из JSON файла"""
    
    def __init__(self, config_path: str = None):
        if config_path is None:
            self.config_path = self._find_config_file()
        else:
            self.config_path = config_path
        
        logger.info(f"Пытаемся загрузить конфиг из: {self.config_path}")
        
        if os.path.exists(self.config_path):
            logger.info(f"Файл конфигурации найден: {self.config_path}")
        else:
            logger.warning(f"Файл конфигурации не найден: {self.config_path}")
        
        self.config = self._load_config()
    
    def _find_config_file(self):
        """Поиск config.json в разных местах"""
        possible_paths = [
            "config.json",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"),
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                logger.info(f"Найден конфиг: {path}")
                return path
        
        return "config.json"
    
    def _load_config(self) -> Dict[str, Any]:
        """Загрузка конфигурации из файла"""
        try:
            if not os.path.exists(self.config_path):
                return self._get_default_config()
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            logger.info("Конфигурация успешно загружена")
            return config
                
        except Exception as e:
            logger.error(f"Ошибка загрузки конфига: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Конфигурация по умолчанию"""
        return {
            "rules": {
                "bruteforce": {
                    "pattern": r"(?:Failed password|Invalid user|authentication failure|Login failed|FAILED LOGIN)",
                    "window": 300,
                    "threshold": 5,
                    "description": "Множественные неудачные попытки аутентификации",
                    "severity": "high",
                    "enabled": True
                },
                "sqli_attempt": {
                    "pattern": r"(?:union.*select|' or '1'='1|sleep\(|benchmark\(|-- |/\*.*\*/|exec\(|SELECT.*FROM|DROP TABLE|INSERT INTO)",
                    "case_sensitive": False,
                    "description": "Попытка SQL-инъекции",
                    "severity": "high",
                    "enabled": True
                },
                "xss_attempt": {
                    "pattern": r"(?:<script>|javascript:|onload=|onerror=|alert\(|document\.location|eval\(|fromCharCode)",
                    "case_sensitive": False,
                    "description": "Попытка XSS-атаки",
                    "severity": "high",
                    "enabled": True
                },
                "port_scan": {
                    "pattern": r"(?:Connection reset by peer|Invalid connection|Bad request|Port scan|drop:|DROP|DPT=.*SRC=|SRC=.*DPT=)",
                    "window": 30,
                    "threshold": 5,
                    "description": "Возможное сканирование портов",
                    "severity": "high",
                    "enabled": True
                },
                "firewall_block": {
                    "pattern": r"(?:drop:|DROP|blocked|Blocked)",
                    "window": 60,
                    "threshold": 3,
                    "description": "Множественные блокировки firewall",
                    "severity": "medium",
                    "enabled": True
                }
            }
        }
    
    def get_rules(self) -> Dict[str, Dict]:
        """Получение правил анализа"""
        return self.config.get("rules", {})
    
    def get_database_config(self) -> Dict[str, Any]:
        """Получение конфигурации базы данных"""
        return self.config.get("database", {"path": "logs.db"})

class LogParser:
    """Парсер для различных форматов логов"""
    
    def __init__(self):
        pass
    
    def should_skip_line(self, line: str) -> bool:
        """Проверка на комментарий"""
        line = line.strip()
        if not line or line.startswith('#'):
            return True
        return False
    
    def parse_nginx(self, line: str) -> Optional[Dict[str, Any]]:
        """Парсинг логов Nginx/Apache"""
        line = line.strip()
        
        if self.should_skip_line(line):
            return None
        
        pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>.*?)\].*?"(?P<method>\w+) (?P<url>.*?) HTTP/\d\.\d".*?(?P<status>\d{3})'
        match = re.match(pattern, line)
        
        if match:
            return {
                'type': 'web',
                'ip': match.group('ip'),
                'timestamp': match.group('timestamp'),
                'method': match.group('method'),
                'url': match.group('url'),
                'status': int(match.group('status')),
                'raw': line
            }
        return None
    
    def parse_json(self, line: str) -> Optional[Dict[str, Any]]:
        """Парсинг JSON-логов"""
        line = line.strip()
        
        if self.should_skip_line(line):
            return None
        
        try:
            data = json.loads(line)
            result = {
                'type': 'json',
                'raw': line,
                'data': data
            }
            
            if 'ip' in data:
                result['ip'] = data['ip']
            elif 'message' in data:
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', data['message'])
                if ip_match:
                    result['ip'] = ip_match.group(0)
            
            if 'timestamp' in data:
                result['timestamp'] = data['timestamp']
            
            return result
        except json.JSONDecodeError:
            return None
    
    def parse_syslog(self, line: str) -> Optional[Dict[str, Any]]:
        """Парсинг Syslog формата"""
        line = line.strip()
        
        if self.should_skip_line(line):
            return None
        
        # Паттерны для разных форматов syslog
        patterns = [
            # Формат: timestamp host program: message
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>\S+):\s+(?P<message>.*)',
            # Формат: timestamp host program[pid]: message
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>\S+)\[(?P<pid>\d+)\]:\s+(?P<message>.*)',
            # Формат: timestamp host program message
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>\S+)\s+(?P<message>.*)',
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                result = {
                    'type': 'syslog',
                    'timestamp': match.group('timestamp'),
                    'host': match.group('host'),
                    'program': match.group('program'),
                    'message': match.group('message'),
                    'raw': line
                }
                
                # Извлекаем дополнительные данные
                self._extract_additional_info(result, line)
                return result
        
        return None
    
    def parse_iptables(self, line: str) -> Optional[Dict[str, Any]]:
        """Парсер для iptables/firewall логов"""
        line = line.strip()
        
        if self.should_skip_line(line):
            return None
        
        is_firewall_log = ('SRC=' in line or 'DPT=' in line or 
                          'drop:' in line.lower() or 'DROP' in line)
        
        if not is_firewall_log:
            return None
        
        # Ищем timestamp
        timestamp = 'unknown'
        timestamp_patterns = [
            r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                timestamp = match.group(0)
                break
        
        result = {
            'type': 'firewall',
            'timestamp': timestamp,
            'message': line,
            'raw': line
        }
        
        # Извлекаем дополнительные данные
        self._extract_additional_info(result, line)
        return result
    
    def _extract_additional_info(self, result: Dict[str, Any], line: str):
        """Извлечение дополнительной информации из строки лога"""
        # IP адрес
        ip_match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            result['ip'] = ip_match.group(1)
        else:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                result['ip'] = ip_match.group(1)
        
        # Порт
        port_match = re.search(r'DPT=(\d+)', line)
        if port_match:
            result['port'] = int(port_match.group(1))
        
        # Действие
        if 'drop:' in line.lower() or 'DROP' in line:
            result['action'] = 'DROP'
            result['event_type'] = 'blocked'
        
        # Протокол
        if 'PROTO=TCP' in line:
            result['protocol'] = 'TCP'
        elif 'PROTO=UDP' in line:
            result['protocol'] = 'UDP'
    
    def parse_generic(self, line: str) -> Dict[str, Any]:
        """Парсинг любого лога как текста"""
        line = line.strip()
        
        if self.should_skip_line(line):
            return None
        
        # Ищем IP
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
        if ip_match:
            ip = ip_match.group(0)
        else:
            ip = 'unknown'
        
        # Ищем timestamp
        timestamp = 'unknown'
        timestamp_patterns = [
            r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                timestamp = match.group(0)
                break
        
        result = {
            'type': 'generic',
            'ip': ip,
            'timestamp': timestamp,
            'message': line,
            'raw': line
        }
        
        # Извлекаем дополнительные данные
        self._extract_additional_info(result, line)
        return result

class LogAnalyzer:
    """Анализатор логов с поддержкой базы данных"""
    
    def __init__(self, config_path: str = "config.json"): 
        self.config_loader = ConfigLoader(config_path)
        self.rules = self.config_loader.get_rules()
        db_config = self.config_loader.get_database_config()
        self.database = DatabaseManager(db_config["path"])
        
        self.events = []
        self.alerts = []
        self.stats = defaultdict(int)
        self.time_series = defaultdict(list)
        
        logger.info(f"Инициализирован анализатор с {len(self.rules)} правилами")
    
    def add_log_entry(self, entry: Dict[str, Any]):
        """Добавление и анализ записи лога"""
        if not entry:
            return
        
        self.events.append(entry)
        self.stats['total_entries'] += 1
        
        # Сохранение в базу данных
        log_entry = LogEntry(
            timestamp=entry.get('timestamp', str(datetime.now())),
            source_ip=entry.get('ip', 'unknown'),
            log_type=entry.get('type', 'unknown'),
            raw_log=entry.get('raw', ''),
            parsed_data=json.dumps(entry, ensure_ascii=False)
        )
        
        try:
            self.database.save_log_entry(log_entry)
            self.stats['db_saved'] = self.stats.get('db_saved', 0) + 1
        except Exception as e:
            logger.error(f"Ошибка сохранения в БД: {e}")
        
        # Проверка правил
        for rule_name, rule in self.rules.items():
            if not rule.get('enabled', True):
                continue
            
            if self._check_rule(entry, rule):
                self._process_rule_match(entry, rule_name, rule)
    
    def _check_rule(self, entry: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Проверка записи на соответствие правилу"""
        search_text = entry.get('message', '') or entry.get('raw', '')
        
        if 'url' in entry:
            search_text += ' ' + entry['url']
        
        pattern = rule['pattern']
        case_sensitive = rule.get('case_sensitive', True)
        
        if not case_sensitive:
            return bool(re.search(pattern, search_text, re.IGNORECASE))
        return bool(re.search(pattern, search_text))
    
    def _process_rule_match(self, entry: Dict[str, Any], rule_name: str, rule: Dict[str, Any]):
        """Обработка совпадения с правилом"""
        ip = entry.get('ip', 'unknown')
        
        # Для правил с временной корреляцией
        if 'window' in rule and 'threshold' in rule:
            key = (rule_name, ip)
            
            self.time_series[key].append({
                'timestamp': datetime.now(),
                'entry': entry
            })
            
            window = timedelta(seconds=rule['window'])
            cutoff_time = datetime.now() - window
            
            self.time_series[key] = [
                item for item in self.time_series[key]
                if item['timestamp'] > cutoff_time
            ]
            
            # Проверка порога
            if len(self.time_series[key]) >= rule['threshold']:
                self._create_alert(entry, rule_name, rule, len(self.time_series[key]))
        else:
            self._create_alert(entry, rule_name, rule)
    
    def _create_alert(self, entry: Dict[str, Any], rule_name: str, rule: Dict[str, Any], count: int = 1):
        """Создание и сохранение оповещения"""
        severity = rule.get('severity', 'medium').upper()
        
        alert_dict = {
            'timestamp': datetime.now().isoformat(),
            'rule': rule_name,
            'description': rule['description'],
            'severity': severity,
            'source_ip': entry.get('ip', 'unknown'),
            'details': {
                'log_entry': entry.get('raw', str(entry)),
                'match_count': count,
                'log_type': entry.get('type', 'unknown')
            }
        }
        
        self.alerts.append(alert_dict)
        self.stats['alerts_generated'] += 1
        self.stats[f'{rule_name}_count'] = self.stats.get(f'{rule_name}_count', 0) + 1
        
        # Сохранение в базу данных
        alert = Alert(
            timestamp=alert_dict['timestamp'],
            rule_name=alert_dict['rule'],
            severity=alert_dict['severity'],
            source_ip=alert_dict['source_ip'],
            description=alert_dict['description'],
            log_data=json.dumps(alert_dict['details'], ensure_ascii=False)
        )
        
        try:
            self.database.save_alert(alert)
        except Exception as e:
            logger.error(f"Ошибка сохранения алерта в БД: {e}")
        
    def backup_database(self, backup_path: str = "backups/"):
        """Создание резервной копии БД"""
        return self.database.backup_database(backup_path)
    
    def clear_old_data(self, days_to_keep: int = 30):
        """Очистка старых данных из БД"""
        return self.database.clear_old_data(days_to_keep)

class SecurityLogTool:
    """Основной класс инструмента"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config_loader = ConfigLoader(config_path)
        self.parser = LogParser()
        self.analyzer = LogAnalyzer(config_path)
        logger.info("Инструмент анализа логов инициализирован")
    
    def process_file(self, filepath: str, log_format: str = 'auto'):
        """Обработка файла с логами"""
        path = Path(filepath)
        
        if not path.exists():
            logger.error(f"Файл {filepath} не найден")
            return False
        
        logger.info(f"Начата обработка файла: {filepath}")
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = 0
                
                for line in f:
                    line_count += 1
                    
                    # Парсинг строки
                    entry = self._parse_line(line, log_format)
                    
                    # Анализ записи
                    if entry:
                        self.analyzer.add_log_entry(entry)
                    
                    if line_count % 100 == 0:
                        logger.info(f"Обработано строк: {line_count}")
                
                logger.info(f"Обработка завершена. Всего строк: {line_count}")
                return True
                
        except Exception as e:
            logger.error(f"Ошибка при обработке файла: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def _parse_line(self, line: str, log_format: str) -> Optional[Dict[str, Any]]:
        """Определение формата и парсинг строки"""
        # Пропускаем пустые строки и комментарии
        if self.parser.should_skip_line(line):
            return None
        
        entry = None
        
        if log_format == 'auto':
            # Пробуем все форматы по порядку
            
            # 1. Сначала firewall/iptables логи
            if 'SRC=' in line or 'DPT=' in line or 'drop:' in line.lower():
                entry = self.parser.parse_iptables(line)
            
            # 2. Пробуем JSON
            if not entry and line.strip().startswith('{'):
                entry = self.parser.parse_json(line)
            
            # 3. Пробуем Nginx
            if not entry and re.search(r'\d+\.\d+\.\d+\.\d+.*\[.*\]', line):
                entry = self.parser.parse_nginx(line)
            
            # 4. Пробуем Syslog
            if not entry and re.search(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line):
                entry = self.parser.parse_syslog(line)
            
            # 5. Если ничего не сработало - generic
            if not entry:
                entry = self.parser.parse_generic(line)
        else:
            # Использовать указанный формат
            if log_format == 'json':
                entry = self.parser.parse_json(line)
            elif log_format == 'nginx':
                entry = self.parser.parse_nginx(line)
            elif log_format == 'syslog':
                entry = self.parser.parse_syslog(line)
            else:
                entry = self.parser.parse_generic(line)
        
        return entry
    
    def print_alerts(self, max_alerts: int = 20):
        """Вывод оповещений в консоль"""
        alerts = self.analyzer.alerts
        
        if not alerts:
            print("Оповещений не обнаружено.")
            return
        
        print(f"\n{'='*70}")
        print(f"ОПОВЕЩЕНИЯ БЕЗОПАСНОСТИ ({len(alerts)})")
        print('='*70)
        
        for i, alert in enumerate(alerts[:max_alerts], 1):
            print(f"\n{i}. [{alert['severity']}] {alert['rule']}")
            print(f"   Время: {alert['timestamp']}")
            print(f"   IP-адрес: {alert['source_ip']}")
            print(f"   Описание: {alert['description']}")
            
            if 'details' in alert and 'log_entry' in alert['details']:
                log_preview = alert['details']['log_entry'][:150]
                if len(alert['details']['log_entry']) > 150:
                    log_preview += "..."
                print(f"   Фрагмент лога: {log_preview}")
    
    def get_statistics(self):
        """Получение статистики"""
        return {
            'processed': self.analyzer.stats.get('total_entries', 0),
            'alerts': len(self.analyzer.alerts),
            'db_saved': self.analyzer.stats.get('db_saved', 0)
        }