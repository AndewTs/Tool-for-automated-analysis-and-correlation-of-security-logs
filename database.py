"""
Модуль для работы с базой данных SQLite
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)

@dataclass
class LogEntry:
    """Структура записи лога"""
    id: int = None
    timestamp: str = ""
    source_ip: str = ""
    log_type: str = ""
    raw_log: str = ""
    parsed_data: str = ""
    created_at: str = ""

@dataclass
class Alert:
    """Структура оповещения"""
    id: int = None
    timestamp: str = ""
    rule_name: str = ""
    severity: str = ""
    source_ip: str = ""
    description: str = ""
    log_data: str = ""
    created_at: str = ""

class DatabaseManager:
    """Менеджер базы данных SQLite"""
    
    def __init__(self, db_path: str = "logs.db"):
        self.db_path = db_path
        self._init_database()
        logger.info(f"База данных инициализирована: {db_path}")
    
    def _init_database(self):
        """Инициализация структуры базы данных"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Таблица логов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                log_type TEXT,
                raw_log TEXT NOT NULL,
                parsed_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица оповещений
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                description TEXT,
                log_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Индексы для ускорения поиска
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        
        conn.commit()
        conn.close()
    
    def _get_connection(self):
        """Получение соединения с базой данных"""
        return sqlite3.connect(self.db_path)
    
    def save_log_entry(self, log_entry: LogEntry) -> int:
        """Сохранение записи лога в базу данных"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO logs (timestamp, source_ip, log_type, raw_log, parsed_data)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            log_entry.timestamp,
            log_entry.source_ip,
            log_entry.log_type,
            log_entry.raw_log,
            log_entry.parsed_data
        ))
        
        log_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.debug(f"Сохранена запись лога с ID: {log_id}")
        return log_id
    
    def save_alert(self, alert: Alert) -> int:
        """Сохранение оповещения в базу данных"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, rule_name, severity, source_ip, description, log_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert.timestamp,
            alert.rule_name,
            alert.severity,
            alert.source_ip,
            alert.description,
            alert.log_data
        ))
        
        alert_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"Сохранено оповещение: {alert.rule_name} (ID: {alert_id})")
        return alert_id
    
    def get_recent_logs(self, limit: int = 100) -> List[LogEntry]:
        """Получение последних записей логов"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, source_ip, log_type, raw_log, parsed_data, created_at
            FROM logs
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            LogEntry(
                id=row[0],
                timestamp=row[1],
                source_ip=row[2],
                log_type=row[3],
                raw_log=row[4],
                parsed_data=row[5],
                created_at=row[6]
            )
            for row in rows
        ]
    
    def get_recent_alerts(self, limit: int = 50) -> List[Alert]:
        """Получение последних оповещений"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, rule_name, severity, source_ip, description, log_data, created_at
            FROM alerts
            ORDER BY created_at DESC
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            Alert(
                id=row[0],
                timestamp=row[1],
                rule_name=row[2],
                severity=row[3],
                source_ip=row[4],
                description=row[5],
                log_data=row[6],
                created_at=row[7]
            )
            for row in rows
        ]
    
    def get_alerts_by_severity(self, severity: str) -> List[Alert]:
        """Получение оповещений по уровню критичности"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, timestamp, rule_name, severity, source_ip, description, log_data, created_at
            FROM alerts
            WHERE severity = ?
            ORDER BY created_at DESC
        ''', (severity,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            Alert(
                id=row[0],
                timestamp=row[1],
                rule_name=row[2],
                severity=row[3],
                source_ip=row[4],
                description=row[5],
                log_data=row[6],
                created_at=row[7]
            )
            for row in rows
        ]
    
    def get_statistics(self, days: int = 7) -> Dict[str, Any]:
        """Получение статистики за указанный период"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Общая статистика
            cursor.execute('SELECT COUNT(*) FROM logs')
            total_logs = cursor.fetchone()[0] or 0
            
            cursor.execute('SELECT COUNT(*) FROM alerts')
            total_alerts = cursor.fetchone()[0] or 0
            
            # Статистика по дням
            try:
                cursor.execute('''
                    SELECT 
                        date(created_at) as day,
                        COUNT(*) as log_count
                    FROM logs
                    WHERE date(created_at) >= date('now', ?)
                    GROUP BY day
                    ORDER BY day DESC
                ''', (f'-{days} days',))
                
                daily_stats = cursor.fetchall()
            except Exception as e:
                logger.error(f"Ошибка при получении ежедневной статистики: {e}")
                daily_stats = []
            
            # Статистика по алертам
            try:
                cursor.execute('''
                    SELECT 
                        severity,
                        COUNT(*) as count
                    FROM alerts
                    GROUP BY severity
                ''')
                
                alert_stats = cursor.fetchall()
            except Exception as e:
                logger.error(f"Ошибка при получении статистики алертов: {e}")
                alert_stats = []
            
            # Получаем алерты по типам (правилам)
            try:
                cursor.execute('''
                    SELECT 
                        rule_name,
                        COUNT(*) as count
                    FROM alerts
                    GROUP BY rule_name
                ''')
                
                rule_stats = cursor.fetchall()
            except Exception as e:
                logger.error(f"Ошибка при получении статистики по правилам: {e}")
                rule_stats = []
            
            conn.close()
            
            return {
                'total_logs': total_logs,
                'total_alerts': total_alerts,
                'daily_stats': [
                    {'day': row[0], 'log_count': row[1]}
                    for row in daily_stats
                ],
                'alert_stats': [
                    {'severity': row[0], 'count': row[1]}
                    for row in alert_stats
                ],
                'rule_stats': [
                    {'rule_name': row[0], 'count': row[1]}
                    for row in rule_stats
                ]
            }
            
        except Exception as e:
            logger.error(f"Критическая ошибка при получении статистики: {e}")
            conn.close()
            return {
                'total_logs': 0,
                'total_alerts': 0,
                'daily_stats': [],
                'alert_stats': [],
                'rule_stats': []
            }
    
    def backup_database(self, backup_path: str = "backups/"):
        """Создание резервной копии базы данных"""
        try:
            import shutil
            import time
            
            if not os.path.exists(backup_path):
                os.makedirs(backup_path)
            
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(backup_path, f"logs_backup_{timestamp}.db")
            
            shutil.copy2(self.db_path, backup_file)
            logger.info(f"Создана резервная копия: {backup_file}")
            
            return backup_file
        except Exception as e:
            logger.error(f"Ошибка при создании резервной копии: {e}")
            return None
    
    def export_alerts_to_json(self, output_file: str) -> bool:
        """Экспорт алертов в JSON файл"""
        try:
            alerts = self.get_recent_alerts(limit=1000)
            
            data = {
                'export_date': datetime.now().isoformat(),
                'total_alerts': len(alerts),
                'alerts': [asdict(alert) for alert in alerts]
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Алерты экспортированы в {output_file}")
            return True
        except Exception as e:
            logger.error(f"Ошибка при экспорте: {e}")
            return False