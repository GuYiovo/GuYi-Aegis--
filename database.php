<?php
// database.php - 核心数据库类 (修复外键约束问题)
require_once 'config.php';

if (!class_exists('Database')) {
    
    class Database {
        public $pdo;
        
        public function __construct() {
            try {
                $db_dir = dirname(DB_PATH);
                if (!is_dir($db_dir)) {
                    mkdir($db_dir, 0755, true);
                }
                
                $this->pdo = new PDO('sqlite:' . DB_PATH);
                $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                
                // [修复] 关闭外键强约束，允许 app_id=0 (通用卡) 存在
                // $this->pdo->exec("PRAGMA foreign_keys = ON;"); 
                
                // 初始化表结构
                $this->createTables();
                $this->migrateForMultiTenant();
                
            } catch (PDOException $e) {
                error_log('DB Error: ' . $e->getMessage());
                die('System Maintenance: Database connection failed.');
            }
        }
        
        private function createTables() {
            // 应用表
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name VARCHAR(100) NOT NULL UNIQUE,
                app_key VARCHAR(64) NOT NULL UNIQUE,
                status INTEGER DEFAULT 1,
                create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            )");

            // 卡密表
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS cards (id INTEGER PRIMARY KEY AUTOINCREMENT, card_code VARCHAR(50) UNIQUE NOT NULL, card_type VARCHAR(20) NOT NULL, status INTEGER DEFAULT 0, device_hash VARCHAR(100), used_time DATETIME, expire_time DATETIME, create_time DATETIME DEFAULT CURRENT_TIMESTAMP, notes TEXT)");
            
            // 日志与设备表
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS usage_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, card_code VARCHAR(50) NOT NULL, card_type VARCHAR(20) NOT NULL, device_hash VARCHAR(100) NOT NULL, ip_address VARCHAR(45), user_agent TEXT, access_time DATETIME DEFAULT CURRENT_TIMESTAMP, result VARCHAR(100))");
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS active_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, device_hash VARCHAR(100) NOT NULL, card_code VARCHAR(50) UNIQUE NOT NULL, card_type VARCHAR(20) NOT NULL, activate_time DATETIME DEFAULT CURRENT_TIMESTAMP, expire_time DATETIME NOT NULL, status INTEGER DEFAULT 1)");
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL)");
            
            // 初始化管理员
            if ($this->pdo->query("SELECT COUNT(*) FROM admin")->fetchColumn() == 0) {
                $this->pdo->prepare("INSERT INTO admin (id, username, password_hash) VALUES (1, 'admin', ?)")->execute([password_hash('admin123', PASSWORD_DEFAULT)]);
            }
        }

        private function ensureColumnExists($table, $column, $definition) {
            try {
                $res = $this->pdo->query("PRAGMA table_info($table)")->fetchAll(PDO::FETCH_ASSOC);
                $cols = array_column($res, 'name');
                if (!in_array($column, $cols)) {
                    $this->pdo->exec("ALTER TABLE $table ADD COLUMN $column $definition");
                }
            } catch (Exception $e) { }
        }

        private function migrateForMultiTenant() {
            // [修复] 移除 REFERENCES 约束，防止因 app_id=0 导致的报错
            $this->ensureColumnExists('cards', 'app_id', 'INTEGER DEFAULT 0');
            $this->pdo->exec("CREATE INDEX IF NOT EXISTS idx_cards_app_id ON cards (app_id)");
            
            $this->ensureColumnExists('usage_logs', 'app_name', "VARCHAR(100) DEFAULT 'System'");
            $this->ensureColumnExists('active_devices', 'app_id', 'INTEGER DEFAULT 0');
        }

        // --- 应用管理 ---
        public function createApp($name, $notes = '') {
            $appKey = bin2hex(random_bytes(32));
            $stmt = $this->pdo->prepare("INSERT INTO applications (app_name, app_key, notes) VALUES (?, ?, ?)");
            $stmt->execute([$name, $appKey, $notes]);
            return $appKey;
        }

        public function getApps() {
            // 包含 ID=0 的虚拟行，用于前端显示
            $apps = $this->pdo->query("SELECT *, (SELECT COUNT(*) FROM cards WHERE cards.app_id = applications.id) as card_count FROM applications ORDER BY create_time DESC")->fetchAll(PDO::FETCH_ASSOC);
            
            // 统计通用卡 (ID=0)
            $generalCount = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE app_id = 0")->fetchColumn();
            
            // 手动在数组头部添加“通用/未分类”
            array_unshift($apps, [
                'id' => 0,
                'app_name' => '通用/未分类',
                'app_key' => '-',
                'status' => 1,
                'card_count' => $generalCount,
                'notes' => '系统默认卡池'
            ]);
            
            return $apps;
        }

        public function toggleAppStatus($id) {
            if ($id == 0) return; // 不允许禁用通用池
            $this->pdo->prepare("UPDATE applications SET status = CASE WHEN status = 1 THEN 0 ELSE 1 END WHERE id = ?")->execute([$id]);
        }

        public function deleteApp($id) {
            if ($id == 0) throw new Exception("无法删除系统默认应用");
            $count = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE app_id = $id")->fetchColumn();
            if ($count > 0) throw new Exception("无法删除：该应用下仍有 {$count} 张卡密。");
            $this->pdo->prepare("DELETE FROM applications WHERE id = ?")->execute([$id]);
        }

        // --- 核心验证 ---
        public function verifyCard($cardCode, $deviceHash, $appKey = null) {
            $this->cleanupExpiredDevices();
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

            $app = null;
            $appNameForLog = 'System'; 
            $appIdStr = " = 0"; 

            // 如果传了 AppKey，进行应用鉴权
            if ($appKey) {
                $appStmt = $this->pdo->prepare("SELECT id, app_name, status FROM applications WHERE app_key = ?");
                $appStmt->execute([$appKey]);
                $app = $appStmt->fetch(PDO::FETCH_ASSOC);

                if (!$app) {
                    $this->logUsage($cardCode, '-', $deviceHash, $ip, $ua, '鉴权失败: Key无效', 'INVALID');
                    return ['success' => false, 'message' => '应用密钥无效'];
                }
                if ($app['status'] == 0) {
                    $this->logUsage($cardCode, '-', $deviceHash, $ip, $ua, '鉴权失败: 应用禁用', $app['app_name']);
                    return ['success' => false, 'message' => '该应用已被禁用'];
                }
                $appNameForLog = $app['app_name'];
                $appIdStr = " = {$app['id']}";
            }

            // 1. 查在线表
            $deviceStmt = $this->pdo->prepare("SELECT * FROM active_devices WHERE device_hash = ? AND status = 1 AND expire_time > datetime('now') AND app_id {$appIdStr}");
            $deviceStmt->execute([$deviceHash]);
            if ($active = $deviceStmt->fetch(PDO::FETCH_ASSOC)) {
                if ($active['card_code'] === $cardCode) {
                    $this->logUsage($active['card_code'], $active['card_type'], $deviceHash, $ip, $ua, '设备活跃', $appNameForLog);
                    return ['success' => true, 'message' => '设备已激活', 'expire_time' => $active['expire_time']];
                }
            }
            
            // 2. 查卡库
            $card = $this->pdo->prepare("SELECT * FROM cards WHERE card_code = ? AND app_id {$appIdStr}");
            $card->execute([$cardCode]);
            $card = $card->fetch(PDO::FETCH_ASSOC);
            
            if (!$card) {
                // 为了安全，这里不提示是“卡密错”还是“应用错”，统一模糊处理
                $this->logUsage($cardCode, 'Unknown', $deviceHash, $ip, $ua, '无效卡密', $appNameForLog);
                return ['success' => false, 'message' => '无效的卡密代码'];
            }
            
            if ($card['status'] == 1) {
                if (strtotime($card['expire_time']) <= time()) {
                    $this->logUsage($cardCode, $card['card_type'], $deviceHash, $ip, $ua, '验证失败: 已过期', $appNameForLog);
                    return ['success' => false, 'message' => '卡密已过期'];
                }
                $boundDevice = $card['device_hash'];
                if (!empty($boundDevice) && $boundDevice !== $deviceHash) {
                    $this->logUsage($cardCode, $card['card_type'], $deviceHash, $ip, $ua, '验证失败: 设备不符', $appNameForLog);
                    return ['success' => false, 'message' => '卡密已绑定其他设备'];
                }
                // 同步绑定
                if ($boundDevice !== $deviceHash) {
                    $this->pdo->prepare("UPDATE cards SET device_hash=? WHERE id=? AND app_id {$appIdStr}")->execute([$deviceHash, $card['id']]);
                }
                // 写入在线
                $this->pdo->prepare("INSERT OR REPLACE INTO active_devices (device_hash, card_code, card_type, expire_time, status, app_id) VALUES (?, ?, ?, ?, 1, ?)")
                     ->execute([$deviceHash, $cardCode, $card['card_type'], $card['expire_time'], $app ? $app['id'] : 0]);
                
                return ['success' => true, 'message' => '验证通过', 'expire_time' => $card['expire_time']];

            } else {
                // 首次激活
                $duration = CARD_TYPES[$card['card_type']]['duration'] ?? 86400;
                $expireTime = date('Y-m-d H:i:s', time() + $duration);
                try {
                    $this->pdo->beginTransaction();
                    $this->pdo->prepare("UPDATE cards SET status=1, device_hash=?, used_time=datetime('now','localtime'), expire_time=? WHERE id=? AND app_id {$appIdStr}")
                         ->execute([$deviceHash, $expireTime, $card['id']]);
                    $this->pdo->prepare("INSERT INTO active_devices (device_hash, card_code, card_type, expire_time, status, app_id) VALUES (?, ?, ?, ?, 1, ?)")
                         ->execute([$deviceHash, $cardCode, $card['card_type'], $expireTime, $app ? $app['id'] : 0]);
                    $this->logUsage($cardCode, $card['card_type'], $deviceHash, $ip, $ua, '激活成功', $appNameForLog);
                    $this->pdo->commit();
                    return ['success' => true, 'message' => '首次激活成功', 'expire_time' => $expireTime];
                } catch (Exception $e) {
                    if ($this->pdo->inTransaction()) $this->pdo->rollBack();
                    return ['success' => false, 'message' => '激活异常'];
                }
            }
        }

        // --- 批量管理 ---
        public function batchDeleteCards($ids) { if (empty($ids)) return 0; $placeholders = implode(',', array_fill(0, count($ids), '?')); $stmt = $this->pdo->prepare("DELETE FROM cards WHERE id IN ($placeholders)"); $stmt->execute($ids); return $stmt->rowCount(); }
        public function batchUnbindCards($ids) { if (empty($ids)) return 0; $placeholders = implode(',', array_fill(0, count($ids), '?')); $this->pdo->beginTransaction(); try { $stmt = $this->pdo->prepare("SELECT card_code FROM cards WHERE id IN ($placeholders)"); $stmt->execute($ids); $codes = $stmt->fetchAll(PDO::FETCH_COLUMN); if($codes) { $codePlaceholders = implode(',', array_fill(0, count($codes), '?')); $this->pdo->prepare("DELETE FROM active_devices WHERE card_code IN ($codePlaceholders)")->execute($codes); } $this->pdo->prepare("UPDATE cards SET device_hash = NULL WHERE id IN ($placeholders)")->execute($ids); $this->pdo->commit(); return count($ids); } catch (Exception $e) { $this->pdo->rollBack(); return 0; } }
        public function batchAddTime($ids, $hours) { if (empty($ids) || $hours <= 0) return 0; $seconds = intval($hours * 3600); $placeholders = implode(',', array_fill(0, count($ids), '?')); $this->pdo->beginTransaction(); try { $stmt = $this->pdo->prepare("SELECT card_code FROM cards WHERE id IN ($placeholders) AND status = 1"); $stmt->execute($ids); $codes = $stmt->fetchAll(PDO::FETCH_COLUMN); if($codes) { $codePlaceholders = implode(',', array_fill(0, count($codes), '?')); $this->pdo->prepare("UPDATE cards SET expire_time = datetime(expire_time, '+{$seconds} seconds') WHERE id IN ($placeholders) AND status = 1")->execute($ids); $this->pdo->prepare("UPDATE active_devices SET expire_time = datetime(expire_time, '+{$seconds} seconds') WHERE card_code IN ($codePlaceholders)")->execute($codes); } $this->pdo->commit(); return count($codes); } catch (Exception $e) { $this->pdo->rollBack(); return 0; } }
        public function getCardsByIds($ids) { if(empty($ids)) return []; $placeholders = implode(',', array_fill(0, count($ids), '?')); $stmt = $this->pdo->prepare("SELECT * FROM cards WHERE id IN ($placeholders)"); $stmt->execute($ids); return $stmt->fetchAll(PDO::FETCH_ASSOC); }
        public function resetDeviceBindingByCardId($id) { return $this->batchUnbindCards([$id]); }

        // --- 数据展示 ---
        public function getDashboardData() {
            $total = $this->pdo->query("SELECT COUNT(*) FROM cards")->fetchColumn();
            $unused = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE status = 0")->fetchColumn();
            $used = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE status = 1")->fetchColumn();
            $active = $this->pdo->query("SELECT COUNT(*) FROM active_devices WHERE status = 1 AND expire_time > datetime('now')")->fetchColumn();
            
            $types = $this->pdo->query("SELECT card_type, COUNT(*) as count FROM cards GROUP BY card_type")->fetchAll(PDO::FETCH_KEY_PAIR);
            // 修正统计逻辑
            $appStats = $this->pdo->query("SELECT IFNULL(T2.app_name, '通用/未分类') as app_name, COUNT(T1.id) as count FROM cards T1 LEFT JOIN applications T2 ON T1.app_id = T2.id GROUP BY T1.app_id ORDER BY count DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC);

            return ['stats' => ['total' => $total, 'unused' => $unused, 'used' => $used, 'active' => $active], 'chart_types' => $types, 'app_stats' => $appStats];
        }

        public function getAllCards() { return $this->pdo->query("SELECT T1.*, IFNULL(T2.app_name, '通用') as app_name FROM cards T1 LEFT JOIN applications T2 ON T1.app_id = T2.id ORDER BY T1.create_time DESC LIMIT 500")->fetchAll(PDO::FETCH_ASSOC); }
        public function searchCards($k) { $s="%$k%"; $q=$this->pdo->prepare("SELECT T1.*, IFNULL(T2.app_name, '通用') as app_name FROM cards T1 LEFT JOIN applications T2 ON T1.app_id = T2.id WHERE T1.card_code LIKE ? OR T1.notes LIKE ? OR T1.device_hash LIKE ? OR T2.app_name LIKE ?"); $q->execute([$s,$s,$s,$s]); return $q->fetchAll(PDO::FETCH_ASSOC); }
        public function getUsageLogs($l, $o) { $q=$this->pdo->prepare("SELECT * FROM usage_logs ORDER BY access_time DESC LIMIT ? OFFSET ?"); $q->bindValue(1,$l,PDO::PARAM_INT); $q->bindValue(2,$o,PDO::PARAM_INT); $q->execute(); return $q->fetchAll(PDO::FETCH_ASSOC); }
        public function getActiveDevices() { return $this->pdo->query("SELECT T1.*, IFNULL(T2.app_name, '通用') as app_name FROM active_devices T1 LEFT JOIN applications T2 ON T1.app_id = T2.id WHERE T1.status=1 AND T1.expire_time > datetime('now') ORDER BY T1.activate_time DESC")->fetchAll(PDO::FETCH_ASSOC); }
        
        public function generateCards($count, $type, $pre, $suf, $len, $note, $appId = 0) {
            $this->pdo->beginTransaction();
            try {
                // appId 允许为 0，因为我们去除了外键约束
                $stmt = $this->pdo->prepare("INSERT INTO cards (card_code, card_type, notes, app_id) VALUES (?, ?, ?, ?)");
                for ($i=0; $i<$count; $i++) {
                    $code = $pre . $this->randStr($len) . $suf;
                    $stmt->execute([$code, $type, $note, $appId]);
                }
                $this->pdo->commit();
            } catch(Exception $e) { $this->pdo->rollBack(); throw $e; }
        }

        public function deleteCard($id) { $this->pdo->prepare("DELETE FROM cards WHERE id=?")->execute([$id]); }
        public function getAdminHash() { return $this->pdo->query("SELECT password_hash FROM admin WHERE id=1")->fetchColumn(); }
        public function updateAdminPassword($pwd) { $this->pdo->prepare("UPDATE admin SET password_hash=? WHERE id=1")->execute([password_hash($pwd, PASSWORD_DEFAULT)]); }
        public function cleanupExpiredDevices() { $this->pdo->exec("UPDATE active_devices SET status=0 WHERE status=1 AND expire_time <= datetime('now')"); }

        private function logUsage($c, $t, $d, $i, $u, $r, $appName = 'System') { $this->pdo->prepare("INSERT INTO usage_logs (card_code, card_type, device_hash, ip_address, user_agent, result, app_name, access_time) VALUES (?,?,?,?,?,?,?,datetime('now','localtime'))")->execute([$c,$t,$d,$i,$u,$r,$appName]); }
        private function randStr($l) { $c='23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; $r=''; for($i=0;$i<$l;$i++) $r.=$c[rand(0,strlen($c)-1)]; return $r; }
    }
}
?>
