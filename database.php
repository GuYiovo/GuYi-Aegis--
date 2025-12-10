<?php
// database.php - 核心数据库类 
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
                
                $this->createTables();
                $this->migrateForMultiTenant();
                
            } catch (PDOException $e) {
                error_log('DB Error: ' . $e->getMessage());
                die('System Maintenance: Database connection failed.');
            }
        }
        
        private function createTables() {
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS applications (id INTEGER PRIMARY KEY AUTOINCREMENT, app_name VARCHAR(100) NOT NULL UNIQUE, app_key VARCHAR(64) NOT NULL UNIQUE, status INTEGER DEFAULT 1, create_time DATETIME DEFAULT CURRENT_TIMESTAMP, notes TEXT)");
            
            // 确保变量表存在
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS app_variables (id INTEGER PRIMARY KEY AUTOINCREMENT, app_id INTEGER NOT NULL, key_name VARCHAR(50) NOT NULL, value TEXT, is_public INTEGER DEFAULT 0, create_time DATETIME DEFAULT CURRENT_TIMESTAMP)");

            $this->pdo->exec("CREATE TABLE IF NOT EXISTS cards (id INTEGER PRIMARY KEY AUTOINCREMENT, card_code VARCHAR(50) UNIQUE NOT NULL, card_type VARCHAR(20) NOT NULL, status INTEGER DEFAULT 0, device_hash VARCHAR(100), used_time DATETIME, expire_time DATETIME, create_time DATETIME DEFAULT CURRENT_TIMESTAMP, notes TEXT)");
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS usage_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, card_code VARCHAR(50) NOT NULL, card_type VARCHAR(20) NOT NULL, device_hash VARCHAR(100) NOT NULL, ip_address VARCHAR(45), user_agent TEXT, access_time DATETIME DEFAULT CURRENT_TIMESTAMP, result VARCHAR(100))");
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS active_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, device_hash VARCHAR(100) NOT NULL, card_code VARCHAR(50) UNIQUE NOT NULL, card_type VARCHAR(20) NOT NULL, activate_time DATETIME DEFAULT CURRENT_TIMESTAMP, expire_time DATETIME NOT NULL, status INTEGER DEFAULT 1)");
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL)");
            
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
            $apps = $this->pdo->query("SELECT *, (SELECT COUNT(*) FROM cards WHERE cards.app_id = applications.id) as card_count FROM applications ORDER BY create_time DESC")->fetchAll(PDO::FETCH_ASSOC);
            $generalCount = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE app_id = 0")->fetchColumn();
            array_unshift($apps, [
                'id' => 0, 'app_name' => '通用/未分类', 'app_key' => '-', 'status' => 1, 'card_count' => $generalCount, 'notes' => '系统默认卡池'
            ]);
            return $apps;
        }

        public function toggleAppStatus($id) { if ($id == 0) return; $this->pdo->prepare("UPDATE applications SET status = CASE WHEN status = 1 THEN 0 ELSE 1 END WHERE id = ?")->execute([$id]); }

        public function deleteApp($id) {
            if ($id == 0) throw new Exception("无法删除系统默认应用");
            $count = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE app_id = $id")->fetchColumn();
            if ($count > 0) throw new Exception("无法删除：该应用下仍有 {$count} 张卡密。");
            $this->pdo->prepare("DELETE FROM app_variables WHERE app_id = ?")->execute([$id]);
            $this->pdo->prepare("DELETE FROM applications WHERE id = ?")->execute([$id]);
        }

        // --- 变量管理核心逻辑 ---
        public function addAppVariable($appId, $key, $value, $isPublic) {
            $check = $this->pdo->prepare("SELECT COUNT(*) FROM app_variables WHERE app_id = ? AND key_name = ?");
            $check->execute([$appId, $key]);
            if ($check->fetchColumn() > 0) throw new Exception("变量名重复");
            $stmt = $this->pdo->prepare("INSERT INTO app_variables (app_id, key_name, value, is_public) VALUES (?, ?, ?, ?)");
            $stmt->execute([$appId, $key, $value, $isPublic]);
        }

        public function deleteAppVariable($id) { $this->pdo->prepare("DELETE FROM app_variables WHERE id = ?")->execute([$id]); }

        // [重要] 获取变量 - 支持公开/私有筛选
        public function getAppVariables($appId, $onlyPublic = false) {
            $sql = "SELECT * FROM app_variables WHERE app_id = ?";
            if ($onlyPublic) {
                $sql .= " AND is_public = 1"; // 如果只请求公开的，必须加上这个条件
            }
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute([$appId]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
        
        // [重要] 通过Key获取App信息 - API.php 依赖此函数
        public function getAppIdByKey($appKey) {
            $stmt = $this->pdo->prepare("SELECT id, status, app_name FROM applications WHERE app_key = ?");
            $stmt->execute([$appKey]);
            return $stmt->fetch(PDO::FETCH_ASSOC);
        }

        // --- 验证核心 ---
        public function verifyCard($cardCode, $deviceHash, $appKey = null) {
            $this->cleanupExpiredDevices();
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown'; $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
            $app = null; $appNameForLog = 'System'; $appIdStr = " = 0"; 

            if ($appKey) {
                $app = $this->getAppIdByKey($appKey); // 复用上面的函数
                if (!$app) return ['success' => false, 'message' => '应用密钥无效'];
                if ($app['status'] == 0) return ['success' => false, 'message' => '应用已被禁用'];
                $appNameForLog = $app['app_name'];
                $appIdStr = " = {$app['id']}";
            }

            $deviceStmt = $this->pdo->prepare("SELECT * FROM active_devices WHERE device_hash = ? AND status = 1 AND expire_time > datetime('now') AND app_id {$appIdStr}");
            $deviceStmt->execute([$deviceHash]);
            if ($active = $deviceStmt->fetch(PDO::FETCH_ASSOC)) {
                if ($active['card_code'] === $cardCode) {
                    $statusCheck = $this->pdo->prepare("SELECT status FROM cards WHERE card_code = ?");
                    $statusCheck->execute([$cardCode]);
                    if ($statusCheck->fetchColumn() == 2) return ['success' => false, 'message' => '此卡密已被管理员封禁'];
                    
                    $this->logUsage($active['card_code'], $active['card_type'], $deviceHash, $ip, $ua, '设备活跃', $appNameForLog);
                    return ['success' => true, 'message' => '设备已激活', 'expire_time' => $active['expire_time'], 'app_id' => $app ? $app['id'] : 0];
                }
            }
            
            $card = $this->pdo->prepare("SELECT * FROM cards WHERE card_code = ? AND app_id {$appIdStr}");
            $card->execute([$cardCode]);
            $card = $card->fetch(PDO::FETCH_ASSOC);
            
            if (!$card) return ['success' => false, 'message' => '无效的卡密代码'];
            if ($card['status'] == 2) return ['success' => false, 'message' => '此卡密已被管理员封禁'];
            
            if ($card['status'] == 1) {
                if (strtotime($card['expire_time']) <= time()) return ['success' => false, 'message' => '卡密已过期'];
                if (!empty($card['device_hash']) && $card['device_hash'] !== $deviceHash) return ['success' => false, 'message' => '卡密已绑定其他设备'];
                if ($card['device_hash'] !== $deviceHash) $this->pdo->prepare("UPDATE cards SET device_hash=? WHERE id=?")->execute([$deviceHash, $card['id']]);
                
                $this->pdo->prepare("INSERT OR REPLACE INTO active_devices (device_hash, card_code, card_type, expire_time, status, app_id) VALUES (?, ?, ?, ?, 1, ?)")->execute([$deviceHash, $cardCode, $card['card_type'], $card['expire_time'], $app ? $app['id'] : 0]);
                return ['success' => true, 'message' => '验证通过', 'expire_time' => $card['expire_time'], 'app_id' => $app ? $app['id'] : 0];
            } else {
                $duration = CARD_TYPES[$card['card_type']]['duration'] ?? 86400;
                $expireTime = date('Y-m-d H:i:s', time() + $duration);
                $this->pdo->prepare("UPDATE cards SET status=1, device_hash=?, used_time=datetime('now','localtime'), expire_time=? WHERE id=?")->execute([$deviceHash, $expireTime, $card['id']]);
                $this->pdo->prepare("INSERT INTO active_devices (device_hash, card_code, card_type, expire_time, status, app_id) VALUES (?, ?, ?, ?, 1, ?)")->execute([$deviceHash, $cardCode, $card['card_type'], $expireTime, $app ? $app['id'] : 0]);
                $this->logUsage($cardCode, $card['card_type'], $deviceHash, $ip, $ua, '激活成功', $appNameForLog);
                return ['success' => true, 'message' => '首次激活成功', 'expire_time' => $expireTime, 'app_id' => $app ? $app['id'] : 0];
            }
        }

        public function batchDeleteCards($ids) { if (empty($ids)) return 0; $placeholders = implode(',', array_fill(0, count($ids), '?')); $stmt = $this->pdo->prepare("DELETE FROM cards WHERE id IN ($placeholders)"); $stmt->execute($ids); return $stmt->rowCount(); }
        public function batchUnbindCards($ids) { if (empty($ids)) return 0; $placeholders = implode(',', array_fill(0, count($ids), '?')); $this->pdo->beginTransaction(); try { $stmt = $this->pdo->prepare("SELECT card_code FROM cards WHERE id IN ($placeholders)"); $stmt->execute($ids); $codes = $stmt->fetchAll(PDO::FETCH_COLUMN); if($codes) { $codePlaceholders = implode(',', array_fill(0, count($codes), '?')); $this->pdo->prepare("DELETE FROM active_devices WHERE card_code IN ($codePlaceholders)")->execute($codes); } $this->pdo->prepare("UPDATE cards SET device_hash = NULL WHERE id IN ($placeholders)")->execute($ids); $this->pdo->commit(); return count($ids); } catch (Exception $e) { $this->pdo->rollBack(); return 0; } }
        public function batchAddTime($ids, $hours) { if (empty($ids) || $hours <= 0) return 0; $seconds = intval($hours * 3600); $placeholders = implode(',', array_fill(0, count($ids), '?')); $this->pdo->beginTransaction(); try { $stmt = $this->pdo->prepare("SELECT card_code FROM cards WHERE id IN ($placeholders) AND status = 1"); $stmt->execute($ids); $codes = $stmt->fetchAll(PDO::FETCH_COLUMN); if($codes) { $codePlaceholders = implode(',', array_fill(0, count($codes), '?')); $this->pdo->prepare("UPDATE cards SET expire_time = datetime(expire_time, '+{$seconds} seconds') WHERE id IN ($placeholders) AND status = 1")->execute($ids); $this->pdo->prepare("UPDATE active_devices SET expire_time = datetime(expire_time, '+{$seconds} seconds') WHERE card_code IN ($codePlaceholders)")->execute($codes); } $this->pdo->commit(); return count($codes); } catch (Exception $e) { $this->pdo->rollBack(); return 0; } }
        public function getCardsByIds($ids) { if(empty($ids)) return []; $placeholders = implode(',', array_fill(0, count($ids), '?')); $stmt = $this->pdo->prepare("SELECT * FROM cards WHERE id IN ($placeholders)"); $stmt->execute($ids); return $stmt->fetchAll(PDO::FETCH_ASSOC); }
        public function resetDeviceBindingByCardId($id) { return $this->batchUnbindCards([$id]); }
        public function updateCardStatus($id, $status) { if ($status == 1) { $check = $this->pdo->prepare("SELECT expire_time FROM cards WHERE id = ?"); $check->execute([$id]); $row = $check->fetch(PDO::FETCH_ASSOC); if ($row && empty($row['expire_time'])) { $status = 0; } } $this->pdo->prepare("UPDATE cards SET status=? WHERE id=?")->execute([$status, $id]); if ($status == 2) { $codeStmt = $this->pdo->prepare("SELECT card_code FROM cards WHERE id = ?"); $codeStmt->execute([$id]); $code = $codeStmt->fetchColumn(); if ($code) { $this->pdo->prepare("DELETE FROM active_devices WHERE card_code = ?")->execute([$code]); } } }
        public function getDashboardData() { $total = $this->pdo->query("SELECT COUNT(*) FROM cards")->fetchColumn(); $unused = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE status = 0")->fetchColumn(); $used = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE status = 1")->fetchColumn(); $active = $this->pdo->query("SELECT COUNT(*) FROM active_devices WHERE status = 1 AND expire_time > datetime('now')")->fetchColumn(); $types = $this->pdo->query("SELECT card_type, COUNT(*) as count FROM cards GROUP BY card_type")->fetchAll(PDO::FETCH_KEY_PAIR); $appStats = $this->pdo->query("SELECT IFNULL(T2.app_name, '通用/未分类') as app_name, COUNT(T1.id) as count FROM cards T1 LEFT JOIN applications T2 ON T1.app_id = T2.id GROUP BY T1.app_id ORDER BY count DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC); return ['stats' => ['total' => $total, 'unused' => $unused, 'used' => $used, 'active' => $active], 'chart_types' => $types, 'app_stats' => $appStats]; }
        public function getAllCards() { return $this->pdo->query("SELECT T1.*, IFNULL(T2.app_name, '通用') as app_name FROM cards T1 LEFT JOIN applications T2 ON T1.app_id = T2.id ORDER BY T1.create_time DESC LIMIT 500")->fetchAll(PDO::FETCH_ASSOC); }
        public function searchCards($k) { $s="%$k%"; $q=$this->pdo->prepare("SELECT T1.*, IFNULL(T2.app_name, '通用') as app_name FROM cards T1 LEFT JOIN applications T2 ON T1.app_id = T2.id WHERE T1.card_code LIKE ? OR T1.notes LIKE ? OR T1.device_hash LIKE ? OR T2.app_name LIKE ?"); $q->execute([$s,$s,$s,$s]); return $q->fetchAll(PDO::FETCH_ASSOC); }
        public function getUsageLogs($l, $o) { $q=$this->pdo->prepare("SELECT * FROM usage_logs ORDER BY access_time DESC LIMIT ? OFFSET ?"); $q->bindValue(1,$l,PDO::PARAM_INT); $q->bindValue(2,$o,PDO::PARAM_INT); $q->execute(); return $q->fetchAll(PDO::FETCH_ASSOC); }
        public function getActiveDevices() { return $this->pdo->query("SELECT T1.*, IFNULL(T2.app_name, '通用') as app_name FROM active_devices T1 LEFT JOIN applications T2 ON T1.app_id = T2.id WHERE T1.status=1 AND T1.expire_time > datetime('now') ORDER BY T1.activate_time DESC")->fetchAll(PDO::FETCH_ASSOC); }
        public function generateCards($count, $type, $pre, $suf, $len, $note, $appId = 0) { $this->pdo->beginTransaction(); try { $stmt = $this->pdo->prepare("INSERT INTO cards (card_code, card_type, notes, app_id) VALUES (?, ?, ?, ?)"); for ($i=0; $i<$count; $i++) { $code = $pre . $this->randStr($len) . $suf; $stmt->execute([$code, $type, $note, $appId]); } $this->pdo->commit(); } catch(Exception $e) { $this->pdo->rollBack(); throw $e; } }
        public function deleteCard($id) { $this->pdo->prepare("DELETE FROM cards WHERE id=?")->execute([$id]); }
        public function getAdminHash() { return $this->pdo->query("SELECT password_hash FROM admin WHERE id=1")->fetchColumn(); }
        public function updateAdminPassword($pwd) { $this->pdo->prepare("UPDATE admin SET password_hash=? WHERE id=1")->execute([password_hash($pwd, PASSWORD_DEFAULT)]); }
        public function cleanupExpiredDevices() { $this->pdo->exec("UPDATE active_devices SET status=0 WHERE status=1 AND expire_time <= datetime('now')"); }
        private function logUsage($c, $t, $d, $i, $u, $r, $appName = 'System') { $this->pdo->prepare("INSERT INTO usage_logs (card_code, card_type, device_hash, ip_address, user_agent, result, app_name, access_time) VALUES (?,?,?,?,?,?,?,datetime('now','localtime'))")->execute([$c,$t,$d,$i,$u,$r,$appName]); }
        private function randStr($l) { $c='23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; $r=''; for($i=0;$i<$l;$i++) $r.=$c[rand(0,strlen($c)-1)]; return $r; }
    }
}
?>
