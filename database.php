<?php
// database.php - 核心数据库类 (安全增强版)
require_once 'config.php';

if (!class_exists('Database')) {
    
    class Database {
        public $pdo;
        
        public function __construct() {
            try {
                $dsn = "mysql:host=".DB_HOST.";port=".DB_PORT.";dbname=".DB_NAME.";charset=utf8mb4";
                $options = [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
                ];
                $this->pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
                $this->createTables();
                
            } catch (PDOException $e) {
                // 生产环境记录日志，不直接显示详细错误
                error_log('DB Connection Error: ' . $e->getMessage());
                die('System Error: Database connection failed. Please check error logs.');
            }
        }
        
        private function createTables() {
            $tableOptions = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

            $this->pdo->exec("CREATE TABLE IF NOT EXISTS applications (
                id INT AUTO_INCREMENT PRIMARY KEY, 
                app_name VARCHAR(100) NOT NULL UNIQUE, 
                app_key VARCHAR(64) NOT NULL UNIQUE, 
                app_version VARCHAR(32) DEFAULT '', 
                status TINYINT DEFAULT 1, 
                create_time DATETIME DEFAULT CURRENT_TIMESTAMP, 
                notes TEXT
            ) $tableOptions");
            
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS app_variables (
                id INT AUTO_INCREMENT PRIMARY KEY, 
                app_id INT NOT NULL, 
                key_name VARCHAR(50) NOT NULL, 
                value TEXT, 
                is_public TINYINT DEFAULT 0, 
                create_time DATETIME DEFAULT CURRENT_TIMESTAMP, 
                INDEX idx_app_var (app_id, key_name)
            ) $tableOptions");

            $this->pdo->exec("CREATE TABLE IF NOT EXISTS cards (
                id INT AUTO_INCREMENT PRIMARY KEY, 
                card_code VARCHAR(50) UNIQUE NOT NULL, 
                card_type VARCHAR(20) NOT NULL, 
                status TINYINT DEFAULT 0, 
                device_hash VARCHAR(100), 
                used_time DATETIME, 
                expire_time DATETIME, 
                create_time DATETIME DEFAULT CURRENT_TIMESTAMP, 
                notes TEXT, 
                app_id INT DEFAULT 0, 
                INDEX idx_card_app (app_id), 
                INDEX idx_card_hash (device_hash)
            ) $tableOptions");
            
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS usage_logs (
                id INT AUTO_INCREMENT PRIMARY KEY, 
                card_code VARCHAR(50) NOT NULL, 
                card_type VARCHAR(20) NOT NULL, 
                device_hash VARCHAR(100) NOT NULL, 
                ip_address VARCHAR(45), 
                user_agent TEXT, 
                access_time DATETIME DEFAULT CURRENT_TIMESTAMP, 
                result VARCHAR(100), 
                app_name VARCHAR(100) DEFAULT 'System', 
                INDEX idx_log_time (access_time)
            ) $tableOptions");
            
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS active_devices (
                id INT AUTO_INCREMENT PRIMARY KEY, 
                device_hash VARCHAR(100) NOT NULL, 
                card_code VARCHAR(50) UNIQUE NOT NULL, 
                card_type VARCHAR(20) NOT NULL, 
                activate_time DATETIME DEFAULT CURRENT_TIMESTAMP, 
                expire_time DATETIME NOT NULL, 
                status TINYINT DEFAULT 1, 
                app_id INT DEFAULT 0, 
                INDEX idx_dev_hash (device_hash), 
                INDEX idx_dev_expire (expire_time)
            ) $tableOptions");
            
            $this->pdo->exec("CREATE TABLE IF NOT EXISTS admin (
                id INT PRIMARY KEY, 
                username VARCHAR(50) UNIQUE NOT NULL, 
                password_hash VARCHAR(255) NOT NULL
            ) $tableOptions");
            
            if ($this->pdo->query("SELECT COUNT(*) FROM admin")->fetchColumn() == 0) {
                $this->pdo->prepare("INSERT IGNORE INTO admin (id, username, password_hash) VALUES (1, 'admin', ?)")->execute([password_hash('admin123', PASSWORD_DEFAULT)]);
            }
        }

        // --- 应用管理 ---
        public function createApp($name, $version = '', $notes = '') {
            $appKey = bin2hex(random_bytes(32));
            $stmt = $this->pdo->prepare("INSERT INTO applications (app_name, app_key, app_version, notes) VALUES (?, ?, ?, ?)");
            $stmt->execute([$name, $appKey, $version, $notes]);
            return $appKey;
        }

        public function updateApp($id, $name, $version, $notes) {
            $check = $this->pdo->prepare("SELECT COUNT(*) FROM applications WHERE app_name = ? AND id != ?");
            $check->execute([$name, $id]);
            if ($check->fetchColumn() > 0) throw new Exception("应用名称已存在");

            $stmt = $this->pdo->prepare("UPDATE applications SET app_name = ?, app_version = ?, notes = ? WHERE id = ?");
            $stmt->execute([$name, $version, $notes, $id]);
        }

        public function getApps() {
            return $this->pdo->query("SELECT *, (SELECT COUNT(*) FROM cards WHERE cards.app_id = applications.id) as card_count FROM applications ORDER BY create_time DESC")->fetchAll(PDO::FETCH_ASSOC);
        }

        public function toggleAppStatus($id) { $this->pdo->prepare("UPDATE applications SET status = CASE WHEN status = 1 THEN 0 ELSE 1 END WHERE id = ?")->execute([$id]); }

        public function deleteApp($id) {
            $count = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE app_id = $id")->fetchColumn();
            if ($count > 0) throw new Exception("无法删除：该应用下仍有 {$count} 张卡密。");
            $this->pdo->prepare("DELETE FROM app_variables WHERE app_id = ?")->execute([$id]);
            $this->pdo->prepare("DELETE FROM applications WHERE id = ?")->execute([$id]);
        }

        // --- 变量管理 ---
        public function addAppVariable($appId, $key, $value, $isPublic) {
            $check = $this->pdo->prepare("SELECT COUNT(*) FROM app_variables WHERE app_id = ? AND key_name = ?");
            $check->execute([$appId, $key]);
            if ($check->fetchColumn() > 0) throw new Exception("变量名重复");
            $stmt = $this->pdo->prepare("INSERT INTO app_variables (app_id, key_name, value, is_public) VALUES (?, ?, ?, ?)");
            $stmt->execute([$appId, $key, $value, $isPublic]);
        }

        public function deleteAppVariable($id) { $this->pdo->prepare("DELETE FROM app_variables WHERE id = ?")->execute([$id]); }

        public function getAppVariables($appId, $onlyPublic = false) {
            $sql = "SELECT * FROM app_variables WHERE app_id = ?";
            if ($onlyPublic) $sql .= " AND is_public = 1";
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute([$appId]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        }

        public function updateAppVariable($id, $key, $value, $isPublic) {
            $stmt = $this->pdo->prepare("SELECT app_id FROM app_variables WHERE id = ?");
            $stmt->execute([$id]);
            $appId = $stmt->fetchColumn();
            if (!$appId) throw new Exception("变量不存在");
            $check = $this->pdo->prepare("SELECT COUNT(*) FROM app_variables WHERE app_id = ? AND key_name = ? AND id != ?");
            $check->execute([$appId, $key, $id]);
            if ($check->fetchColumn() > 0) throw new Exception("变量名重复");
            $this->pdo->prepare("UPDATE app_variables SET key_name=?, value=?, is_public=? WHERE id=?")->execute([$key, $value, $isPublic, $id]);
        }
        
        public function getAppIdByKey($appKey) {
            $stmt = $this->pdo->prepare("SELECT id, status, app_name FROM applications WHERE app_key = ?");
            $stmt->execute([$appKey]);
            return $stmt->fetch(PDO::FETCH_ASSOC);
        }

        // --- 核心验证 (安全修复版) ---
        public function verifyCard($cardCode, $deviceHash, $appKey = null) {
            $this->cleanupExpiredDevices();
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown'; 
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

            if (empty($appKey)) return ['success' => false, 'message' => '鉴权失败：未提供AppKey'];

            $app = $this->getAppIdByKey($appKey);
            if (!$app) return ['success' => false, 'message' => '应用密钥无效'];
            if ($app['status'] == 0) return ['success' => false, 'message' => '应用已被禁用'];
            
            $currentAppId = $app['id'];
            $appNameForLog = $app['app_name'];

            // 1. 检查 active_devices
            $deviceStmt = $this->pdo->prepare("SELECT * FROM active_devices WHERE device_hash = ? AND status = 1 AND expire_time > NOW() AND app_id = ?");
            $deviceStmt->execute([$deviceHash, $currentAppId]);
            $activeInfo = $deviceStmt->fetch(PDO::FETCH_ASSOC);

            if ($activeInfo) {
                if ($activeInfo['card_code'] === $cardCode) {
                    // [安全修复] 回查 cards 表，防止脏读（卡已被删或被封，但缓存还在）
                    $cardCheck = $this->pdo->prepare("SELECT status FROM cards WHERE card_code = ?");
                    $cardCheck->execute([$cardCode]);
                    $cardStatus = $cardCheck->fetchColumn();

                    // 如果查不到($cardStatus === false) 说明卡被删了; 如果等于2 说明被封了
                    if ($cardStatus === false) {
                        $this->pdo->prepare("DELETE FROM active_devices WHERE card_code = ?")->execute([$cardCode]);
                        return ['success' => false, 'message' => '卡密已失效'];
                    }
                    if ($cardStatus == 2) {
                        return ['success' => false, 'message' => '此卡密已被管理员封禁'];
                    }

                    $this->logUsage($activeInfo['card_code'], $activeInfo['card_type'], $deviceHash, $ip, $ua, '设备活跃', $appNameForLog);
                    return ['success' => true, 'message' => '设备已激活', 'expire_time' => $activeInfo['expire_time'], 'app_id' => $currentAppId];
                }
            }
            
            // 2. 检查卡密表
            $cardStmt = $this->pdo->prepare("SELECT * FROM cards WHERE card_code = ? AND app_id = ?");
            $cardStmt->execute([$cardCode, $currentAppId]);
            $card = $cardStmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$card) return ['success' => false, 'message' => '无效的卡密 (或不属于当前应用)'];
            if ($card['status'] == 2) return ['success' => false, 'message' => '此卡密已被管理员封禁'];
            
            // 已激活但设备码对不上
            if ($card['status'] == 1) {
                if (strtotime($card['expire_time']) <= time()) return ['success' => false, 'message' => '卡密已过期'];
                if (!empty($card['device_hash']) && $card['device_hash'] !== $deviceHash) return ['success' => false, 'message' => '卡密已绑定其他设备'];
                
                // 修复：如果 device_hash 为空但 status=1 (异常数据)，允许重新绑定
                if ($card['device_hash'] !== $deviceHash) $this->pdo->prepare("UPDATE cards SET device_hash=? WHERE id=?")->execute([$deviceHash, $card['id']]);
                
                // 更新/插入 active_devices
                $this->pdo->prepare("REPLACE INTO active_devices (device_hash, card_code, card_type, expire_time, status, app_id) VALUES (?, ?, ?, ?, 1, ?)")->execute([$deviceHash, $cardCode, $card['card_type'], $card['expire_time'], $currentAppId]);
                return ['success' => true, 'message' => '验证通过', 'expire_time' => $card['expire_time'], 'app_id' => $currentAppId];
            } 
            
            // 首次激活
            else {
                $duration = CARD_TYPES[$card['card_type']]['duration'] ?? 86400;
                $this->pdo->prepare("UPDATE cards SET status=1, device_hash=?, used_time=NOW(), expire_time=DATE_ADD(NOW(), INTERVAL ? SECOND) WHERE id=?")->execute([$deviceHash, $duration, $card['id']]);
                
                $newExpStmt = $this->pdo->prepare("SELECT expire_time FROM cards WHERE id=?");
                $newExpStmt->execute([$card['id']]);
                $expireTime = $newExpStmt->fetchColumn();

                $this->pdo->prepare("INSERT INTO active_devices (device_hash, card_code, card_type, expire_time, status, app_id) VALUES (?, ?, ?, ?, 1, ?)")->execute([$deviceHash, $cardCode, $card['card_type'], $expireTime, $currentAppId]);
                $this->logUsage($cardCode, $card['card_type'], $deviceHash, $ip, $ua, '激活成功', $appNameForLog);
                return ['success' => true, 'message' => '首次激活成功', 'expire_time' => $expireTime, 'app_id' => $currentAppId];
            }
        }

        // --- 批量操作 (安全修复版) ---
        // [修复] 批量删除时，必须同步清理 active_devices，否则会出现"幽灵卡"
        public function batchDeleteCards($ids) { 
            if (empty($ids)) return 0; 
            
            // 1. 查找要删除的卡密Code
            $placeholders = implode(',', array_fill(0, count($ids), '?')); 
            $stmt = $this->pdo->prepare("SELECT card_code FROM cards WHERE id IN ($placeholders)");
            $stmt->execute($ids);
            $codes = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            $this->pdo->beginTransaction();
            try {
                // 2. 先踢下线 (从 active_devices 删除)
                if (!empty($codes)) {
                    $codePlaceholders = implode(',', array_fill(0, count($codes), '?'));
                    $this->pdo->prepare("DELETE FROM active_devices WHERE card_code IN ($codePlaceholders)")->execute($codes);
                }
                
                // 3. 再删卡
                $delStmt = $this->pdo->prepare("DELETE FROM cards WHERE id IN ($placeholders)");
                $delStmt->execute($ids);
                $count = $delStmt->rowCount();
                
                $this->pdo->commit();
                return $count;
            } catch (Exception $e) {
                $this->pdo->rollBack();
                throw $e;
            }
        }

        public function batchUnbindCards($ids) { 
            if (empty($ids)) return 0; 
            $placeholders = implode(',', array_fill(0, count($ids), '?')); 
            $this->pdo->beginTransaction(); 
            try { 
                $stmt = $this->pdo->prepare("SELECT card_code FROM cards WHERE id IN ($placeholders)"); 
                $stmt->execute($ids); 
                $codes = $stmt->fetchAll(PDO::FETCH_COLUMN); 
                if($codes) { 
                    $codePlaceholders = implode(',', array_fill(0, count($codes), '?')); 
                    $this->pdo->prepare("DELETE FROM active_devices WHERE card_code IN ($codePlaceholders)")->execute($codes); 
                } 
                $this->pdo->prepare("UPDATE cards SET device_hash = NULL WHERE id IN ($placeholders)")->execute($ids); 
                $this->pdo->commit(); 
                return count($ids); 
            } catch (Exception $e) { $this->pdo->rollBack(); return 0; } 
        }
        
        public function batchAddTime($ids, $hours) { 
            if (empty($ids) || $hours <= 0) return 0; 
            $seconds = intval($hours * 3600); 
            $placeholders = implode(',', array_fill(0, count($ids), '?')); 
            $this->pdo->beginTransaction(); 
            try { 
                $stmt = $this->pdo->prepare("SELECT card_code FROM cards WHERE id IN ($placeholders) AND status = 1"); 
                $stmt->execute($ids); 
                $codes = $stmt->fetchAll(PDO::FETCH_COLUMN); 
                if($codes) { 
                    $codePlaceholders = implode(',', array_fill(0, count($codes), '?')); 
                    $this->pdo->prepare("UPDATE cards SET expire_time = DATE_ADD(expire_time, INTERVAL {$seconds} SECOND) WHERE id IN ($placeholders) AND status = 1")->execute($ids); 
                    $this->pdo->prepare("UPDATE active_devices SET expire_time = DATE_ADD(expire_time, INTERVAL {$seconds} SECOND) WHERE card_code IN ($codePlaceholders)")->execute($codes); 
                } 
                $this->pdo->commit(); 
                return count($codes); 
            } catch (Exception $e) { $this->pdo->rollBack(); return 0; } 
        }
        
        public function getCardsByIds($ids) { if(empty($ids)) return []; $placeholders = implode(',', array_fill(0, count($ids), '?')); $stmt = $this->pdo->prepare("SELECT * FROM cards WHERE id IN ($placeholders)"); $stmt->execute($ids); return $stmt->fetchAll(PDO::FETCH_ASSOC); }
        public function resetDeviceBindingByCardId($id) { return $this->batchUnbindCards([$id]); }
        
        public function updateCardStatus($id, $status) { 
            if ($status == 1) { 
                $check = $this->pdo->prepare("SELECT expire_time FROM cards WHERE id = ?"); 
                $check->execute([$id]); 
                $row = $check->fetch(PDO::FETCH_ASSOC); 
                if ($row && empty($row['expire_time'])) { $status = 0; } 
            } 
            $this->pdo->prepare("UPDATE cards SET status=? WHERE id=?")->execute([$status, $id]); 
            // 封禁时强制下线
            if ($status == 2) { 
                $codeStmt = $this->pdo->prepare("SELECT card_code FROM cards WHERE id = ?"); 
                $codeStmt->execute([$id]); 
                $code = $codeStmt->fetchColumn(); 
                if ($code) { $this->pdo->prepare("DELETE FROM active_devices WHERE card_code = ?")->execute([$code]); } 
            } 
        }
        
        // --- 统计与数据 ---
        public function getDashboardData() { 
            $total = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE app_id > 0")->fetchColumn(); 
            $unused = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE status = 0 AND app_id > 0")->fetchColumn(); 
            $used = $this->pdo->query("SELECT COUNT(*) FROM cards WHERE status = 1 AND app_id > 0")->fetchColumn(); 
            $active = $this->pdo->query("SELECT COUNT(*) FROM active_devices WHERE status = 1 AND expire_time > NOW() AND app_id > 0")->fetchColumn(); 
            $types = $this->pdo->query("SELECT card_type, COUNT(*) as count FROM cards WHERE app_id > 0 GROUP BY card_type")->fetchAll(PDO::FETCH_KEY_PAIR); 
            $appStats = $this->pdo->query("SELECT T2.app_name, COUNT(T1.id) as count FROM cards T1 JOIN applications T2 ON T1.app_id = T2.id WHERE T1.app_id > 0 GROUP BY T1.app_id ORDER BY count DESC LIMIT 5")->fetchAll(PDO::FETCH_ASSOC); 
            return ['stats' => ['total' => $total, 'unused' => $unused, 'used' => $used, 'active' => $active], 'chart_types' => $types, 'app_stats' => $appStats]; 
        }
        
        public function getTotalCardCount($statusFilter = null, $appId = null) {
            $sql = "SELECT COUNT(*) FROM cards WHERE app_id > 0";
            $params = [];
            if ($statusFilter !== null) { $sql .= " AND status = ?"; $params[] = $statusFilter; }
            if ($appId !== null) { $sql .= " AND app_id = ?"; $params[] = $appId; }
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            return $stmt->fetchColumn();
        }
        
        public function getCardsPaginated($limit, $offset, $statusFilter = null, $appId = null) {
            $sql = "SELECT T1.*, T2.app_name FROM cards T1 JOIN applications T2 ON T1.app_id = T2.id WHERE 1=1 ";
            if ($statusFilter !== null) $sql .= "AND T1.status = :status ";
            if ($appId !== null) $sql .= "AND T1.app_id = :app_id ";
            $sql .= "ORDER BY T1.create_time DESC LIMIT :limit OFFSET :offset";
            
            $stmt = $this->pdo->prepare($sql);
            if ($statusFilter !== null) $stmt->bindValue(':status', $statusFilter, PDO::PARAM_INT);
            if ($appId !== null) $stmt->bindValue(':app_id', $appId, PDO::PARAM_INT);
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        }

        public function searchCards($k) { 
            $s="%$k%"; 
            $q=$this->pdo->prepare("SELECT T1.*, T2.app_name FROM cards T1 JOIN applications T2 ON T1.app_id = T2.id WHERE (T1.card_code LIKE ? OR T1.notes LIKE ? OR T1.device_hash LIKE ? OR T2.app_name LIKE ?) AND T1.app_id > 0"); 
            $q->execute([$s,$s,$s,$s]); 
            return $q->fetchAll(PDO::FETCH_ASSOC); 
        }

        public function getUsageLogs($l, $o) { $q=$this->pdo->prepare("SELECT * FROM usage_logs ORDER BY access_time DESC LIMIT ? OFFSET ?"); $q->bindValue(1,$l,PDO::PARAM_INT); $q->bindValue(2,$o,PDO::PARAM_INT); $q->execute(); return $q->fetchAll(PDO::FETCH_ASSOC); }
        public function getActiveDevices() { return $this->pdo->query("SELECT T1.*, T2.app_name FROM active_devices T1 JOIN applications T2 ON T1.app_id = T2.id WHERE T1.status=1 AND T1.expire_time > NOW() AND T1.app_id > 0 ORDER BY T1.activate_time DESC")->fetchAll(PDO::FETCH_ASSOC); }
        
        // [安全增强] 使用 random_int 代替 insecure rand
        public function generateCards($count, $type, $pre, $suf, $len, $note, $appId) { 
            if(empty($appId) || $appId <= 0) throw new Exception("必须指定有效的应用 ID");
            $this->pdo->beginTransaction(); 
            try { 
                $stmt = $this->pdo->prepare("INSERT INTO cards (card_code, card_type, notes, app_id) VALUES (?, ?, ?, ?)"); 
                for ($i=0; $i<$count; $i++) { 
                    $code = $pre . $this->secureRandStr($len) . $suf; 
                    $stmt->execute([$code, $type, $note, $appId]); 
                } 
                $this->pdo->commit(); 
            } catch(Exception $e) { 
                $this->pdo->rollBack(); 
                throw $e; 
            } 
        }

        public function deleteCard($id) { 
            // 封装调用批量删除，保证逻辑一致
            $this->batchDeleteCards([$id]); 
        }
        
        public function getAdminHash() { return $this->pdo->query("SELECT password_hash FROM admin WHERE id=1")->fetchColumn(); }
        public function updateAdminPassword($pwd) { $this->pdo->prepare("UPDATE admin SET password_hash=? WHERE id=1")->execute([password_hash($pwd, PASSWORD_DEFAULT)]); }
        public function cleanupExpiredDevices() { $this->pdo->exec("UPDATE active_devices SET status=0 WHERE status=1 AND expire_time <= NOW()"); }
        private function logUsage($c, $t, $d, $i, $u, $r, $appName = 'System') { $this->pdo->prepare("INSERT INTO usage_logs (card_code, card_type, device_hash, ip_address, user_agent, result, app_name, access_time) VALUES (?,?,?,?,?,?,?,NOW())")->execute([$c,$t,$d,$i,$u,$r,$appName]); }
        
        // [安全新增] 密码学安全的随机字符串
        private function secureRandStr($length) {
            $keyspace = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
            $str = '';
            $max = mb_strlen($keyspace, '8bit') - 1;
            for ($i = 0; $i < $length; ++$i) {
                $str .= $keyspace[random_int(0, $max)];
            }
            return $str;
        }
    }
}
?>
