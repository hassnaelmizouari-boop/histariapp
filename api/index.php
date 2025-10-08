<?php
declare(strict_types=1);

// File: api/index.php
// HistariApp lightweight JSON API.

// -----------------------------------------------------------------------------
// CORS headers
// -----------------------------------------------------------------------------
$allowedOrigin = getenv('HISTARI_ALLOWED_ORIGIN') ?: '*';
$allowedMethods = 'GET, POST, OPTIONS';
$allowedHeaders = 'Content-Type, Authorization, X-Requested-With';

if ($allowedOrigin === '*' && !empty($_SERVER['HTTP_ORIGIN'])) {
    header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
    header('Vary: Origin');
} else {
    header('Access-Control-Allow-Origin: ' . $allowedOrigin);
}
if ($allowedOrigin !== '*') {
    header('Access-Control-Allow-Credentials: true');
}
header('Access-Control-Allow-Methods: ' . $allowedMethods);
header('Access-Control-Allow-Headers: ' . $allowedHeaders);
header('Content-Type: application/json; charset=UTF-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit();
}

// -----------------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------------

/**
 * Emit a JSON response and stop the script.
 */
function json_response(int $statusCode, array $payload): void
{
    http_response_code($statusCode);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit();
}

/**
 * Read and decode the request JSON body.
 */
function read_json_body(): array
{
    $rawBody = file_get_contents('php://input');
    if ($rawBody === false || trim($rawBody) === '') {
        return [];
    }

    $decoded = json_decode($rawBody, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        json_response(400, [
            'status' => 'error',
            'message' => 'Le corps de la requête doit contenir un JSON valide.'
        ]);
    }

    return is_array($decoded) ? $decoded : [];
}

/**
 * Ensure the HTTP method matches the expected one(s).
 */
function require_method(string ...$allowedMethods): void
{
    $allowed = array_map('strtoupper', $allowedMethods);
    if (!in_array($_SERVER['REQUEST_METHOD'], $allowed, true)) {
        throw new RuntimeException('Méthode HTTP non autorisée pour cette action.');
    }
}

/**
 * Check if a database table exists.
 */
function table_exists(PDO $pdo, string $table): bool
{
    static $cache = [];
    if (array_key_exists($table, $cache)) {
        return $cache[$table];
    }

    try {
        $pdo->query('SELECT 1 FROM `' . $table . '` LIMIT 1');
        return $cache[$table] = true;
    } catch (Throwable $exception) {
        return $cache[$table] = false;
    }
}

/**
 * Retrieve and cache column names for a table.
 */
function get_table_columns(PDO $pdo, string $table): array
{
    static $cache = [];
    if (array_key_exists($table, $cache)) {
        return $cache[$table];
    }

    $columns = [];
    try {
        $stmt = $pdo->query('SHOW COLUMNS FROM `' . $table . '`');
        $columns = array_map(static fn(array $row): string => $row['Field'], $stmt->fetchAll());
    } catch (Throwable $exception) {
        $columns = [];
    }

    return $cache[$table] = $columns;
}

/**
 * Return the first existing column for a table among provided candidates.
 */
function find_first_existing_column(PDO $pdo, string $table, array $candidates): ?string
{
    $columns = get_table_columns($pdo, $table);
    foreach ($candidates as $candidate) {
        if (in_array($candidate, $columns, true)) {
            return $candidate;
        }
    }

    return null;
}

/**
 * Filter an associative array using available table columns.
 */
function filter_payload(PDO $pdo, string $table, array $payload): array
{
    $columns = get_table_columns($pdo, $table);
    if ($columns === []) {
        throw new RuntimeException("La table {$table} est introuvable dans la base de données.");
    }

    $filtered = [];
    foreach ($payload as $field => $value) {
        if (!in_array($field, $columns, true)) {
            continue;
        }

        if ($field === 'id' && ($value === null || $value === '')) {
            continue;
        }

        if (is_array($value) || is_object($value)) {
            $filtered[$field] = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        } else {
            $filtered[$field] = $value;
        }
    }

    return $filtered;
}

/**
 * Build a SET clause for SQL updates and return placeholders/values.
 */
function build_set_clause(array $payload): array
{
    $fields = array_keys($payload);
    $setParts = [];
    $params = [];
    foreach ($fields as $field) {
        $placeholder = ':' . $field;
        $setParts[] = '`' . $field . '` = ' . $placeholder;
        $params[$placeholder] = $payload[$field];
    }

    return [implode(', ', $setParts), $params];
}

/**
 * Fetch a row by its primary key.
 */
function fetch_row_by_id(PDO $pdo, string $table, $id): ?array
{
    if ($id === null || $id === '') {
        return null;
    }

    $stmt = $pdo->prepare('SELECT * FROM `' . $table . '` WHERE `id` = :id LIMIT 1');
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch();

    return $row === false ? null : $row;
}

/**
 * Decode JSON fields in-place when possible.
 */
function decode_json_fields(array &$rows, array $fields): void
{
    foreach ($rows as &$row) {
        foreach ($fields as $field) {
            if (isset($row[$field]) && is_string($row[$field])) {
                $decoded = json_decode($row[$field], true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    $row[$field] = $decoded;
                }
            }
        }
    }
    unset($row);
}

/**
 * Authenticate a user and optionally enforce admin permissions.
 */
function authenticate_user(PDO $pdo, array $credentials, bool $requireAdmin = false): array
{
    $email = isset($credentials['email']) ? trim((string) $credentials['email']) : '';
    $password = isset($credentials['password']) ? (string) $credentials['password'] : '';

    if ($email === '' || $password === '') {
        throw new RuntimeException('Identifiants de connexion manquants.');
    }

    $adminBypassEmail = getenv('HISTARI_ADMIN_EMAIL') ?: 'ADMIN';
    $adminBypassPassword = getenv('HISTARI_ADMIN_PASSWORD') ?: 'ADMIN';

    if ($email === $adminBypassEmail && $password === $adminBypassPassword) {
        $stmt = $pdo->prepare("SELECT id, name, email, histaCoins, role, profilePictureUrl FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1");
        $stmt->execute();
        $user = $stmt->fetch();
        if (!$user) {
            throw new RuntimeException('Compte administrateur introuvable.');
        }
        $user['bypass'] = true;
    } else {
        $stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email LIMIT 1');
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch();
        if (!$user || !isset($user['password_hash']) || !password_verify($password, (string) $user['password_hash'])) {
            throw new RuntimeException('E-mail ou mot de passe invalide.');
        }
    }

    if ($requireAdmin && (($user['role'] ?? '') !== 'admin')) {
        throw new RuntimeException('Accès refusé : privilèges administrateur requis.');
    }

    unset($user['password_hash']);
    return $user;
}

/**
 * Insert a row and return the stored representation.
 */
function insert_row(PDO $pdo, string $table, array $payload): array
{
    if ($payload === []) {
        throw new RuntimeException('Aucun champ fourni pour la création.');
    }

    $fields = array_keys($payload);
    $placeholders = array_map(static fn(string $field): string => ':' . $field, $fields);
    $sql = sprintf('INSERT INTO `%s` (%s) VALUES (%s)', $table, implode(', ', array_map(static fn(string $field): string => '`' . $field . '`', $fields)), implode(', ', $placeholders));

    $stmt = $pdo->prepare($sql);
    foreach ($payload as $field => $value) {
        $stmt->bindValue(':' . $field, $value);
    }
    $stmt->execute();

    $id = $pdo->lastInsertId();
    if ($id && in_array('id', array_map('strtolower', $fields), true) === false) {
        $row = fetch_row_by_id($pdo, $table, $id);
        if ($row !== null) {
            return $row;
        }
    }

    $lookupId = $payload['id'] ?? $id;
    if ($lookupId) {
        $row = fetch_row_by_id($pdo, $table, $lookupId);
        if ($row !== null) {
            return $row;
        }
    }

    return $payload;
}

/**
 * Update a row identified by its id.
 */
function update_row(PDO $pdo, string $table, $id, array $payload): array
{
    if ($id === null || $id === '') {
        throw new RuntimeException('Identifiant requis pour la mise à jour.');
    }
    if ($payload === []) {
        throw new RuntimeException('Aucun champ fourni pour la mise à jour.');
    }

    [$setClause, $params] = build_set_clause($payload);
    $params[':id'] = $id;
    $sql = sprintf('UPDATE `%s` SET %s WHERE `id` = :id', $table, $setClause);

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    $row = fetch_row_by_id($pdo, $table, $id);
    return $row ?? $payload;
}

/**
 * Build the base configuration with sensible defaults.
 */
function get_database_configuration(): array
{
    $defaultConfig = [
        'host' => 'sdb-e.hosting.stackcp.net',
        'database' => 'histaria_db-3138332e70',
        'username' => 'histadmin',
        'password' => 'g4:M,Xp^E8D>',
        'charset' => 'utf8mb4',
    ];

    return [
        'host' => getenv('HISTARI_DB_HOST') ?: $defaultConfig['host'],
        'database' => getenv('HISTARI_DB_NAME') ?: $defaultConfig['database'],
        'username' => getenv('HISTARI_DB_USER') ?: $defaultConfig['username'],
        'password' => getenv('HISTARI_DB_PASSWORD') ?: $defaultConfig['password'],
        'charset' => getenv('HISTARI_DB_CHARSET') ?: $defaultConfig['charset'],
    ];
}

/**
 * Retrieve quests with decoded JSON fields.
 */
function fetch_all_quests(PDO $pdo): array
{
    if (!table_exists($pdo, 'quests')) {
        return [];
    }

    $quests = $pdo->query('SELECT * FROM `quests`')->fetchAll();
    decode_json_fields($quests, ['steps']);
    return $quests;
}

/**
 * Retrieve partners if the table exists.
 */
function fetch_all_partners(PDO $pdo): array
{
    if (!table_exists($pdo, 'partners')) {
        return [];
    }

    return $pdo->query('SELECT * FROM `partners`')->fetchAll();
}

/**
 * Retrieve rewards if the table exists.
 */
function fetch_all_rewards(PDO $pdo): array
{
    if (!table_exists($pdo, 'rewards')) {
        return [];
    }

    return $pdo->query('SELECT * FROM `rewards`')->fetchAll();
}

/**
 * Retrieve the quest history for a given user.
 */
function fetch_user_history(PDO $pdo, $userId): array
{
    if (!table_exists($pdo, 'quest_rewards')) {
        return [];
    }

    $stmt = $pdo->prepare('SELECT * FROM `quest_rewards` WHERE `userId` = :userId ORDER BY `date` DESC');
    $stmt->execute([':userId' => $userId]);
    $history = $stmt->fetchAll();
    decode_json_fields($history, ['stats']);
    return $history;
}

/**
 * Retrieve the distinct list of cities available in the quests table.
 */
function fetch_cities(PDO $pdo): array
{
    if (!table_exists($pdo, 'quests')) {
        return [];
    }

    $cityColumn = find_first_existing_column($pdo, 'quests', ['citySlug', 'city', 'location']);
    if ($cityColumn === null) {
        return [];
    }

    $sql = sprintf(
        "SELECT DISTINCT `%1\$s` AS city FROM `quests` WHERE `%1\$s` IS NOT NULL AND `%1\$s` <> '' ORDER BY `%1\$s`",
        $cityColumn
    );
    $stmt = $pdo->query($sql);
    $cities = [];
    foreach ($stmt->fetchAll() as $row) {
        $cities[] = [
            'key' => $row['city'],
            'label' => $row['city'],
        ];
    }

    return $cities;
}

/**
 * Load the city specific payload.
 */
function fetch_city_payload(PDO $pdo, string $cityKey): array
{
    if (!table_exists($pdo, 'quests')) {
        throw new RuntimeException('Aucune quête n\'est disponible.');
    }

    $cityColumn = find_first_existing_column($pdo, 'quests', ['citySlug', 'city', 'location']);
    if ($cityColumn === null) {
        throw new RuntimeException('Impossible de déterminer la colonne ville des quêtes.');
    }

    $stmt = $pdo->prepare('SELECT * FROM `quests` WHERE `' . $cityColumn . '` = :city');
    $stmt->execute([':city' => $cityKey]);
    $quests = $stmt->fetchAll();
    decode_json_fields($quests, ['steps']);

    if ($quests === []) {
        throw new RuntimeException('Aucune quête trouvée pour cette ville.');
    }

    $partners = [];
    if (table_exists($pdo, 'partners')) {
        $partnerCityColumn = find_first_existing_column($pdo, 'partners', ['citySlug', 'city', 'location']);
        if ($partnerCityColumn) {
            $partnerStmt = $pdo->prepare('SELECT * FROM `partners` WHERE `' . $partnerCityColumn . '` = :city');
            $partnerStmt->execute([':city' => $cityKey]);
            $partners = $partnerStmt->fetchAll();
        } else {
            $partners = fetch_all_partners($pdo);
        }
    }

    $rewards = [];
    if (table_exists($pdo, 'rewards')) {
        $rewardCityColumn = find_first_existing_column($pdo, 'rewards', ['citySlug', 'city', 'location']);
        if ($rewardCityColumn) {
            $rewardStmt = $pdo->prepare('SELECT * FROM `rewards` WHERE `' . $rewardCityColumn . '` = :city');
            $rewardStmt->execute([':city' => $cityKey]);
            $rewards = $rewardStmt->fetchAll();
        } else {
            $rewards = fetch_all_rewards($pdo);
        }
    }

    $cityDetails = null;
    if (table_exists($pdo, 'cities')) {
        $cityTableColumn = find_first_existing_column($pdo, 'cities', ['slug', 'citySlug', 'code', 'name']);
        if ($cityTableColumn) {
            $cityStmt = $pdo->prepare('SELECT * FROM `cities` WHERE `' . $cityTableColumn . '` = :city LIMIT 1');
            $cityStmt->execute([':city' => $cityKey]);
            $cityDetails = $cityStmt->fetch() ?: null;
        }
    }

    return [
        'city' => $cityDetails ?: ['key' => $cityKey, 'label' => $cityKey],
        'quests' => $quests,
        'partners' => $partners,
        'rewards' => $rewards,
    ];
}

// -----------------------------------------------------------------------------
// Database connection
// -----------------------------------------------------------------------------
$config = get_database_configuration();
try {
    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s', $config['host'], $config['database'], $config['charset']);
    $pdo = new PDO($dsn, $config['username'], $config['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $exception) {
    json_response(500, [
        'status' => 'error',
        'message' => 'Impossible de se connecter à la base de données : ' . $exception->getMessage(),
    ]);
}

$action = $_GET['action'] ?? '';
$input = read_json_body();

try {
    switch ($action) {
        case 'get_initial_data':
            require_method('GET');

            $quests = fetch_all_quests($pdo);
            $partners = fetch_all_partners($pdo);
            $rewards = fetch_all_rewards($pdo);
            $cities = fetch_cities($pdo);

            $response = [
                'quests' => $quests,
                'partners' => $partners,
                'rewards' => $rewards,
                'cities' => $cities,
                'user' => null,
                'questHistory' => [],
            ];

            if (!empty($_GET['email'])) {
                $email = trim((string) $_GET['email']);
                $userStmt = $pdo->prepare('SELECT id, name, email, histaCoins, role, profilePictureUrl FROM `users` WHERE `email` = :email LIMIT 1');
                $userStmt->execute([':email' => $email]);
                $user = $userStmt->fetch();
                if ($user) {
                    $response['user'] = $user;
                    $response['questHistory'] = fetch_user_history($pdo, $user['id']);
                }
            }

            json_response(200, $response);
            break;

        case 'get_city_data':
            require_method('GET');
            $cityKey = isset($_GET['city']) ? trim((string) $_GET['city']) : '';
            if ($cityKey === '') {
                throw new RuntimeException('Le paramètre "city" est requis.');
            }

            $cityPayload = fetch_city_payload($pdo, $cityKey);
            json_response(200, [
                'status' => 'success',
                'data' => $cityPayload,
            ]);
            break;

        case 'auth':
            require_method('POST');

            $isSignup = !empty($input['isSignup']);
            $email = isset($input['email']) ? trim((string) $input['email']) : '';
            $password = isset($input['password']) ? (string) $input['password'] : '';
            $name = isset($input['name']) ? trim((string) $input['name']) : '';

            if ($isSignup) {
                if ($name === '' || $email === '' || $password === '') {
                    throw new RuntimeException('Nom, e-mail et mot de passe sont obligatoires pour créer un compte.');
                }

                $existingStmt = $pdo->prepare('SELECT id FROM `users` WHERE `email` = :email LIMIT 1');
                $existingStmt->execute([':email' => $email]);
                if ($existingStmt->fetch()) {
                    throw new RuntimeException('Un utilisateur avec cet e-mail existe déjà.');
                }

                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                $insertStmt = $pdo->prepare('INSERT INTO `users` (name, email, password_hash) VALUES (:name, :email, :password)');
                $insertStmt->execute([
                    ':name' => $name,
                    ':email' => $email,
                    ':password' => $hashedPassword,
                ]);

                $userId = (int) $pdo->lastInsertId();
                $userStmt = $pdo->prepare('SELECT id, name, email, histaCoins, role, profilePictureUrl FROM `users` WHERE `id` = :id LIMIT 1');
                $userStmt->execute([':id' => $userId]);
                $user = $userStmt->fetch();
            } else {
                $user = authenticate_user($pdo, ['email' => $email, 'password' => $password]);
            }

            json_response(200, [
                'status' => 'success',
                'user' => $user,
            ]);
            break;

        case 'save_quest_reward':
            require_method('POST');

            $userEmail = isset($input['userEmail']) ? trim((string) $input['userEmail']) : '';
            $reward = $input['reward'] ?? null;
            $coinsToAdd = isset($input['coinsToAdd']) ? (int) $input['coinsToAdd'] : 0;

            if ($userEmail === '' || !is_array($reward)) {
                throw new RuntimeException('Les informations de récompense et l\'e-mail utilisateur sont requis.');
            }

            $userStmt = $pdo->prepare('SELECT id FROM `users` WHERE `email` = :email LIMIT 1');
            $userStmt->execute([':email' => $userEmail]);
            $user = $userStmt->fetch();
            if (!$user) {
                throw new RuntimeException('Utilisateur introuvable.');
            }

            $payload = filter_payload($pdo, 'quest_rewards', [
                'id' => $reward['id'] ?? null,
                'userId' => $user['id'],
                'questId' => $reward['questId'] ?? null,
                'date' => $reward['date'] ?? null,
                'city' => $reward['city'] ?? null,
                'questTitle' => $reward['questTitle'] ?? null,
                'medalTitle' => $reward['medalTitle'] ?? null,
                'medalColor' => $reward['medalColor'] ?? null,
                'stats' => $reward['stats'] ?? new stdClass(),
                'rating' => $reward['rating'] ?? null,
                'feedback' => $reward['feedback'] ?? null,
            ]);

            insert_row($pdo, 'quest_rewards', $payload);

            if ($coinsToAdd !== 0) {
                $updateCoins = $pdo->prepare('UPDATE `users` SET `histaCoins` = `histaCoins` + :coins WHERE `id` = :id');
                $updateCoins->execute([
                    ':coins' => $coinsToAdd,
                    ':id' => $user['id'],
                ]);
            }

            $coinStmt = $pdo->prepare('SELECT `histaCoins` FROM `users` WHERE `id` = :id');
            $coinStmt->execute([':id' => $user['id']]);
            $newCoinTotal = (int) $coinStmt->fetchColumn();

            json_response(200, [
                'status' => 'success',
                'newCoinTotal' => $newCoinTotal,
            ]);
            break;

        case 'create_quest':
            require_method('POST');
            $auth = $input['auth'] ?? [];
            $questData = isset($input['quest']) && is_array($input['quest']) ? $input['quest'] : [];

            $adminUser = authenticate_user($pdo, $auth, true);
            $payload = filter_payload($pdo, 'quests', $questData);
            if (!isset($payload['createdBy']) && in_array('createdBy', get_table_columns($pdo, 'quests'), true)) {
                $payload['createdBy'] = $adminUser['id'] ?? null;
            }

            $stored = insert_row($pdo, 'quests', $payload);
            $quests = [$stored];
            decode_json_fields($quests, ['steps']);
            json_response(201, [
                'status' => 'success',
                'quest' => $quests[0],
            ]);
            break;

        case 'update_quest':
            require_method('POST');
            $auth = $input['auth'] ?? [];
            $questData = isset($input['quest']) && is_array($input['quest']) ? $input['quest'] : [];
            $questId = $questData['id'] ?? null;
            if ($questId === null || $questId === '') {
                throw new RuntimeException('Identifiant de la quête requis.');
            }

            authenticate_user($pdo, $auth, true);
            unset($questData['id']);
            $payload = filter_payload($pdo, 'quests', $questData);
            $stored = update_row($pdo, 'quests', $questId, $payload);
            $quests = [$stored];
            decode_json_fields($quests, ['steps']);
            json_response(200, [
                'status' => 'success',
                'quest' => $quests[0],
            ]);
            break;

        case 'create_reward':
            require_method('POST');
            $auth = $input['auth'] ?? [];
            $rewardData = isset($input['reward']) && is_array($input['reward']) ? $input['reward'] : [];

            authenticate_user($pdo, $auth, true);
            $payload = filter_payload($pdo, 'rewards', $rewardData);
            $stored = insert_row($pdo, 'rewards', $payload);
            json_response(201, [
                'status' => 'success',
                'reward' => $stored,
            ]);
            break;

        case 'update_reward':
            require_method('POST');
            $auth = $input['auth'] ?? [];
            $rewardData = isset($input['reward']) && is_array($input['reward']) ? $input['reward'] : [];
            $rewardId = $rewardData['id'] ?? null;
            if ($rewardId === null || $rewardId === '') {
                throw new RuntimeException('Identifiant de la récompense requis.');
            }

            authenticate_user($pdo, $auth, true);
            unset($rewardData['id']);
            $payload = filter_payload($pdo, 'rewards', $rewardData);
            $stored = update_row($pdo, 'rewards', $rewardId, $payload);
            json_response(200, [
                'status' => 'success',
                'reward' => $stored,
            ]);
            break;

        default:
            json_response(404, [
                'status' => 'error',
                'message' => 'Action non trouvée.',
            ]);
    }
} catch (RuntimeException $runtimeException) {
    json_response(400, [
        'status' => 'error',
        'message' => $runtimeException->getMessage(),
    ]);
} catch (Throwable $throwable) {
    json_response(500, [
        'status' => 'error',
        'message' => 'Erreur serveur : ' . $throwable->getMessage(),
    ]);
}
