<?php
require_once("../conexion/config.php");
$conexion = Conexion::conectar();


// Responder el preflight ANTES de validar el JWT
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// PARA LAS PRUEBAS UNITARIAS

require_once __DIR__ . '/../Funciones/ValidarEstudiante.php'; 

// START SESSION (idéntico al de index.php)
require "../firebase-php-jwt/vendor/autoload.php";

try {
    $decoded = Firebase\JWT\JWT::decode($token, new Firebase\JWT\Key($claveJWT, "HS256"));
    $usuario = explode("|", $decoded->sub);
    $login   = true;
}
catch (Exception $error) {
    $usuario = array();
    $login   = false;
}

if (!$login) {
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(["status" => "error", "message" => "No autorizado"]);
    exit;
}
// END SESSION


$token = "jXiPb5HnqfCG87SvAk60kRPeAtbPZC";
$url   = "http://2.24.80.205:8080/withoutJWT.php";

if ($_GET['accion'] === 'buscarMatricula' && isset($_POST['matricula'])) {
    $datos = [
        "token"     => $token,
        "matricula" => $_POST['matricula']
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($datos));

    $respuesta = curl_exec($ch);
    curl_close($ch);

    header('Content-Type: application/json');
    echo $respuesta;
    exit;
}

$accion = $_GET['accion'] ?? '';

switch ($accion) {
    case 'listar':
        $res = $conexion->query("SELECT * FROM estudiantes");
        $datos = [];
        while($fila = $res->fetch_assoc()) {
            $datos[] = $fila;
        }
        header('Content-Type: application/json');
        echo json_encode($datos);
        break;

    case 'insertar':
    $input = $_POST;
    if (empty($input)) {
        $input = json_decode(file_get_contents("php://input"), true);
    }

    $matricula = $input['matricula'] ?? null;
    $nombre    = $input['nombre'] ?? null;
    $grado     = $input['grado'] ?? null;
    $seccion   = $input['seccion'] ?? null;
    $genero    = $input['genero'] ?? null;
    $carrera   = $input['carrera'] ?? null;
    $contacto  = $input['contacto'] ?? null;

    // if ($matricula && $nombre && $grado && $seccion && $genero && $carrera && $contacto) {

    // AGREGUE ESTO PRUEBAS UNITARIAS
    if (validarDatosEstudiante($input)) {
        
        // Verificar matrícula duplicada
        $stmtCheck = $conexion->prepare("SELECT Id_estudiante FROM estudiantes WHERE Matricula = ?");
        $stmtCheck->bind_param("i", $matricula);
        $stmtCheck->execute();
        $stmtCheck->store_result();
        if ($stmtCheck->num_rows > 0) {
            echo json_encode(["status" => "error", "message" => "Ya existe un estudiante con esa matrícula"]);
            break;
        }

        $stmt = $conexion->prepare("INSERT INTO estudiantes (Matricula, Nombre, Grado, Seccion, Genero, Carrera, Contacto) VALUES (?,?,?,?,?,?,?)");
        $stmt->bind_param("ssissss", $matricula, $nombre, $grado, $seccion, $genero, $carrera, $contacto);
        $stmt->execute();
        header('Content-Type: application/json');
        echo json_encode(["status" => "success", "message" => "Estudiante insertado"]);
    } else {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
    }
    break;

    case 'estudiante':
        if (!isset($_GET['id'])) {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
            break;
        }
        $id = intval($_GET['id']);
        $stmt = $conexion->prepare("SELECT * FROM estudiantes WHERE Id_estudiante=?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $res = $stmt->get_result();
        $estudiante = $res->fetch_assoc();

        if ($estudiante) {
            header('Content-Type: application/json');
            echo json_encode($estudiante);
        } else {
            http_response_code(404);
            echo json_encode(["status" => "error", "message" => "Estudiante no encontrado"]);
        }
        break;

    case 'modificar':
        $input = $_POST;
        if (empty($input)) {
            $input = json_decode(file_get_contents("php://input"), true);
        }

        $id       = $input['Id_estudiante'] ?? null;
        $matricula= $input['matricula'] ?? null;
        $nombre   = $input['nombre'] ?? null;
        $grado    = $input['grado'] ?? null;
        $seccion  = $input['seccion'] ?? null;
        $genero   = $input['genero'] ?? null;
        $carrera  = $input['carrera'] ?? null;
        $contacto = $input['contacto'] ?? null;

        if ($id && $matricula && $nombre && $grado && $seccion && $genero && $carrera && $contacto) {
            $stmt = $conexion->prepare("UPDATE estudiantes SET Matricula=?, Nombre=?, Grado=?, Seccion=?, Genero=?, Carrera=?, Contacto=? WHERE Id_estudiante=?");
            $stmt->bind_param("ssissssi", $matricula, $nombre, $grado, $seccion, $genero, $carrera, $contacto, $id);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Estudiante modificado"]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
        }
        break;

    case 'eliminar':
        $input = $_POST;
        if (empty($input)) {
            $input = json_decode(file_get_contents("php://input"), true);
        }
        $id = $input['Id_estudiante'] ?? null;

        if ($id) {
            $stmt = $conexion->prepare("DELETE FROM estudiantes WHERE Id_estudiante=?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Estudiante eliminado"]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
        }
        break;

    case 'eliminar_varios':
    $input = json_decode(file_get_contents("php://input"), true);
    $ids = $input['ids'] ?? [];

    if (empty($ids)) {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "No se recibieron IDs"]);
        break;
    }

    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $stmt = $conexion->prepare("DELETE FROM estudiantes WHERE Id_estudiante IN ($placeholders)");
    $types = str_repeat('i', count($ids));
    $stmt->bind_param($types, ...$ids);
    $stmt->execute();

    echo json_encode(["status" => "success", "message" => count($ids) . " estudiante(s) eliminado(s)"]);
    break;

    case 'graficarGenero':
        $sql = "SELECT Genero, COUNT(*) AS Total
                FROM estudiantes
                GROUP BY Genero";

        $res = $conexion->query($sql);
        $datos = [];

        while($fila = $res->fetch_assoc()){
            $datos[] = $fila;
        }
        header('Content-Type: application/json');
        echo json_encode($datos);
        break;

    default:
        echo json_encode(["error" => "Acción no válida"]);
}
?>