<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
// header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
# mkdir kreait_firebase-php
# cd kreait_firebase-php
# composer require kreait/firebase-php 

require_once "../vendor/autoload.php";

require_once("../conexion/config.php");
$conexion = Conexion::conectar();
date_default_timezone_set('America/Matamoros');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// START SESSION
require "../vendor/autoload.php";
require_once "../php-qrcode/vendor/autoload.php";

$claveJWT = "MA-S-A-D-A-T-G-G-V-1-2-2-U------------------------------";
$headers = getallheaders();
 
$token = "";
if (isset($headers["Authorization"])) {
  $token = str_replace("Bearer ", "", $headers["Authorization"]);
}
 
try {
  $decoded = Firebase\JWT\JWT::decode($token, new Firebase\JWT\Key($claveJWT, "HS256"));
 
  # $usuario puede ser usada para validaciones
  $usuario = explode("|", $decoded->sub);
  $id      = $usuario[0];
  $usr     = $usuario[1];
  $tipo    = $usuario[2];
 
  # $login puede ser usada para validaciones
  $login = true;
}
catch (Exception $error) {
  $usuario = array();
  $login   = false;
}

if (isset($_GET["sesion"])) {
  header("Content-Type: application/json");
  echo json_encode($usuario);
  exit;
}
elseif (isset($_GET["iniciarSesion"])) {
    $QrToken        = $_GET["QRToken"] ?? null;
    $Nombre_Usuario = $_POST["txtUsuario"] ?? null;
    $Contrasena     = $_POST["txtContrasena"] ?? null;
    $PIN            = $_POST["txtPIN"] ?? null;

    $usuario = null;
    $loginValido = false;

    if (!empty($Nombre_Usuario)) {
        $stmt = $conexion->prepare("SELECT Id_Usuario, Nombre_Usuario, Tipo_Usuario, Contrasena, PIN 
                                    FROM usuarios WHERE Nombre_Usuario = ?");
        $stmt->bind_param("s", $Nombre_Usuario);
        $stmt->execute();
        $res = $stmt->get_result();
        $usuario = $res->fetch_assoc();

        if ($usuario) {
            if (!empty($Contrasena) && $usuario["Contrasena"] === $Contrasena) {
                $loginValido = true;
            } elseif (!empty($PIN) && !empty($usuario["PIN"]) && password_verify($PIN, $usuario["PIN"])) {
                $loginValido = true;
            }
        }
    } elseif (!empty($QrToken)) {

        $stmt = $conexion->prepare("
            SELECT Id_Usuario, Nombre_Usuario, Tipo_Usuario
            FROM usuarios
            WHERE Token = ?
        ");

        $stmt->bind_param("s", $QrToken);
        $stmt->execute();
        $res = $stmt->get_result();
        $usuario = $res->fetch_assoc();

        if ($usuario) {
            $loginValido = true;
            
            $stmt = $conexion->prepare("UPDATE usuarios SET Token = NULL WHERE Id_Usuario = ?");
            $stmt->bind_param("i", $usuario["Id_Usuario"]);
            $stmt->execute();
            $stmt->close();
        }
    }

    if ($loginValido) {
        $payload = [
            "iat" => time(),
            "exp" => time() + (60 * 60 * 24 * 7),
            "sub" => $usuario["Id_Usuario"] . "|" . $usuario["Nombre_Usuario"] . "|" . $usuario["Tipo_Usuario"]
        ];
        $jwt = Firebase\JWT\JWT::encode($payload, $claveJWT, "HS256");
        echo $jwt;
    } else {
        echo "error";
    }
    exit;
}
elseif (isset($_GET["confirmarQR"])) {
    header("Content-Type: application/json");

    if (!$login) {
        http_response_code(401);
        echo json_encode(["status" => "error", "message" => "Debes iniciar sesión primero"]);
        exit;
    }

    $QrToken = $_POST["QRToken"] ?? null;
    if (empty($QrToken)) {
        echo json_encode(["status" => "error", "message" => "Token requerido"]);
        exit;
    }

    $idUsuario = $id;
    $stmt = $conexion->prepare("UPDATE usuarios SET Token = ? WHERE Id_Usuario = ?");
    $stmt->bind_param("si", $QrToken, $idUsuario);
    $stmt->execute();

    if ($stmt->affected_rows > 0) {
        echo json_encode(["status" => "ok", "message" => "Sesión confirmada"]);
    } else {
        echo json_encode(["status" => "error", "message" => "No se pudo confirmar"]);
    }
    $stmt->close();
    exit;
}
elseif (isset($_GET["guardarPIN"])) {
    header("Content-Type: application/json");

    if (!isset($_POST["pin"])) {
        echo json_encode(["success" => false, "message" => "No se recibió el PIN."]);
        exit;
    }

    $pin = $_POST["pin"];

    $headers = apache_request_headers();
    $token = str_replace("Bearer ", "", $headers["Authorization"]);
    $decoded = Firebase\JWT\JWT::decode($token, new Firebase\JWT\Key($claveJWT, "HS256"));
    $partes = explode("|", $decoded->sub);
    $idUsuario = $partes[0];

    $pinHash = password_hash($pin, PASSWORD_DEFAULT);

    $stmt = $conexion->prepare("UPDATE usuarios SET PIN = ? WHERE Id_Usuario = ?");
    $stmt->bind_param("si", $pinHash, $idUsuario);

    if ($stmt->execute()) {
        echo json_encode(["success" => true, "message" => "PIN guardado correctamente."]);
    } else {
        echo json_encode(["success" => false, "message" => "Error al guardar el PIN."]);
    }

    $stmt->close();
    exit;
}
elseif (isset($_GET["eliminarPIN"])) {
    header("Content-Type: application/json");

    $headers = apache_request_headers();
    $token = str_replace("Bearer ", "", $headers["Authorization"]);
    $decoded = Firebase\JWT\JWT::decode($token, new Firebase\JWT\Key($claveJWT, "HS256"));
    $partes = explode("|", $decoded->sub);
    $idUsuario = $partes[0];

    $stmt = $conexion->prepare("UPDATE usuarios SET PIN = NULL WHERE Id_Usuario = ?");
    $stmt->bind_param("i", $idUsuario);

    if ($stmt->execute()) {
        echo json_encode(["success" => true, "message" => "PIN eliminado correctamente."]);
    } else {
        echo json_encode(["success" => false, "message" => "Error al eliminar el PIN."]);
    }

    $stmt->close();
    exit;
}
// END SESSION
elseif (isset($_GET["qrIniciarSesion"])) {
    $token = uniqid();

    $protocolo = (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off") ? "https" : "http";
    $host      = $_SERVER["HTTP_HOST"];
    $urlBase   = "https://emotional-milk-shepherd-supplement.trycloudflare.com";

    $url = "$urlBase/Usuarios/login.html?QRToken=$token";

    header("Content-Type: application/json");
    echo json_encode([
        "src"   => (new chillerlan\QRCode\QRCode)->render($url),
        "token" => $token,
        "url" => $url
    ]);
    exit;
}

if (!$login) {
    $accionActual   = $_GET["accion"] ?? "";
    $claveCron      = $_GET["clave"] ?? null;
    $claveCronReal  = "Cron-Job-prestamos-abc123xyz";

    $esCronAutorizado = ($accionActual === "notificacionPrestamos" && $claveCron === $claveCronReal);

    if (!$esCronAutorizado) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(["status" => "error", "message" => "No autorizado"]);
        exit;
    }

}

$accion = $_GET['accion'] ?? '';

switch ($accion) {
    case 'notificacionPrestamos':
    $result = $conexion->query("
        SELECT Id_prestamo, Estudiante, Fecha_devolucion, Fecha_entrega
        FROM prestamos
        WHERE Estado = 'Pendiente'
    ");

    $prestamos = [];
    while ($row = $result->fetch_assoc()) {
        $prestamos[] = $row;
    }

    $cantidad = count($prestamos);

    $tokens = $conexion->query("SELECT token FROM fbtokens");

    while ($tk = $tokens->fetch_assoc()) {
        if ($cantidad == 0) {
            $message = [
                "token" => $tk['token'],
                "notification" => [
                    "title" => "Biblioteca",
                    "body" => "No hay préstamos pendientes actualmente."
                ]
            ];
            $firebase->send($message);
        }
        elseif ($cantidad >= 20) {
            $message = [
                "token" => $tk['token'],
                "notification" => [
                    "title" => "¡Atención!",
                    "body" => "Hay demasiados prestamos pendientes: {$cantidad}"
                ]
            ];
            $firebase->send($message);
        }
        elseif ($cantidad <= 5) {
            $message = [
                "token" => $tk['token'],
                "notification" => [
                    "title" => "Biblioteca",
                    "body" => "Hay {$cantidad} préstamos pendientes actualmente."
                ]
            ];
            $firebase->send($message);
        }
        else {
            $message = [
                "token" => $tk['token'],
                "notification" => [
                    "title" => "Biblioteca",
                    "body" => "Actualmente hay {$cantidad} préstamos pendientes."
                ]
            ];
            $firebase->send($message);
        }
    }

    header('Content-Type: application/json');
    echo json_encode([
        "status" => "ok",
        "pendientes" => $cantidad
    ]);
    break;
    
    case 'insertarToken':
        $input = json_decode(file_get_contents("php://input"), true);
        $token = $input['fbtoken'] ?? null;

        if ($token) {
            $stmt = $conexion->prepare("
                INSERT INTO fbtokens (token, fechaHora) 
                VALUES (?, NOW())
                ON DUPLICATE KEY UPDATE fechaHora = NOW()
            ");
            $stmt->bind_param("s", $token);
            $stmt->execute();
            echo json_encode(["status" => "success", "message" => "Token guardado"]);
        } else {
            echo json_encode(["status" => "error", "message" => "Token requerido"]);
        }
        break;

    case 'buscar_estudiantes':
    $matricula = $_GET['matricula'] ?? '';
    $stmt = $conexion->prepare("
        SELECT
            Id_estudiante,
            Nombre,
            Matricula,
            Grado,
            Seccion,
            Genero,
            Carrera,
            Contacto
        FROM estudiantes
        WHERE Matricula LIKE ?
        LIMIT 10
    ");

    $busqueda = "%".$matricula."%";
    $stmt->bind_param("s", $busqueda);
    $stmt->execute();
    $resultado = $stmt->get_result();
    $datos = [];
    while($fila = $resultado->fetch_assoc()){
        $datos[] = $fila;
    }
    header('Content-Type: application/json');
    echo json_encode($datos);
    break;

    case 'listar':
        $res = $conexion->query("SELECT * FROM carreras");
        $datos = [];
        while($fila = $res->fetch_assoc()) {
            $datos[] = $fila;
        }
        header('Content-Type: application/json');
        echo json_encode($datos);
        break;
    
    // ----- PRESTAMOS CON JOIN A ESTUDIANTES -----
    case 'prestamos':
        $sql = "
            SELECT
                p.Id_prestamo,
                e.Matricula AS Estudiante,
                p.Fecha_prestamo,
                p.Fecha_entrega,
                p.Fecha_devolucion,
                p.Estado
            FROM prestamos p
            INNER JOIN estudiantes e
                ON p.Estudiante = e.Id_estudiante
        ";
        $res = $conexion->query($sql);
        $datos = [];
        while($fila = $res->fetch_assoc()){
            $datos[] = $fila;
        }
        header('Content-Type: application/json');
        echo json_encode($datos);
        break;

        // ----- INSERTAR PRÉSTAMOS -----
    case 'insertar_prestamo':
        $input = $_POST;
        if (empty($input)) {
            $input = json_decode(file_get_contents("php://input"), true);
        }

        $estudiante = $input['estudiante'] ?? null;
        $fecha_prestamo = date('Y-m-d');
        $fecha_entrega = $input['fecha_entrega'] ?? null;
        $fecha_devolucion = $input['fecha_devolucion'] ?? null;
        $estado   = $input['estado'] ?? null;

        if ($estudiante && $fecha_entrega && $fecha_devolucion && $estado) {
            $stmt = $conexion->prepare("INSERT INTO prestamos (Estudiante, Fecha_prestamo, Fecha_entrega, Fecha_devolucion, Estado) VALUES (?,?,?,?,?)");
            $stmt->bind_param("issss", $estudiante, $fecha_prestamo, $fecha_entrega, $fecha_devolucion, $estado);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Prestamo insertado"]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
        }
        break;

    // ----- MODIFICAR PRESTAMOS -----
    case 'modificar_prestamo':
        $input = $_POST;
        if (empty($input)) {
            $input = json_decode(file_get_contents("php://input"), true);
        }

        $id_prestamo = $input['id_prestamo'] ?? null;
        $estudiante = $input['estudiante'] ?? null;
        $fecha_prestamo   = $input['fecha_prestamo'] ?? null;
        $fecha_entrega = $input['fecha_entrega'] ?? null;
        $fecha_devolucion = $input['fecha_devolucion'] ?? null;
        $estado   = $input['estado'] ?? null;

        if ($id_prestamo && $estudiante && $fecha_prestamo && $fecha_entrega && $fecha_devolucion && $estado) {
            $stmt = $conexion->prepare("UPDATE prestamos SET Estudiante=?, Fecha_prestamo=?, Fecha_entrega=?, Fecha_devolucion=?, Estado=? WHERE Id_prestamo=?");
            $stmt->bind_param("issssi", $estudiante, $fecha_prestamo, $fecha_entrega, $fecha_devolucion, $estado, $id_prestamo);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Prestamo modificado"]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
        }
        break;

    // ----- ELIMINAR PRÉSTAMOS -----
    case 'eliminar_prestamo':
        $id = $_POST['id_prestamo'] ?? null;
        if ($id) {
            // Primero eliminar detalles
            $stmt = $conexion->prepare("DELETE FROM detalle_prestamos WHERE Prestamo = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();

            // Luego eliminar historial
            $stmt = $conexion->prepare("DELETE FROM historial_prestamos WHERE Prestamo = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();

            // Finalmente eliminar el préstamo
            $stmt = $conexion->prepare("DELETE FROM prestamos WHERE Id_prestamo = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();

            echo json_encode(["status" => "success", "message" => "Préstamo eliminado"]);
        }
    break;

    case 'eliminar_varios_prestamos':
        $input = json_decode(file_get_contents("php://input"), true);
        $ids = $input['ids'] ?? [];
        if (empty($ids)) { echo json_encode(["status"=>"error","message"=>"No se recibieron IDs"]); break; }
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $conexion->prepare("DELETE FROM detalle_prestamos WHERE Prestamo IN ($placeholders)");
        $stmt->bind_param(str_repeat('i', count($ids)), ...$ids);
        $stmt->execute();
        $stmt = $conexion->prepare("DELETE FROM historial_prestamos WHERE Prestamo IN ($placeholders)");
        $stmt->bind_param(str_repeat('i', count($ids)), ...$ids);
        $stmt->execute();
        $stmt = $conexion->prepare("DELETE FROM prestamos WHERE Id_prestamo IN ($placeholders)");
        $stmt->bind_param(str_repeat('i', count($ids)), ...$ids);
        $stmt->execute();
        echo json_encode(["status"=>"success","message"=>count($ids)." préstamo(s) eliminado(s)"]);
        break;
    

    // ----- OBTENER UN PRÉSTAMO POR ID -----
    case 'get_prestamo':
            if (!isset($_GET['id'])) {
                http_response_code(400);
                echo json_encode(["status" => "error", "message" => "ID requerido"]);
                break;
            }
            $id   = intval($_GET['id']);
            $stmt = $conexion->prepare("SELECT p.*, e.Matricula FROM prestamos p INNER JOIN estudiantes e ON p.Estudiante = e.Id_estudiante WHERE p.Id_prestamo = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $res      = $stmt->get_result();
            $prestamo = $res->fetch_assoc();
    
            if ($prestamo) {
                header('Content-Type: application/json');
                echo json_encode($prestamo);
            } else {
                http_response_code(404);
                echo json_encode(["status" => "error", "message" => "Prestamo no encontrado"]);
            }
            break;

    case 'insertar':
        $nombre = null;
        if (isset($_POST['Nombre'])) {
            $nombre = $_POST['Nombre'];
        } else {
            $input = json_decode(file_get_contents("php://input"), true);
            $nombre = $input['Nombre'] ?? null;
        }

        if ($nombre) {
            $stmt = $conexion->prepare("INSERT INTO carreras (Nombre) VALUES (?)");
            $stmt->bind_param("s", $nombre);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Carrera insertada"]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Nombre requerido"]);
        }
        break;


    case 'carrera':
        if (!isset($_GET['id'])) {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
            break;
        }
        $id = intval($_GET['id']);
        $stmt = $conexion->prepare("SELECT * FROM carreras WHERE Id_carrera=?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $res = $stmt->get_result();
        $carrera = $res->fetch_assoc();

        if ($carrera) {
            header('Content-Type: application/json');
            echo json_encode($carrera);
        } else {
            http_response_code(404);
            echo json_encode(["status" => "error", "message" => "Carrera no encontrada"]);
        }
        break;

    case 'modificar':
        $id = null; $nombre = null;
        if (isset($_POST['Id_carrera'])) {
            $id = $_POST['Id_carrera'];
            $nombre = $_POST['Nombre'];
        } else {
            $input = json_decode(file_get_contents("php://input"), true);
            $id = $input['Id_carrera'] ?? null;
            $nombre = $input['Nombre'] ?? null;
        }

        if ($id && $nombre) {
            $stmt = $conexion->prepare("UPDATE carreras SET Nombre=? WHERE Id_carrera=?");
            $stmt->bind_param("si", $nombre, $id);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Carrera modificada"]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
        }
        break;

    case 'eliminar':
        $id = null;
        if (isset($_POST['Id_carrera'])) {
            $id = $_POST['Id_carrera'];
        } else {
            $input = json_decode(file_get_contents("php://input"), true);
            $id = $input['Id_carrera'] ?? null;
        }

        if ($id) {
            $stmt = $conexion->prepare("DELETE FROM carreras WHERE Id_carrera=?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Carrera eliminada"]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
        }
        break;

        // ----- SERVICIOS -----
    case 'listar_servicios':
            $res = $conexion->query("SELECT * FROM servicios");
            $datos = [];
            while ($fila = $res->fetch_assoc()) {
                $datos[] = $fila;
            }
            header('Content-Type: application/json');
            echo json_encode($datos);
            break;
    
        // ----- INSERTAR SERVICIO -----
    case 'insertar_servicio':
            $nombre = null;
            if (isset($_POST['Nombre'])) {
                $nombre = $_POST['Nombre'];
            } else {
                $input  = json_decode(file_get_contents("php://input"), true);
                $nombre = $input['Nombre'] ?? null;
            }
    
            if ($nombre) {
                $stmt = $conexion->prepare("INSERT INTO servicios (Nombre) VALUES (?)");
                $stmt->bind_param("s", $nombre);
                $stmt->execute();
                header('Content-Type: application/json');
                echo json_encode(["status" => "success", "message" => "Servicio insertado"]);
            } else {
                http_response_code(400);
                echo json_encode(["status" => "error", "message" => "Nombre requerido"]);
            }
            break;
    
        // ----- OBTENER UN SERVICIO POR ID -----
    case 'get_servicio':
            if (!isset($_GET['id'])) {
                http_response_code(400);
                echo json_encode(["status" => "error", "message" => "ID requerido"]);
                break;
            }
            $id   = intval($_GET['id']);
            $stmt = $conexion->prepare("SELECT * FROM servicios WHERE Id_servicio = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $res      = $stmt->get_result();
            $servicio = $res->fetch_assoc();
    
            if ($servicio) {
                header('Content-Type: application/json');
                echo json_encode($servicio);
            } else {
                http_response_code(404);
                echo json_encode(["status" => "error", "message" => "Servicio no encontrado"]);
            }
            break;
    
        // ----- MODIFICAR SERVICIO -----
    case 'modificar_servicio':
            $id = null; $nombre = null;
            if (isset($_POST['Id_servicio'])) {
                $id     = $_POST['Id_servicio'];
                $nombre = $_POST['Nombre'];
            } else {
                $input  = json_decode(file_get_contents("php://input"), true);
                $id     = $input['Id_servicio'] ?? null;
                $nombre = $input['Nombre']      ?? null;
            }
    
            if ($id && $nombre) {
                $stmt = $conexion->prepare("UPDATE servicios SET Nombre = ? WHERE Id_servicio = ?");
                $stmt->bind_param("si", $nombre, $id);
                $stmt->execute();
                header('Content-Type: application/json');
                echo json_encode(["status" => "success", "message" => "Servicio modificado"]);
            } else {
                http_response_code(400);
                echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
            }
            break;

        // ----- ELIMINAR SERVICIO -----
    case 'eliminar_servicio':
            $id = null;
            if (isset($_POST['Id_servicio'])) {
                $id = $_POST['Id_servicio'];
            } else {
                $input = json_decode(file_get_contents("php://input"), true);
                $id    = $input['Id_servicio'] ?? null;
            }
    
            if ($id) {
                $stmt = $conexion->prepare("DELETE FROM servicios WHERE Id_servicio = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                header('Content-Type: application/json');
                echo json_encode(["status" => "success", "message" => "Servicio eliminado"]);
            } else {
                http_response_code(400);
                echo json_encode(["status" => "error", "message" => "ID requerido"]);
            }
            break;

    case 'eliminar_varios_servicios':
        $input = json_decode(file_get_contents("php://input"), true);
        $ids = $input['ids'] ?? [];
        if (empty($ids)) { echo json_encode(["status"=>"error","message"=>"No se recibieron IDs"]); break; }
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $conexion->prepare("DELETE FROM servicios WHERE Id_servicio IN ($placeholders)");
        $stmt->bind_param(str_repeat('i', count($ids)), ...$ids);
        $stmt->execute();
        echo json_encode(["status"=>"success","message"=>count($ids)." servicio(s) eliminado(s)"]);
        break;

    // ----- LIBROS -----
    case 'listar_libro':
        $res   = $conexion->query("SELECT * FROM libros");
        $datos = [];
        while ($fila = $res->fetch_assoc()) {
            $datos[] = $fila;
        }
        header('Content-Type: application/json');
        echo json_encode($datos);
        break;

    // ----- INSERTAR LIBRO -----
    case 'insertar_libro':
        $data = $_POST;
        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true) ?? [];
        }

        $titulo    = $data['Titulo']                   ?? null;
        $fecha_edi = $data['Fecha_edicion']            ?? null;
        $autores   = $data['Autores']                  ?? null;
        $res_cus   = $data['Responsable_custodia']     ?? null;
        $dep_res   = $data['Departamento_responsable'] ?? null;
        $tipo      = $data['Tipo']                     ?? null;
        $editora   = $data['Editora']                  ?? null;
        $isbn      = $data['ISBN']                     ?? null;
        $area      = $data['Area']                     ?? null;
        $cantidad  = $data['Cantidad']                 ?? null;

        if ($titulo && $fecha_edi && $autores && $res_cus && $dep_res && $tipo && $editora && $isbn && $area && $cantidad) {
            $stmt = $conexion->prepare("
                INSERT INTO libros (Titulo, Fecha_edicion, Autores, Responsable_custodia, Departamento_responsable, Tipo, Editora, ISBN, Area, Cantidad)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            $stmt->bind_param("sssssssssi", $titulo, $fecha_edi, $autores, $res_cus, $dep_res, $tipo, $editora, $isbn, $area, $cantidad);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Libro insertado"]);
        } else {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(["status" => "error", "message" => "Error al registrar el libro"]);
        }
        break;

    // ----- OBTENER UN LIBRO POR ID -----
    case 'get_libro':
        if (!isset($_GET['id'])) {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
            break;
        }

        $id   = intval($_GET['id']);
        $stmt = $conexion->prepare("SELECT * FROM libros WHERE Id_libro = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $res   = $stmt->get_result();
        $libro = $res->fetch_assoc();

        if ($libro) {
            header('Content-Type: application/json');
            echo json_encode($libro);
        } else {
            http_response_code(404);
            echo json_encode(["status" => "error", "message" => "Libro no encontrado"]);
        }
        break;

    // ----- MODIFICAR LIBRO -----
    case 'modificar_libro':
        $data = $_POST;
        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true) ?? [];
        }

        $id        = $data['Id_libro']                 ?? null;
        $titulo    = $data['Titulo']                   ?? null;
        $fecha_edi = $data['Fecha_edicion']            ?? null;
        $autores   = $data['Autores']                  ?? null;
        $res_cus   = $data['Responsable_custodia']     ?? null;
        $dep_res   = $data['Departamento_responsable'] ?? null;
        $tipo      = $data['Tipo']                     ?? null;
        $editora   = $data['Editora']                  ?? null;
        $isbn      = $data['ISBN']                     ?? null;
        $area      = $data['Area']                     ?? null;
        $cantidad  = $data['Cantidad']                 ?? null;

        if ($id && $titulo && $fecha_edi && $autores && $res_cus && $dep_res && $tipo && $editora && $isbn && $area && $cantidad) {
            $stmt = $conexion->prepare("
                UPDATE libros
                SET Titulo = ?, Fecha_edicion = ?, Autores = ?, Responsable_custodia = ?,
                    Departamento_responsable = ?, Tipo = ?, Editora = ?, ISBN = ?, Area = ?, Cantidad = ?
                WHERE Id_libro = ?
            ");
            $stmt->bind_param("sssssssssii", $titulo, $fecha_edi, $autores, $res_cus, $dep_res, $tipo, $editora, $isbn, $area, $cantidad, $id);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Libro modificado"]);
        } else {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
        }
        break;

    // ----- ELIMINAR LIBRO -----
    case 'eliminar_libro':
        $id = null;
        if (isset($_POST['Id_libro'])) {
            $id = $_POST['Id_libro'];
        } else {
            $input = json_decode(file_get_contents("php://input"), true);
            $id    = $input['Id_libro'] ?? null;
        }

        if ($id) {
            $stmt = $conexion->prepare("DELETE FROM libros WHERE Id_libro = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Libro eliminado"]);
        } else {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
        }
        break;

    case 'eliminar_varios_libros':
        $input = json_decode(file_get_contents("php://input"), true);
        $ids = $input['ids'] ?? [];
        if (empty($ids)) { echo json_encode(["status"=>"error","message"=>"No se recibieron IDs"]); break; }
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $conexion->prepare("DELETE FROM libros WHERE Id_libro IN ($placeholders)");
        $stmt->bind_param(str_repeat('i', count($ids)), ...$ids);
        $stmt->execute();
        echo json_encode(["status"=>"success","message"=>count($ids)." libro(s) eliminado(s)"]);
        break;
    
    // ----- Historial Prestamos -----
    case 'listar_HistorialP':
        $res   = $conexion->query("SELECT historial_prestamos.Id_historial, estudiantes.Nombre, historial_prestamos.Descripcion, historial_prestamos.Fecha, historial_prestamos.Estado FROM historial_prestamos INNER JOIN prestamos ON historial_prestamos.Prestamo = prestamos.Id_prestamo INNER JOIN estudiantes ON prestamos.Estudiante = estudiantes.Id_estudiante");
        $datos = [];
        while ($fila = $res->fetch_assoc()) {
            $datos[] = $fila;
        }
        header('Content-Type: application/json');
        echo json_encode($datos);
        break;

    // ----- INSERTAR HistorialP -----
    case 'insertar_HistorialP':
        $data = $_POST;
        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true) ?? [];
        }

        $prestamo    = $data['Prestamo']     ?? null;
        $descripcion = $data['Descripcion']  ?? null;
        $fecha       = $data['Fecha']        ?? null;
        $estado      = $data['Estado']       ?? null;

        if ($prestamo && $descripcion && $fecha && $estado) {
            $stmt = $conexion->prepare("
                INSERT INTO historial_prestamos (Prestamo, Descripcion, Fecha, Estado)
                VALUES (?, ?, ?, ?)
            ");
            $stmt->bind_param("isss", $prestamo, $descripcion, $fecha, $estado);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Historial de préstamo insertado"]);
        } else {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(["status" => "error", "message" => "Error al registrar el historial de préstamo"]);
        }
        break;
    
    // Select de Id prestamos
    case 'listar_prestamos_select':
    $res = $conexion->query("
        SELECT prestamos.Id_prestamo, estudiantes.Nombre
        FROM prestamos
        INNER JOIN estudiantes ON prestamos.Estudiante = estudiantes.Id_estudiante
    ");
    $datos = [];
    while ($fila = $res->fetch_assoc()) {
        $datos[] = $fila;
    }
    header('Content-Type: application/json');
    echo json_encode($datos);
    break;

    // ----- OBTENER UN HISTORIAL DE PRESTAMO POR ID -----
    case 'get_HistorialP':
        if (!isset($_GET['id'])) {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
            break;
        }

        $id   = intval($_GET['id']);
        $stmt = $conexion->prepare("SELECT * FROM historial_prestamos WHERE Id_historial = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $res   = $stmt->get_result();
        $Historial = $res->fetch_assoc();

        if ($Historial) {
            header('Content-Type: application/json');
            echo json_encode($Historial);
        } else {
            http_response_code(404);
            echo json_encode(["status" => "error", "message" => "Historial de préstamo no encontrado"]);
        }
        break;

    // ----- MODIFICAR HISTORIAL PRESTAMO -----
    case 'modificar_HistorialP':
        $data = $_POST;
        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true) ?? [];
        }

        $id          = $data['Id_historial'] ?? null;
        $prestamo    = $data['Prestamo']     ?? null;
        $descripcion = $data['Descripcion']  ?? null;
        $fecha       = $data['Fecha']        ?? null;
        $estado      = $data['Estado']       ?? null;

        if ($id && $prestamo && $descripcion && $fecha && $estado) {
            $stmt = $conexion->prepare("
                UPDATE historial_prestamos
                SET Prestamo = ?, Descripcion = ?, Fecha = ?, Estado = ? 
                WHERE Id_historial = ?
            ");
            $stmt->bind_param("isssi", $prestamo, $descripcion, $fecha, $estado, $id);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Historial de préstamo modificado"]);
        } else {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
        }
        break;

    //  ----- ELIMINAR HistorialP -----
    case 'eliminar_HistorialP':
        $id = null;
        if (isset($_POST['Id_historial'])) {
            $id = $_POST['Id_historial'];
        } else {
            $input = json_decode(file_get_contents("php://input"), true);
            $id    = $input['Id_historial'] ?? null;
        }

        if ($id) {
            $stmt = $conexion->prepare("DELETE FROM historial_prestamos WHERE Id_historial = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Historial de préstamo eliminado"]);
        } else {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
        }
        break;    

    case 'eliminar_varios_historialP':
        $input = json_decode(file_get_contents("php://input"), true);
        $ids = $input['ids'] ?? [];
        if (empty($ids)) { echo json_encode(["status"=>"error","message"=>"No se recibieron IDs"]); break; }
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $conexion->prepare("DELETE FROM historial_prestamos WHERE Id_historial IN ($placeholders)");
        $stmt->bind_param(str_repeat('i', count($ids)), ...$ids);
        $stmt->execute();
        echo json_encode(["status"=>"success","message"=>count($ids)." reporte(s) eliminado(s)"]);
        break;

    // ----- DETALLE PRESTAMOS -----
    case 'listar_DetalleP':
        $res   = $conexion->query("SELECT detalle_prestamos.Id_detalle_prestamo, estudiantes.Nombre, libros.Titulo, detalle_prestamos.Cantidad FROM detalle_prestamos INNER JOIN prestamos ON detalle_prestamos.Prestamo = prestamos.Id_prestamo INNER JOIN estudiantes ON prestamos.Estudiante = estudiantes.Id_estudiante INNER JOIN libros ON detalle_prestamos.Libro = libros.Id_libro");
        $datos = [];
        while ($fila = $res->fetch_assoc()) {
            $datos[] = $fila;
        }
        header('Content-Type: application/json');
        echo json_encode($datos);
        break;

    // ----- INSERTAR DETALLE PRESTAMOS -----
    case 'insertar_DetalleP':
        $data = $_POST;
        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true) ?? [];
        }

        $prestamo   = $data['Prestamo']   ?? null;
        $libro      = $data['Libro']      ?? null;
        $cantidad   = $data['Cantidad']   ?? null;

        if ($prestamo && $libro && $cantidad) {
            $stmt = $conexion->prepare("
                INSERT INTO detalle_prestamos (Prestamo, Libro, Cantidad)
                VALUES (?, ?, ?)
            ");
            $stmt->bind_param("iii", $prestamo, $libro, $cantidad);

            $stmt->execute();

            // NOTI DETALLE PRESTAMO
            $stmtNombre = $conexion->prepare("
                SELECT e.Nombre
                FROM prestamos p
                INNER JOIN estudiantes e
                    ON p.Estudiante = e.Id_estudiante
                WHERE p.Id_prestamo = ?
            ");

            $stmtNombre->bind_param("i", $prestamo);
            $stmtNombre->execute();

            $resNombre = $stmtNombre->get_result();
            $datosNombre = $resNombre->fetch_assoc();

            $nombreEstudiante = $datosNombre['Nombre'] ?? 'Estudiante';
            // Contar libros del préstamo
            $stmtTotal = $conexion->prepare("
                SELECT SUM(Cantidad) AS total
                FROM detalle_prestamos
                WHERE Prestamo = ?
            ");
            $stmtTotal->bind_param("i", $prestamo);
            $stmtTotal->execute();
            $resultado = $stmtTotal->get_result();
            $fila = $resultado->fetch_assoc();
            $totalLibros = $fila['total'] ?? 0;

            header('Content-Type: application/json');

            // COMPARACIÓN
            if ($totalLibros >= 5) {

            $tokens = $conexion->query("SELECT token FROM fbtokens");

                while ($tk = $tokens->fetch_assoc()) {

                    $message = [
                        "token" => $tk['token'],
                        "notification" => [
                            "title" => "Préstamo grande",
                            "body" => "{$nombreEstudiante} registró un préstamo de {$totalLibros} libros."
                        ]
                    ];

                    $firebase->send($message);
                    
                }
            }
            echo json_encode(["status" => "success", "message" => "Detalle de préstamo insertado"]);
        } else {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(["status" => "error", "message" => "Error al registrar el detalle de préstamo"]);
        }
        break;

    // ----- OBTENER UN HISTORIAL DE PRESTAMO POR ID -----
    case 'get_DetalleP':
        if (!isset($_GET['id'])) {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
            break;
        }

        $id   = intval($_GET['id']);
        $stmt = $conexion->prepare("SELECT * FROM detalle_prestamos WHERE Id_detalle_prestamo = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $res   = $stmt->get_result();
        $Detalle = $res->fetch_assoc();

        if ($Detalle) {
            header('Content-Type: application/json');
            echo json_encode($Detalle);
        } else {
            http_response_code(404);
            echo json_encode(["status" => "error", "message" => "Detalle de préstamo no encontrado"]);
        }
        break;

    // ----- MODIFICAR DETALLE PRESTAMO -----
    case 'modificar_DetalleP':
        $data = $_POST;
        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true) ?? [];
        }

        $id          = $data['Id_detalle_prestamo']  ?? null;
        $prestamo    = $data['Prestamo']             ?? null;
        $libro       = $data['Libro']                ?? null;
        $cantidad    = $data['Cantidad']             ?? null;

        if ($id && $prestamo && $libro && $cantidad) {
            $stmt = $conexion->prepare("
                UPDATE detalle_prestamos
                SET Prestamo = ?, Libro = ?, Cantidad = ?
                WHERE Id_detalle_prestamo = ?
            ");
            $stmt->bind_param("iiii", $prestamo, $libro, $cantidad, $id);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Detalle de préstamo modificado"]);
        } else {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
        }
        break;

    
    //  ----- ELIMINAR DETALLE PRESTAMO -----
    case 'eliminar_DetalleP':
        $id = null;
        if (isset($_POST['Id_detalle_prestamo'])) {
            $id = $_POST['Id_detalle_prestamo'];
        } else {
            $input = json_decode(file_get_contents("php://input"), true);
            $id    = $input['Id_detalle_prestamo'] ?? null;
        }

        if ($id) {
            $stmt = $conexion->prepare("DELETE FROM detalle_prestamos WHERE Id_detalle_prestamo = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Detalle de préstamo eliminado"]);
        } else {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
        }
        break;   

    case 'eliminar_varios_detalleP':
        $input = json_decode(file_get_contents("php://input"), true);
        $ids = $input['ids'] ?? [];
        if (empty($ids)) { echo json_encode(["status"=>"error","message"=>"No se recibieron IDs"]); break; }
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $conexion->prepare("DELETE FROM detalle_prestamos WHERE Id_detalle_prestamo IN ($placeholders)");
        $stmt->bind_param(str_repeat('i', count($ids)), ...$ids);
        $stmt->execute();
        echo json_encode(["status"=>"success","message"=>count($ids)." detalle(s) eliminado(s)"]);
        break;    

    // ----- USUARIOS -----
    case 'listar_Usuarios':
        $res   = $conexion->query("SELECT usuarios.Id_Usuario, usuarios.Nombre_Usuario, usuarios.Contrasena, usuarios.PIN, usuarios.Token FROM usuarios");
        $datos = [];
        while ($fila = $res->fetch_assoc()) {
            $datos[] = $fila;
        }
        header('Content-Type: application/json');
        echo json_encode($datos);
        break;

    // ----- INSERTAR USUARIO -----
    case 'insertar_usuario':
        $data = $_POST;
        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true) ?? [];
        }

        $nombre_usuario = $data['Nombre_Usuario'] ?? null;
        $contrasena     = $data['Contrasena']     ?? null;
        $tipo_usuario = 1;
        

        if ($nombre_usuario && $contrasena && $tipo_usuario) {
            $stmt = $conexion->prepare("
                INSERT INTO usuarios (Nombre_Usuario, Contrasena, Tipo_Usuario)
                VALUES (?, ?, ?)
            ");
            $stmt->bind_param("ssi", $nombre_usuario, $contrasena, $tipo_usuario);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Usuario insertado"]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Todos los campos son requeridos"]);
        }
        break;

    case 'get_usuario':
        $id = intval($_GET['id']);
        $stmt = $conexion->prepare("SELECT * FROM usuarios WHERE Id_Usuario = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $res = $stmt->get_result();
        echo json_encode($res->fetch_assoc());
        break;

    case 'modificar_usuario':
        $data = $_POST;
        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true) ?? [];
        }

        $id             = $data['Id_Usuario']     ?? null;
        $nombre_usuario = $data['Nombre_Usuario'] ?? null;
        $contrasena     = $data['Contrasena']     ?? null;
        $tipo_usuario = 1;

        if ($id && $nombre_usuario && $contrasena && $tipo_usuario) {
            $stmt = $conexion->prepare("
                UPDATE usuarios SET Nombre_Usuario=?, Contrasena=?, Tipo_Usuario=?
                WHERE Id_Usuario=?
            ");
            $stmt->bind_param("ssii", $nombre_usuario, $contrasena, $tipo_usuario, $id);
            $stmt->execute();
            echo json_encode(["status" => "success", "message" => "Usuario modificado"]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
        }
        break;

    case 'eliminar_usuario':
        $data = $_POST;
        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true) ?? [];
        }
        $id = $data['Id_Usuario'] ?? null;
        if ($id) {
            $stmt = $conexion->prepare("DELETE FROM usuarios WHERE Id_Usuario = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            echo json_encode(["status" => "success", "message" => "Usuario eliminado"]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
        }
        break;

    case 'eliminar_varios_usuarios':
        $input = json_decode(file_get_contents("php://input"), true);
        $ids = $input['ids'] ?? [];
        if (empty($ids)) { echo json_encode(["status"=>"error","message"=>"No se recibieron IDs"]); break; }
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $conexion->prepare("DELETE FROM usuarios WHERE Id_Usuario IN ($placeholders)");
        $stmt->bind_param(str_repeat('i', count($ids)), ...$ids);
        $stmt->execute();
        echo json_encode(["status"=>"success","message"=>count($ids)." usuario(s) eliminado(s)"]);
        break;

// ----- VISITAS -----
    case 'listar_Visitas':
        $res   = $conexion->query("SELECT entrada_salida.Id_entrada_salida, estudiantes.Nombre AS NE, servicios.Nombre AS NS, entrada_salida.Fecha,entrada_salida.Hora_entrada,entrada_salida.Hora_salida FROM entrada_salida INNER JOIN estudiantes ON entrada_salida.Estudiante = estudiantes.Id_estudiante INNER JOIN servicios ON entrada_salida.Servicio = servicios.Id_servicio");
        $datos = [];
        while ($fila = $res->fetch_assoc()) {
            $datos[] = $fila;
        }
        header('Content-Type: application/json');
        echo json_encode($datos);
        break;

    //  ----- ELIMINAR Visitas -----
    case 'eliminar_Visitas':
        $id = null;
        if (isset($_POST['Id_entrada_salida'])) {
            $id = $_POST['Id_entrada_salida'];
        } else {
            $input = json_decode(file_get_contents("php://input"), true);
            $id    = $input['Id_entrada_salida'] ?? null;
        }

        if ($id) {
            $stmt = $conexion->prepare("DELETE FROM entrada_salida WHERE Id_entrada_salida = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Visita eliminada"]);
        } else {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
        }
        break;    

    case 'eliminar_varios_visitas':
        $input = json_decode(file_get_contents("php://input"), true);
        $ids = $input['ids'] ?? [];
        if (empty($ids)) { echo json_encode(["status"=>"error","message"=>"No se recibieron IDs"]); break; }
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $conexion->prepare("DELETE FROM entrada_salida WHERE Id_entrada_salida IN ($placeholders)");
        $stmt->bind_param(str_repeat('i', count($ids)), ...$ids);
        $stmt->execute();
        echo json_encode(["status"=>"success","message"=>count($ids)." visita(s) eliminada(s)"]);
        break;

    // ----- VERIFICAR ESTUDIANTE POR MATRÍCULA -----
    case 'verificar_estudiante':
        $matricula = $_GET['matricula'] ?? null;

        if (!$matricula) {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Matrícula requerida"]);
            break;
        }

        $stmt = $conexion->prepare("SELECT Id_estudiante, Nombre FROM estudiantes WHERE Matricula = ?");
        $stmt->bind_param("i", $matricula);
        $stmt->execute();
        $res = $stmt->get_result();
        $estudiante = $res->fetch_assoc();

        if (!$estudiante) {
            http_response_code(404);
            echo json_encode(["status" => "error", "message" => "Estudiante no encontrado"]);
            break;
        }

        $id    = $estudiante['Id_estudiante'];
        $fecha = date('Y-m-d');

        // cierre automatico
        $stmt0 = $conexion->prepare("
            UPDATE entrada_salida 
            SET Hora_salida = '23:59:59'
            WHERE Estudiante = ? AND Fecha < ? AND Hora_salida IS NULL
        ");
        $stmt0->bind_param("is", $id, $fecha);
        $stmt0->execute();

        // entrada pendiente HOY
        $stmt2 = $conexion->prepare("
            SELECT Id_entrada_salida FROM entrada_salida
            WHERE Estudiante = ? AND Fecha = ? AND Hora_salida IS NULL
        ");
        $stmt2->bind_param("is", $id, $fecha);
        $stmt2->execute();
        $res2  = $stmt2->get_result();
        $entrada = $res2->fetch_assoc();

        header('Content-Type: application/json');
        echo json_encode([
            "status"            => "success",
            "Id_estudiante"     => $id,
            "Nombre"            => $estudiante['Nombre'],
            "tiene_entrada"     => $entrada ? true : false,
            "Id_entrada_salida" => $entrada['Id_entrada_salida'] ?? null
        ]);
        break;

// ----- REGISTRAR ENTRADA -----
    case 'registrar_entrada':
        $data = $_POST;
        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true) ?? [];
        }

        $estudiante = $data['Estudiante'] ?? null;
        $servicio   = $data['Servicio']   ?? null;
        $fecha      = date('Y-m-d');
        $hora       = date('H:i:s');

        if ($estudiante && $servicio) {
            $stmt = $conexion->prepare("
                INSERT INTO entrada_salida (Estudiante, Servicio, Fecha, Hora_entrada)
                VALUES (?, ?, ?, ?)
            ");
            $stmt->bind_param("iiss", $estudiante, $servicio, $fecha, $hora);
            $stmt->execute();

            // noti
            $stmt_count = $conexion->prepare("
                SELECT COUNT(*) as total FROM entrada_salida WHERE Fecha = ?
            ");

            if (!$stmt_count) {
                error_log("Error prepare afluencia: " . $conexion->error);
            } else {
                $stmt_count->bind_param("s", $fecha);
                $stmt_count->execute();
                $res_count = $stmt_count->get_result();
                $conteo    = $res_count->fetch_assoc();

                if ($conteo['total'] >= 3) {
                    $tokens = $conexion->query("SELECT token FROM fbtokens");
                    while ($tk = $tokens->fetch_assoc()) {
                        try {
                            $message = [
                                "token" => $tk['token'],
                                "notification" => [
                                    "title" => "¡Muchas entradas!",
                                    "body"  => "Se han registrado 100 estudiantes en la biblioteca hoy."
                                ]
                            ];
                            $firebase->send($message);
                        } catch (\Exception $e) {
                            error_log("Token inválido: " . $tk['token']);
                        }
                    }
                }
            }

            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Entrada registrada", "hora" => $hora]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Datos incompletos"]);
        }
        break;

    // ----- REGISTRAR SALIDA -----
    case 'registrar_salida':
        $data = $_POST;
        if (empty($data)) {
            $data = json_decode(file_get_contents("php://input"), true) ?? [];
        }

        $id_entrada = $data['Id_entrada_salida'] ?? null;
        $hora       = date('H:i:s');

        if ($id_entrada) {
            $stmt = $conexion->prepare("
                UPDATE entrada_salida SET Hora_salida = ? WHERE Id_entrada_salida = ?
            ");
            $stmt->bind_param("si", $hora, $id_entrada);
            $stmt->execute();
            header('Content-Type: application/json');
            echo json_encode(["status" => "success", "message" => "Salida registrada", "hora" => $hora]);
        } else {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "ID requerido"]);
        }
        break;

    // ----- GRAFICAR VISITAS POR FECHA -----
    case 'graficarVisitas':
        $mes  = $_GET['mes']  ?? '';
        $anio = $_GET['anio'] ?? '';

        $where = [];
        if ($mes)  $where[] = "MONTH(Fecha) = '$mes'";
        if ($anio) $where[] = "YEAR(Fecha) = '$anio'";
        $filtro = count($where) ? "WHERE " . implode(" AND ", $where) : "";

        $sql = "SELECT Fecha, COUNT(*) AS Total
                FROM entrada_salida
                $filtro
                GROUP BY Fecha
                ORDER BY Fecha ASC";

        $res = $conexion->query($sql);
        $datos = [];
        while($fila = $res->fetch_assoc()) {
            $datos[] = $fila;
        }
        header('Content-Type: application/json');
        echo json_encode($datos);
    break;

    // ----- GRAFICAR VISITAS POR SERVICIO -----
    case 'graficarVisitasServicio':

        $sql = "SELECT 
                    servicios.Nombre AS Servicio,
                    COUNT(*) AS Total
                FROM entrada_salida
                INNER JOIN servicios 
                ON entrada_salida.Servicio = servicios.Id_servicio
                GROUP BY servicios.Nombre
                ORDER BY Total DESC";


        $res = $conexion->query($sql);

        $datos = [];

        while($fila = $res->fetch_assoc()){
            $datos[] = $fila;
        }

        header('Content-Type: application/json');
        echo json_encode($datos);

    break;

    // ----- LISTAR SERVICIOS PARA ESTUDIANTE -----
    case 'listar_servicios_estudiante':
        $res = $conexion->query("SELECT Id_servicio, Nombre FROM servicios");
        $datos = [];
        while ($fila = $res->fetch_assoc()) {
            $datos[] = $fila;
        }
        header('Content-Type: application/json');
        echo json_encode($datos);
        break;

    case 'totalEntradas':
        $fecha = date('Y-m-d');
        $stmt = $conexion->prepare("SELECT COUNT(*) as total FROM entrada_salida WHERE Fecha = ?");
        $stmt->bind_param("s", $fecha);
        $stmt->execute();
        $res = $stmt->get_result()->fetch_assoc();
        echo json_encode(["total" => $res['total']]);
    break;

    case 'totalLibros':
        $res = $conexion->query("SELECT COUNT(*) as total FROM libros");
        $fila = $res->fetch_assoc();
        echo json_encode(["total" => $fila['total']]);
    break;

    case 'totalEstudiantes':
        $res = $conexion->query("SELECT COUNT(*) as total FROM estudiantes");
        $fila = $res->fetch_assoc();
        echo json_encode(["total" => $fila['total']]);
    break;

    case 'totalPrestamos':
        $res = $conexion->query("SELECT COUNT(*) as total FROM prestamos WHERE Estado = 'Prestado'");
        $fila = $res->fetch_assoc();
        echo json_encode(["total" => $fila['total']]);
    break;

    default:
        echo json_encode(["error" => "Acción no válida"]);
}
?>
