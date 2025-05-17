<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
include('inc/funciones.inc.php');
include('secure/ips.php');

$metodo_permitido = "POST";
$archivo = "../logs/log.log";
$dominio_autorizado = "localhost";
$ip = ip_in_ranges($_SERVER['REMOTE_ADDR'], $rango);
$txt_usuario_autorizado = "admin";
$txt_contrasena_autorizada = "admin";

//verificar que el usuario haya navegado en nuestro sistema para llegar aqui a este archivo
if (array_key_exists('HTTP_REFERER', $_SERVER)) {
    //verificar que el referer sea del dominio autorizado
    if (strpos($_SERVER["HTTP_REFERER"], $dominio_autorizado) !== false) { // Corregido: Added closing parenthesis for strpos and comparison
        //se verifica que la direccion ip del usuario este autorizada
        if ($ip === true) {
            //la direccion ip del usuario si esta autorizada

            //verificar que el usuario haya enviado una peticion autorizada (método POST)
            if ($_SERVER['REQUEST_METHOD'] == $metodo_permitido) { // Corregido: Removed extra closing parenthesis
                //EL METODO ENVIADO POR EL USUARIO SI ESTA AUTORIZADO
                // LIMPIEZA DE VALORES QUE VIENEN DESDE EL FORMULARIO
                $valor_campo_usuario = ((array_key_exists("txt_user", $_POST)) ? htmlspecialchars(stripslashes(trim($_POST["txt_user"])), ENT_QUOTES) : "");
                $valor_campo_pasword = ((array_key_exists("txt_pass", $_POST)) ? htmlspecialchars(stripslashes(trim($_POST["txt_pass"])), ENT_QUOTES) : "");

                //se verifica que valores de los campos sean diferentes de vacio
                if (($valor_campo_usuario != "" || strlen($valor_campo_usuario) > 0) and ($valor_campo_pasword != "" || strlen($valor_campo_pasword) > 0)) {

                    //las variables si tienen valores
                    // Se asume que $valor_campo_password es una errata y debería ser $valor_campo_pasword
                    $usuario = preg_match('/^[a-zA-Z0-9]{1,10}+$/', $valor_campo_usuario);
                    $password = preg_match('/^[a-zA-Z0-9]{1,10}+$/', $valor_campo_pasword); // Corregido variable name

                    if ($usuario !== false and $usuario !== 0 and $password !== false and $password !== 0) {
                        //el usuario y la contraseña posee los valores aceptados

                        if ($valor_campo_usuario == $txt_usuario_autorizado and $valor_campo_pasword == $txt_contrasena_autorizada) {
                            //el usuario y la contraseña son correctos
                            //se redirige al usuario a la pagina de inicio
                            echo("HOLA MUNDO"); // Nota: Header redirects should happen before any output
                            crear_editar_log($archivo, "El usuario $valor_campo_usuario ha iniciado sesion correctamente", 1, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_REFERER"], $_SERVER["HTTP_USER_AGENT"]);
                            // Puedes añadir un header Location aquí si quieres redirigir después de loguear
                        } else {
                            //EL USUARIO NO INGRESO LAS CREDENCIALES CORRECTAS
                            crear_editar_log($archivo, "CREDENCIALES INCORRECTAS ENVIADAS HACIA //{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}", 1, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_REFERER"], $_SERVER["HTTP_USER_AGENT"]); // Corregido: Missing closing bracket for referer
                            header("HTTP/1.1 301 MOVED PERMANENTLY");
                            header("Location: ../?status=7");
                        }
                    } else {
                        //Los valores ingresados en los campos poseen caracteres no soportados
                        crear_editar_log($archivo, "ENVIO DE DATOS NO SOPORTADOS", 3, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_REFERER"], $_SERVER["HTTP_USER_AGENT"]);
                        header("HTTP/1.1 301 MOVED PERMANENTLY");
                        header("Location: ../?status=6");
                    }
                } else {
                    //LAS VARIABLES ESTAN VACIAS
                    crear_editar_log($archivo, "ENVIO DE CAMPOS VACIOS AL SERVIDOR", 2, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_REFERER"], $_SERVER["HTTP_USER_AGENT"]);
                    header("HTTP/1.1 301 MOVED PERMANENTLY");
                    header("Location: ../?status=5");
                }
            } else {
                //EL METODO ENVIADO NO ES AUTORIZADO
                crear_editar_log($archivo, "EL METODO ENVIADO NO ES AUTORIZADO", 2, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_REFERER"], $_SERVER["HTTP_USER_AGENT"]);
                header("HTTP/1.1 301 MOVED PERMANENTLY");
                header("Location: ../?status=4");
            }
        } else {
            //LA IP DEL USUARIO NO ESTA AUTORIZADA
            crear_editar_log($archivo, "LA IP DEL USUARIO NO ESTA AUTORIZADA", 2, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_REFERER"], $_SERVER["HTTP_USER_AGENT"]);
            header("HTTP/1.1 301 MOVED PERMANENTLY");
            header("Location: ../?status=3");
        }
    } else {
        //el referer de donde viene la peticion es de origen desconocido
        crear_editar_log($archivo, "EL REFERER DE DONDE VIENE LA PETICION ES DE ORIGEN DESCONOCIDO", 2, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_REFERER"], $_SERVER["HTTP_USER_AGENT"]);
        header("HTTP/1.1 301 MOVED PERMANENTLY");
        header("Location: ../?status=2");
    }
} else {
    //el usuario digito la url desde el navegador sin pasar por el formulario (No hay HTTP_REFERER)
    crear_editar_log($archivo, "EL USUARIO HA INTENTADO INGRESAR AL SISTEMA DE MANERA INCORRECTA (SIN REFERER)", 2, $_SERVER["REMOTE_ADDR"], "", $_SERVER["HTTP_USER_AGENT"]); // Corregido: $_SERVER["HTTP_REFERER"] might not exist here
    header("HTTP/1.1 301 MOVED PERMANENTLY");
    header("Location: ../?status=1");
}

?>