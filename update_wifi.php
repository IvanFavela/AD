<?php



date_default_timezone_set('America/Denver');
require 'database.php';

header("Cache-Control: no-cache, must-revalidate"); 
header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");

$defaultLdapServer = "ldap://na.foxconn.com";
$ldapconn = null;
$searchResults = [];
$message = '';

// Procesar credenciales LDAP y búsqueda
if (isset($_POST['username']) && isset($_POST['password'])) {
    $ldapserver = $defaultLdapServer;
    $username = $_POST['username'];
    $ldapuser = $username . "@na.foxconn.com";
    $ldappass = $_POST['password'];

// Conectar al servidor LDAP
    $ldapconn = ldap_connect($ldapserver);
    if (!$ldapconn) {
        $message = "La conexión a Active Directory ha fallado.";
    } else {
        ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);

        $ldapbind = @ldap_bind($ldapconn, $ldapuser, $ldappass);
        if (!$ldapbind) {
            $message = "La autenticación en Active Directory ha fallado: " . ldap_error($ldapconn);
        }
    }
}

/////////////////////////////////////////////////////////////   ------- Obtener datos ------    ////////////////////////////////////////////////////////////////////////////////////////////
// obtener datos
function getUserData($ldapconn, $username) {
    if (!$ldapconn) {
        error_log("Error: No hay conexión LDAP activa en getUserData");
        return false;
    }

    $basedn = "OU=JZ - Wireless Accounts,OU=MX_Juarez_CMMSG_Site01,DC=na,DC=foxconn,DC=com";
    $filter = "(sAMAccountName=$username)";
    $attributes = array("displayName", "description", "employeeID", "mail", "telephoneNumber", "title", "department");

    $search = @ldap_search($ldapconn, $basedn, $filter, $attributes);
    if (!$search) {
        error_log("Error en búsqueda LDAP: " . ldap_error($ldapconn));
        return false;
    }

    $entries = ldap_get_entries($ldapconn, $search);
    if ($entries["count"] > 0) {
        error_log("Datos de usuario obtenidos: " . print_r($entries[0], true));
        return $entries[0];
    } else {
        error_log("No se encontraron datos para el usuario: $username");
        return false;
    }
}
// Función para obtener los grupos del usuario
function getUserGroups($ldapconn, $username) {
    $basedn = "DC=na,DC=foxconn,DC=com";
    $filter = "(&(objectClass=user)(sAMAccountName=$username))";
    $attributes = array("memberOf");

    $search = ldap_search($ldapconn, $basedn, $filter, $attributes);
    $entries = ldap_get_entries($ldapconn, $search);

    $groups = array();
    if ($entries['count'] > 0 && isset($entries[0]['memberof'])) {
        for ($i = 0; $i < $entries[0]['memberof']['count']; $i++) {
            $groupDN = $entries[0]['memberof'][$i];
            preg_match('/CN=([^,]+)/', $groupDN, $matches);
            if (isset($matches[1])) {
                $groups[] = $matches[1];
            }
        }
    }

    return $groups;
}

/////////////////////////////////////////////////////////////   ------- Busqueda ------    ////////////////////////////////////////////////////////////////////////////////////////////



// Procesar búsqueda
if ($ldapconn && isset($_POST['search']) && !empty($_POST['searchTerm'])) {
    $searchTerm = $_POST['searchTerm'];
    $basedn = "OU=JZ-Business Units,OU=MX_Juarez_CMMSG_Site01,DC=na,DC=foxconn,DC=com";

    function searchUsers($ldapconn, $basedn, $searchTerm) {
        $searchTerm = ldap_escape($searchTerm, "", LDAP_ESCAPE_FILTER);
        
        $filter = "(&(objectCategory=person)(objectClass=user)(|(anr=$searchTerm)(userPrincipalName=*$searchTerm*)(mail=*$searchTerm*)(cn=*$searchTerm*)(description=*$searchTerm*)(employeeID=*$searchTerm*)(displayName=*$searchTerm*)))";
        
        $attributes = array("cn", "sAMAccountName", "userAccountControl", "description", "employeeID", "displayName", "accountExpires", "mail", "givenName", "sn", "telephonenumber", "title", "department");

        $search = @ldap_search($ldapconn, $basedn, $filter, $attributes);
        if (!$search) {
            error_log("LDAP search failed: " . ldap_error($ldapconn));
            return false;
        }
        
        return ldap_get_entries($ldapconn, $search);
    }

    function isAccountEnabled($userAccountControl) {
    return ($userAccountControl & 0x0001) == 0;
	}

    function passwordNeverExpires($userAccountControl) {
        return ($userAccountControl & 0x10000) != 0; 
    }

    function formatAccountExpires($timestamp) {
        if ($timestamp == 0 || $timestamp == '9223372036854775807') {
            return "Nunca expira";
        } else {
            return date('Y-m-d', ($timestamp / 10000000) - 11644473600);
        }
    }

    $searchResults = searchUsers($ldapconn, $basedn, $searchTerm);

    if (!empty($searchResults) && $searchResults !== false) {
        logSearch($conn, $_POST['username'], $searchTerm);
    }
	if (!empty($searchResults) && $searchResults !== false) {
        $userGroups = getUserGroups($ldapconn, $searchResults[0]["samaccountname"][0]);
        logSearch($conn, $_POST['username'], $searchTerm);
    } else {
        echo ("No se encontraron datos para el usuario: $username");
        return 0;
    }
	
	function canUserChangePassword($userAccountControl) {
    return ($userAccountControl & 0x00004000) == 0;
	}
	
	$availableGroups = [
    "FSJ_GUESTS_SYSTEM_MAC",
    "FSJ_OTHER_VISITOR_SYSTEM_MAC",
    "FSJ_VISITOR_SYSTEM_MAC",
    "FSJ_OFFICE_USERS_SYSTEM_MAC",
	"FSJ_TL6_SYSTEM_MAC",
	"FSJ_RAYPRUS_SYSTEM_MAC"
    ];
	
}
// Función para obtener todos los grupos de AD
function getAllGroups($ldapconn) {
    $basedn = "DC=na,DC=foxconn,DC=com";
    $filter = "(objectClass=group)";
    $attributes = array("cn");

    $search = ldap_search($ldapconn, $basedn, $filter, $attributes);
    $entries = ldap_get_entries($ldapconn, $search);

    $groups = array();
    for ($i = 0; $i < $entries['count']; $i++) {
        $groups[] = $entries[$i]['cn'][0];
    }

    return $groups;
}
// insertar busqueda
function logSearch($conn, $username, $searchTerm) {
    $sql = "INSERT INTO trackeo (Action, user, admin_user, change_date) VALUES (:Action, :user, :admin_user, :change_date)";
    $stmt = $conn->prepare($sql);
    
    $action = "Busqueda ";
	$stmt->bindParam(':user', $searchTerm);
    $stmt->bindParam(':Action', $action);
    $stmt->bindParam(':admin_user', $username);
    
    $date = date("Y-m-d H:i:s");
    $stmt->bindParam(':change_date', $date);
    
    $stmt->execute();
}

/////////////////////////////////////////////////////////////   ------- Modificaciones ------    ////////////////////////////////////////////////////////////////////////////////////////////

// insertar modificacion
function logAttributeChange($conn, $username, $adminUser, $attribute, $oldValue, $newValue) {
    // Solo registrar el cambio si los valores son diferentes
    if ($oldValue !== $newValue) {
        $sql = "INSERT INTO trackeo (Action, user, admin_user, attribute, old_value, new_value, change_date) 
                VALUES (:action, :user, :admin_user, :attribute, :old_value, :new_value, :change_date)";
        $stmt = $conn->prepare($sql);

        $date = date("Y-m-d H:i:s");
        $action = "Modificacion"; 

        $stmt->bindParam(':action', $action);
        $stmt->bindParam(':user', $username);
        $stmt->bindParam(':admin_user', $adminUser);
        $stmt->bindParam(':attribute', $attribute);
        $stmt->bindParam(':old_value', $oldValue);
        $stmt->bindParam(':new_value', $newValue);
        $stmt->bindParam(':change_date', $date);

        if (!$stmt->execute()) {
            error_log("Error al insertar en la base de datos: " . print_r($stmt->errorInfo(), true));
        } else {
            error_log("Cambio registrado exitosamente en la base de datos para $attribute");
        }
    } else {
        error_log("No hubo cambios en el atributo $attribute para el usuario $username.");
    }
}
////aqui funciona chidi alv

// Modificar atributos en el AD e insertar en la BD
if (isset($_POST['modify'])) {
    $username = $_POST['username'];
    $server = $defaultLdapServer;
    $adminUsername = $_POST['adminUsername'];
    $adminPassword = $_POST['adminPassword'];
    
    $attributes = [
        'displayName', 'description', 'employeeID', 'mail', 'telephoneNumber', 'title', 'department'
    ];
    
    // Obtener los valores antiguos
    $ldapconn = ldap_connect($server);
    $oldUserData = false;
    if ($ldapconn) {
        ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, 0);
        if (@ldap_bind($ldapconn, $adminUsername . "@na.foxconn.com", $adminPassword)) {
            $oldUserData = getUserData($ldapconn, $username);
            error_log("Datos antiguos obtenidos: " . print_r($oldUserData, true));
        } else {
            error_log("No se pudo autenticar con LDAP para obtener datos antiguos");
        }
    } else {
        error_log("No se pudo conectar a LDAP para obtener datos antiguos");
    }

    // Construye el comando PowerShell
    $command = "powershell.exe -File \"C:\\xampp\\htdocs\\Active_directory\\shells\\modify_attribute.ps1\" -username \"$username\" -server \"$server\" -adminUsername \"$adminUsername\" -adminPassword \"$adminPassword\"";
    
    foreach ($attributes as $attr) {
        if (isset($_POST[$attr])) {
            $value = $_POST[$attr];
            $command .= " -$attr \"$value\"";
        }
    }
	
	 if (isset($_POST['enableAccount'])) {
        $command .= " -enableAccount \"" . $_POST['enableAccount'] . "\"";
    }
    if (isset($_POST['unlockAccount'])) {
        $command .= " -unlockAccount \"" . $_POST['unlockAccount'] . "\"";
    }
    if (isset($_POST['accountExpiration'])) {
        $command .= " -accountExpiration \"" . $_POST['accountExpiration'] . "\"";
    }
    if (isset($_POST['groups'])) {
        $groups = implode(',', $_POST['groups']);
        $command .= " -groups \"$groups\"";
    }

    // Ejecuta el comando PowerShell
    $output = shell_exec($command);
    error_log("Salida del comando PowerShell: " . $output);
    
    // Verifica si la modificación fue exitosa
    if (strpos($output, "Modificacion completa") !== false) {
        foreach ($attributes as $attr) {
            if (isset($_POST[$attr])) {
                $newValue = $_POST[$attr];
                $oldValue = ($oldUserData && isset($oldUserData[strtolower($attr)][0])) ? $oldUserData[strtolower($attr)][0] : "";
                
                error_log("Registrando cambio - Atributo: $attr, Valor antiguo: $oldValue, Valor nuevo: $newValue");
                
                // Registra el cambio en la base de datos
                logAttributeChange($conn, $username, $adminUsername, $attr, $oldValue, $newValue);
            }
        }
		
		if (isset($_POST['enableAccount'])) {
            logAttributeChange($conn, $username, $adminUsername, 'accountStatus', 'N/A', $_POST['enableAccount'] ? 'Habilitada' : 'Deshabilitada');
        }
        if (isset($_POST['unlockAccount']) && $_POST['unlockAccount']) {
            logAttributeChange($conn, $username, $adminUsername, 'accountLock', 'Bloqueada', 'Desbloqueada');
        }
        if (isset($_POST['accountExpiration'])) {
            logAttributeChange($conn, $username, $adminUsername, 'accountExpiration', 'N/A', $_POST['accountExpiration']);
        }
        if (isset($_POST['groups'])) {
            logAttributeChange($conn, $username, $adminUsername, 'groups', 'N/A', implode(', ', $_POST['groups']));
        }
		
		echo "<div class=output-container>";
		echo "Modificaciones realizadas y registradas en la base de datos.";
		echo "</div>";
        
    } else {
        echo "Error al modificar atributos. No se registraron cambios en la base de datos.";
    }
//arreglar esta respuesta
	echo "<div class=output-container>";
		echo "<pre>$output</pre>";
	echo "</div>";
}

?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Active Directory Tracking</title>
    <link rel="stylesheet" href="css/desing.css?v=2.1">
	<script>
			let timeout;
			
			let lastActivityTime = Date.now();
	
	function resetTimer() {
    console.log('Timer reset at:', new Date().toISOString());
    clearTimeout(timeout);
    timeout = setTimeout(clearResults, 180000); 
}

	function checkInactivity() {
    if (Date.now() - lastActivityTime >= 30000) {
        clearResults();
    } else {
        timeout = setTimeout(checkInactivity, 30000 - (Date.now() - lastActivityTime));
    }
}

	function clearResults() {
			console.log('Clearing results');
			
			// Clear table container
			const tableContainer = document.querySelector('.table-container');
			if (tableContainer) {
				tableContainer.innerHTML = ''; 
			} else {
				console.log('Element with class table-container not found.');
			}

			// Clear output container
			const outputContainers = document.querySelectorAll('.output-container');
			outputContainers.forEach(container => {
				container.innerHTML = ''; 
			});
			
			console.log('Redirigiendo a index.html');
			window.location.href = 'index.html';
		}

	document.addEventListener('mousemove', resetTimer);
	document.addEventListener('keypress', resetTimer);
	window.addEventListener('load', resetTimer);

		window.addEventListener('load', function() {
			const clearButton = document.getElementById('clearButton');
			if (clearButton) {
				clearButton.addEventListener('click', clearResults);
			}
		});
	</script>
</head>
<body>
    
        <div class="date-time" id="dateTime"></div>
		 <?php
		require_once 'menu.php';
		echo $menuHtml;
		?>
		<h3>Informacion sobre cuentas wifi</h3>

        <form method="post" action="" class="search-form">
		
		
			<br>
            <input  type="text" name="searchTerm" class="search-input" placeholder="" required>
            <br>
            <label for="username" class="search-input">Usuario Admin:</label>
            <input type="text" id="username" class="center" name="username" required>
            <label for="password">Contraseña Admin:</label>
            <input type="password" id="password" class="center" name="password" required>
            <br>
            <input type="submit" name="search" value="Buscar"  id="clearButton">
        </form>
		
			<div class="loading" id="loading">
			<div class="spinner"></div>
				<p>Buscando...</p>
			</div>
			
			<?php if ($message): ?>
				<div class=output-container id="message"><?php echo $message; ?></div>
			<?php endif; ?>
	
	<div class="container">
        <?php if ($ldapconn && !empty($searchResults) && $searchResults !== false): ?>
            <div class="table-container">
                <?php for ($i = 0; $i < $searchResults["count"]; $i++): ?>
                    <?php 
                    $uac = intval($searchResults[$i]["useraccountcontrol"][0]);
                    $isEnabled = isAccountEnabled($uac);
                    $canChangePassword = canUserChangePassword($uac);
                    ?>
                    <form method="post" action="" class="user-form">
				
                        <input type="hidden" name="username" value="<?php echo htmlspecialchars($searchResults[$i]["samaccountname"][0]); ?>">
                        
                        <div class="form-group">
                            <label>Nombre de Usuario:</label>
                            <input type="text" value="<?php echo htmlspecialchars($searchResults[$i]["samaccountname"][0]); ?>" readonly>
                        </div>

                        <div class="form-group">
                            <label for="description">Descripción:</label>
                            <input type="text" id="description" name="description" value="<?php echo isset($searchResults[$i]["description"][0]) ? htmlspecialchars($searchResults[$i]["description"][0]) : ''; ?>">
                        </div><br>
						
						<div class="form-border">
						<br><div class="form-group">
						<label>Grupos:</label>
						</div>
						<br><div class="form-memberof">
							<label>Actuales:</label>
							<div class="group-section">
								<ul class="group-list">
									<?php foreach ($userGroups as $group): ?>
										<li><?php echo htmlspecialchars($group); ?></li>
									<?php endforeach; ?>
								</ul>
							</div>
						</div>
						<div class="form-memberof2">
							<label for="groups">Disponibles:</label><br>
							<select id="groups" name="groups[]" multiple>
								<?php foreach ($availableGroups as $group): ?>
									<option value="<?php echo htmlspecialchars($group); ?>"
										<?php echo in_array($group, $userGroups) ? 'disabled' : ''; ?>>
										<?php echo htmlspecialchars($group); ?>
									</option>
								<?php endforeach; ?>
							</select>
						</div><br></div><br>
						
						<div class="form-border">
						<br><div class="form-group">
						<label>Cuenta Expira:</label>
						</div>
                        <br><div class="form-memberof">
                            <label>Fecha de expiracion:</label>
                            <input type="text" value="<?php echo formatAccountExpires($searchResults[$i]["accountexpires"][0]); ?>" readonly>
                        </div>
						<div class="form-memberof2">
							<label for="accountExpiration">Nueva fecha de expiracion:</label>
							<input type="date" id="accountExpiration" name="accountExpiration">
						</div><br></div><br>

						<div class="form-border">
                        <br><br><div class="form-group">
						<label>Estado de la cuenta:</label>
						</div>
                        <div class="form-memberof">
                            <label>Estado:</label>
                            <input type="text" value="<?php echo $isEnabled ? "Habilitada" : "Deshabilitada"; ?>" readonly>
                        </div>
						<div class="form-memberof2">
							<label for="enableAccount">Habilitar / Deshabilitar:</label>
							<select id="enableAccount" name="enableAccount">
								<option value="1">Habilitar</option>
								<option value="0">Deshabilitar</option>
							</select>
						</div><br></div><br>
						
						<div class="form-group">
                            <label for="employeeID">No. de Reloj:</label>
                            <input type="text" id="employeeID" name="employeeID" value="<?php echo isset($searchResults[$i]["employeeid"][0]) ? htmlspecialchars($searchResults[$i]["employeeid"][0]) : ''; ?>">
                        </div>
						
                        <div class="form-group">
                            <label for="mail">Correo:</label>
                            <input type="email" id="mail" name="mail" value="<?php echo isset($searchResults[$i]["mail"][0]) ? htmlspecialchars($searchResults[$i]["mail"][0]) : ''; ?>">
                        </div>

                        <div class="form-group">
                            <label for="telephoneNumber">Número de Teléfono:</label>
                            <input type="text" id="telephoneNumber" name="telephoneNumber" value="<?php echo isset($searchResults[$i]["telephonenumber"][0]) ? htmlspecialchars($searchResults[$i]["telephonenumber"][0]) : ''; ?>">
                        </div>

                        <div class="form-group">
                            <label for="title">Título:</label>
                            <input type="text" id="title" name="title" value="<?php echo isset($searchResults[$i]["title"][0]) ? htmlspecialchars($searchResults[$i]["title"][0]) : ''; ?>">
                        </div>

                        <div class="form-group">
                            <label for="department">Departamento:</label>
                            <input type="text" id="department" name="department" value="<?php echo isset($searchResults[$i]["department"][0]) ? htmlspecialchars($searchResults[$i]["department"][0]) : ''; ?>">
                        </div><br>			

                        <div class="form-group2">
                            <label for="adminUsername">Usuario Admin:</label>
                            <input type="text" id="adminUsername" name="adminUsername" required>
                        </div>

                        <div class="form-group2">
                            <label for="adminPassword">Contraseña Admin:</label>
                            <input type="password" id="adminPassword" name="adminPassword" required>
                        </div>
						
						<div class="form-group">
							<label for="unlockAccount">Desbloquear cuenta:</label>
							<input type="checkbox" id="unlockAccount" name="unlockAccount" value="1">
						</div>

                        <input type="submit" name="modify" value="Modificar Atributos">
                    </form>
                <?php endfor; ?>
            </div>
        <?php endif; ?>
    </div>
	<script>
        function updateTime() {
            const now = new Date();
            const formattedTime = now.toLocaleString('es-ES', { hour12: false });
            document.getElementById('dateTime').textContent = formattedTime;
        }

        setInterval(updateTime, 1000);
        updateTime(); 
		
		document.addEventListener('DOMContentLoaded', function() {
        const form = document.querySelector('.search-form');
        const loading = document.getElementById('loading');

        form.addEventListener('submit', function() {
            loading.style.display = 'block';
        });
    });
		function moveGroups(from, to) {
            var selectedOptions = $(from + ' option:selected');
            $(to).append(selectedOptions);
            selectedOptions.prop('selected', false);
            updateGroupSelections();
        }

        function updateGroupSelections() {
            $('#currentGroups option').prop('selected', true);
            $('#availableGroups option:not(:disabled)').prop('selected', true);
        }

        $(document).ready(function() {
            $('#moveToAvailable').click(function() {
                moveGroups('#currentGroups', '#availableGroups');
            });

            $('#moveToCurrent').click(function() {
                moveGroups('#availableGroups', '#currentGroups');
            });

            $('form').submit(updateGroupSelections);
        });
    </script>
</body>
</html>