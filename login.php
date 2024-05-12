<?php

// Ricava i valori da POST
$username = $_POST['insertEmail'];
$password = $_POST['insertPsw'];

// Validate email
if (!filter_var($username, FILTER_VALIDATE_EMAIL)) {
	//$errorMessage = "Formato e-mail non valido";
	$errorMessage = '2';
}

// Validate password
if (strlen($password) < 8) {
	//$errorMessage = "La password deve essere di almeno 8 caratteri";
	$errorMessage = '3';
}

// Check for at least one special character
if (!preg_match("/[!@#$%^&*()\-_=+{};:,<.>1234567890]/", $password)) {
	//$errorMessage = "La password deve contenere almeno un carattere speciale e/o numero";
	$errorMessage = '4';
}

// Check for at least one capitalized character
if (!preg_match("/[A-Z]/", $password)) {
	//$errorMessage = "La password deve contenere almeno un carattere maiuscolo";
	$errorMessage = '5';
}

if (!empty ($errorMessage)) {
	header("Location: login.html?error=" . urlencode($errorMessage));
	exit();
}

// Hash password
$password_hashed = password_hash($password, PASSWORD_DEFAULT);

// Dati di connessione al database
$servename = "leofor-login.db.tb-hosting.com";
$usernameDB = "leofor_admin";
$passwordDB = "Lions5AT?";
$dbname = "leofor_login";

try {
	// Tentativo di connessione al database
	$conn = new mysqli($servename, $usernameDB, $passwordDB, $dbname);

	// Controlla la connessione
	if ($conn->connect_error) {
		throw new Exception("Connection failed: " . $conn->connect_error);
	}

	// Preparazione della query SQL per evitare SQL Injection
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

	// Esecuzione della query
    if ($result->num_rows == 1) {
        // Fetch user data
        $row = $result->fetch_assoc();
        // Verify password
        if (password_verify($password_hashed, $row['password'])) {
            // Password is correct, set session variables
            $_SESSION["loggedin"] = true;
            $_SESSION["username"] = $username;
            // Redirect to home page or any other authenticated page
            header("Location:https://www.leoforum.it/main.html");
        } else {
            // Password is incorrect
            //echo "Password errata";
			$errorMessage = "1";
			header("Location: login.html?error=" . urlencode($errorMessage));
			exit();
        }
    } else {
        // User does not exist
        //echo "Utente non trovato";			
		$errorMessage = "6";
		header("Location: login.html?error=" . urlencode($errorMessage));
		exit();
    }

	// Chiusura dello statement e della connessione
	$stmt->close();
	$conn->close();

} catch (Exception $e) {
	// Gestione degli errori
	echo "An error occurred: " . $e->getMessage();
	// Qui puoi decidere se terminare lo script o meno
	// exit();
}

