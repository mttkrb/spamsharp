# Lern- und Statistik-API, nur im Container erreichbar; die App wird über secure_ip ohne Passwort vertraut
bind_socket = "127.0.0.1:11334";
secure_ip = "127.0.0.1";
secure_ip = "::1";
allow_file_and_shm_inputs = false;
# Ersetzt das Standardpasswort "q1" des Images: Hash eines verworfenen Zufallspassworts, niemand kennt es
password = "$2$64oq3cx45yp8ei187j9e548ox7mq94gz$6trmqqzpy9wz8bqb6f8g1au5mm9qq7qr9kbr45y8a1ccdqujqhoy";
enable_password = "$2$64oq3cx45yp8ei187j9e548ox7mq94gz$6trmqqzpy9wz8bqb6f8g1au5mm9qq7qr9kbr45y8a1ccdqujqhoy";
