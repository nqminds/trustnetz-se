This demonstration establishes a secure TLS communication between a raspberry used as client (with certificates stored in a VaultIC) and a server.

1) declare the scripts as executable using 'chmod +rwx ./scripts/*.sh' 

2) run './scripts/install.sh'

3) edit the file config.cfg using 'geany ../../config.cfg', and adapt it to your project (if required)
   save and exit
   run './scripts/build.sh'
   WARNING: it is necessary to run build.sh each time you change the comm interface via config.cfg 

4) run './scripts/perso_client_vaultic.sh' (the manufacturer password provided by your FAE is required).

5) in one terminal run './scripts/run_server.sh' to start the server and wait it to start.

6) in another terminal run './scripts/run_client_vaultic.sh' to start the client.