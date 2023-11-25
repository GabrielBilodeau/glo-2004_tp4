"""\
GLO-2000 Travail pratique 4 - Serveur
Noms et numéros étudiants:
-
-
-
"""
import pathlib
import re
import hashlib
import hmac
import json
import os
import select
import socket
import sys

import glosocket
import gloutils


class Server:
    """Serveur mail @glo2000.ca."""

    def __init__(self) -> None:
        """
        Prépare le socket du serveur `_server_socket`
        et le met en mode écoute.

        Prépare les attributs suivants:
        - `_client_socs` une liste des sockets clients.
        - `_logged_users` un dictionnaire associant chaque
            socket client à un nom d'utilisateur.

        S'assure que les dossiers de données du serveur existent.
        """
        try :
             self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
             self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
             self._server_socket.bind(("127.0.0.1", gloutils.APP_PORT))
             self._server_socket.listen()
        except socket.error:
            sys.exit(1)

        self._client_socs = []
        self._logged_users = {}


        current_dir =os.path.dirname(os.path.abspath(__file__))
        SERVER_DATA_DIR = os.path.join(current_dir, gloutils.SERVER_DATA_DIR)
        SERVER_LOST_DIR = gloutils.SERVER_LOST_DIR

        if not os.path.exists(SERVER_DATA_DIR):
            os.makedirs(SERVER_DATA_DIR)
        
        lost_dir_path = os.path.join(SERVER_DATA_DIR, SERVER_LOST_DIR)
        if not os.path.exists(lost_dir_path):
            os.makedirs(lost_dir_path)

        self._SERVER_LOST_DIR = SERVER_DATA_DIR

    def cleanup(self) -> None:
        """Ferme toutes les connexions résiduelles."""
        for client_soc in self._client_socs:
            client_soc.close()
        self._server_socket.close()

    def _accept_client(self) -> None:
        """Accepte un nouveau client."""
        print("accepting new client")
        client_socket, _  = self._server_socket.accept()
        self._client_socs.append(client_socket)

        payload = glosocket.recv_mesg(client_socket)

        if json.loads(payload)["header"] == gloutils.Headers.AUTH_LOGIN:
            message = self._login(client_socket, payload)
            glosocket.send_mesg(client_socket, json.dumps(message))
        elif json.loads(payload)["header"] == gloutils.Headers.AUTH_REGISTER:
            message = self._create_account(client_socket, payload)
            glosocket.send_mesg(client_socket,json.dumps(message))
        elif json.loads(payload)["header"] == gloutils.Headers.BYE:
            # Si logged in retirer du dic
            self._client_socs.pop(client_socket)
            client_socket.close()

    def _remove_client(self, client_soc: socket.socket) -> None:
        """Retire le client des structures de données et ferme sa connexion."""
        if client_soc in self._client_socs:
            self._client_socs.remove(client_soc)
        client_soc.close()

    def _create_account(self, client_soc: socket.socket,
                        payload: gloutils.AuthPayload
                        ) -> gloutils.GloMessage:
        """
        Crée un compte à partir des données du payload.

        Si les identifiants sont valides, créee le dossier de l'utilisateur,
        associe le socket au nouvel l'utilisateur et retourne un succès,
        sinon retourne un message d'erreur.
        """
        print('Creating a new account server side')

        message = json.loads(payload)
        received_username = message["payload"]["username"]
        received_pwd = message["payload"]["password"]

        if self._is_valid_username(received_username):
            lowerCaseUsername = received_username.lower()
            user_dir = os.path.join(self._SERVER_LOST_DIR, lowerCaseUsername)

            if not os.path.exists(user_dir):

                if re.search(r"(?=[^a-z]*[a-z])(?=[^A-Z]*[A-Z])(?=[^\d]*\d).{10,}",
                              received_pwd):
                    
                    hasher = hashlib.sha3_512()
                    hasher.update(received_pwd.encode('utf-8'))
  
                    os.makedirs(user_dir)
                    with open(user_dir + '/' + 
                              gloutils.PASSWORD_FILENAME, "a") as f:
                        f.write(hasher.hexdigest())

                    return gloutils.GloMessage(
                        header=gloutils.Headers.OK,
                    )
                   
                else:
                   error_payload = gloutils.ErrorPayload(
                       error_message="Le mot de passe n'est pas assez securise"
                    )
                   return gloutils.GloMessage(
                       header=gloutils.Headers.ERROR,
                       payload=error_payload
                    )   
            else:
                error_payload = gloutils.ErrorPayload(
                   error_message="le nom d'utilisateur est deja utilise"
                   )
                return gloutils.GloMessage(
                   header=gloutils.Headers.ERROR,
                   payload=error_payload
               )
        else:
            error_payload = gloutils.ErrorPayload(
                error_message="le nom d'utilisateur n'est pas valide"
            )
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload=error_payload
            )
        return gloutils.GloMessage()
    
    def _is_valid_username(self, other) -> bool:
        pattern = re.compile(r'^[a-zA-Z0-9_.-]+$')
        return bool(pattern.match(other))

    def _login(self, client_soc: socket.socket, payload: gloutils.AuthPayload
               ) -> gloutils.GloMessage:
        """
        Vérifie que les données fournies correspondent à un compte existant.

        Si les identifiants sont valides, associe le socket à l'utilisateur et
        retourne un succès, sinon retourne un message d'erreur.
        """

        # Changer le header
        if client_soc in self._logged_users:
            if self._logged_users[client_soc] == payload:
                return gloutils.GloMessage(
                        header=gloutils.Headers.AUTH_LOGIN,
                        payload=gloutils.Headers.OK
                    )
        else:
            return gloutils.GloMessage(
                        header=gloutils.Headers.AUTH_LOGIN,
                        payload=gloutils.Headers.ERROR
                    )

    def _logout(self, client_soc: socket.socket) -> None:
        """Déconnecte un utilisateur."""

    def _get_email_list(self, client_soc: socket.socket
                        ) -> gloutils.GloMessage:
        """
        Récupère la liste des courriels de l'utilisateur associé au socket.
        Les éléments de la liste sont construits à l'aide du gabarit
        SUBJECT_DISPLAY et sont ordonnés du plus récent au plus ancien.

        Une absence de courriel n'est pas une erreur, mais une liste vide.
        """
        return gloutils.GloMessage()

    def _get_email(self, client_soc: socket.socket,
                   payload: gloutils.EmailChoicePayload
                   ) -> gloutils.GloMessage:
        """
        Récupère le contenu de l'email dans le dossier de l'utilisateur associé
        au socket.
        """
        return gloutils.GloMessage()

    def _get_stats(self, client_soc: socket.socket) -> gloutils.GloMessage:
        """
        Récupère le nombre de courriels et la taille du dossier et des fichiers
        de l'utilisateur associé au socket.
        """
        return gloutils.GloMessage()

    def _send_email(self, payload: gloutils.EmailContentPayload
                    ) -> gloutils.GloMessage:
        """
        Détermine si l'envoi est interne ou externe et:
        - Si l'envoi est interne, écris le message tel quel dans le dossier
        du destinataire.
        - Si le destinataire n'existe pas, place le message dans le dossier
        SERVER_LOST_DIR et considère l'envoi comme un échec.
        - Si le destinataire est externe, considère l'envoi comme un échec.

        Retourne un messange indiquant le succès ou l'échec de l'opération.
        """
        return gloutils.GloMessage()

    def run(self):
        """Point d'entrée du serveur."""
        result = select.select([self._server_socket] + self._client_socs, [], [])
        waiters = result[0]
        while True:
            # Select readable sockets
            for waiter in waiters:
                if waiter == self._server_socket:
                    self._accept_client()
                
                   
            


def _main() -> int:
    server = Server()
    try:
        server.run()
    except KeyboardInterrupt:
        server.cleanup()
    return 0


if __name__ == '__main__':
    sys.exit(_main())
