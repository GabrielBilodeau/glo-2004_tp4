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
        client_socket, _  = self._server_socket.accept()
        self._client_socs.append(client_socket)

        

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
        received_username = payload["username"]
        received_pwd = payload["password"]

        if self._is_valid_username(received_username):
            lowerCaseUsername = received_username.lower()
            user_dir = os.path.join(self._SERVER_LOST_DIR, lowerCaseUsername)

            if not os.path.exists(user_dir):

                if re.search(r"(?=[^a-z]*[a-z])(?=[^A-Z]*[A-Z])(?=[^\d]*\d).{10,}",
                              received_pwd):
                    
                    hasher = hashlib.sha3_512()
                    hasher.update(received_pwd.encode('utf-8'))
  
                    os.makedirs(user_dir)
                    with open(os.path.join(user_dir, gloutils.PASSWORD_FILENAME),
                               "a") as f:
                        f.write(hasher.hexdigest())

                    self._logged_users[client_soc] = received_username

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

        recv_username = payload["username"]
        recv_pwd = payload["password"]

        hasher = hashlib.sha3_512()
        hasher.update(recv_pwd.encode('utf-8'))

        user_dir = os.path.join(self._SERVER_LOST_DIR, recv_username.lower())

        if os.path.exists(user_dir):
            with open(os.path.join(user_dir, gloutils.PASSWORD_FILENAME), "r") as f:
                stored_pwd =  f.readline()
                if hmac.compare_digest(hasher.hexdigest(), stored_pwd):
                    print('connecion ressuite')
                    self._logged_users[client_soc] = recv_username
                    return gloutils.GloMessage(
                        header=gloutils.Headers.OK
                    )

        error_payload = gloutils.ErrorPayload(
            error_message="Les indentifiants ne sont pas valides"
        )
        return gloutils.GloMessage(
            header=gloutils.Headers.ERROR,
            payload=error_payload
        )

    def _logout(self, client_soc: socket.socket) -> None:
        """Déconnecte un utilisateur."""
        del self._logged_users[client_soc]


    def _get_email_list(self, client_soc: socket.socket
                        ) -> gloutils.GloMessage:
        """
        Récupère la liste des courriels de l'utilisateur associé au socket.
        Les éléments de la liste sont construits à l'aide du gabarit
        SUBJECT_DISPLAY et sont ordonnés du plus récent au plus ancien.

        Une absence de courriel n'est pas une erreur, mais une liste vide.
        """

        mail_list = []

        username = self._logged_users[client_soc]

        path = os.path.join(self._SERVER_LOST_DIR, username.lower())
        user_path = pathlib.Path(path)
        counter = 1
        for file in user_path.iterdir():
            if os.path.basename(file) != gloutils.PASSWORD_FILENAME:
                with open (file, "r") as f:
                    info = json.load(f)
                    formattedText = gloutils.SUBJECT_DISPLAY.format(number=counter, sender=info["sender"], subject=info["subject"], date=info["date"])
                    mail_list.append(formattedText)
                    counter += 1

        payload = gloutils.EmailListPayload(
            email_list=mail_list
        )

        return gloutils.GloMessage(
            header= gloutils.Headers.OK,
            payload=payload
        )

    def _get_email(self, client_soc: socket.socket,
                   payload: gloutils.EmailChoicePayload
                   ) -> gloutils.GloMessage:
        """
        Récupère le contenu de l'email dans le dossier de l'utilisateur associé
        au socket.
        """

        choice = payload["choice"]
        username = self._logged_users[client_soc]

        path = os.path.join(self._SERVER_LOST_DIR, username.lower())
        user_path = pathlib.Path(path)
        counter = 1
        for file in user_path.iterdir():
            if os.path.basename(file) != gloutils.PASSWORD_FILENAME:
                if choice == counter:
                    with open (file, "r") as f:
                        mailcontent =  json.load(f)
                    break
                counter += 1
        payload = gloutils.EmailContentPayload(
            content=mailcontent["content"],
            date=mailcontent["date"],
            destination=mailcontent["destination"],
            sender=mailcontent["sender"],
            subject=mailcontent["subject"]
        )   

        return gloutils.GloMessage(
            header=gloutils.Headers.OK,
            payload=payload
        )

    def _get_stats(self, client_soc: socket.socket) -> gloutils.GloMessage:
        """
        Récupère le nombre de courriels et la taille du dossier et des fichiers
        de l'utilisateur associé au socket.
        """
        username = self._logged_users[client_soc]

        path = os.path.join(self._SERVER_LOST_DIR, username.lower())
        user_path = pathlib.Path(path)
        counter = 0
        size = 0
        for file in user_path.iterdir():
            if os.path.basename(file) != gloutils.PASSWORD_FILENAME:
                counter += 1
                size += os.path.getsize(file)

        payload = gloutils.StatsPayload(
            count=counter,
            size=size
        )
        return gloutils.GloMessage(
            header=gloutils.Headers.OK,
            payload=payload
        )

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

        dest = payload["destination"]
        try:
            username = dest[:dest.index('@')]
            domain = dest[dest.index('@') + 1:]
        except ValueError:
            error_payload = gloutils.ErrorPayload(
                error_message= "Le nom du destinataire n'est pas valide"
            )
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload=error_payload
            )
        

        dest_path = os.path.join(self._SERVER_LOST_DIR, username.lower())
        if domain != gloutils.SERVER_DOMAIN:
            print("externe")
            print(domain, gloutils.SERVER_DOMAIN)
            error_payload = gloutils.ErrorPayload(
               error_message= "Destinateur externe non pas pris en compte"
            )
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload=error_payload
            )
        
        if os.path.exists(dest_path):
            filename = f"{gloutils.get_current_utc_time()}.json"
            file_path = os.path.join(dest_path, filename)
            with open(file_path, "w") as json_file:
                json.dump(payload, json_file)

            return gloutils.GloMessage(
                header=gloutils.Headers.OK,
            )
        
        elif not os.path.exists(dest_path):
            
            lost_file = os.path.join(self._SERVER_LOST_DIR, gloutils.SERVER_LOST_DIR)
            filename = f"{gloutils.get_current_utc_time()}.json"
            file_path = os.path.join(lost_file, filename)
            with open(file_path, "w") as json_file:
                json.dump(payload, json_file)
            error_payload = gloutils.ErrorPayload(
                error_message="Destinataire introuvable"
            )
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload=error_payload
            )

    def run(self):
        while True:
            try:
            # Use select to wait for readable sockets
                readable, _, _ = select.select([self._server_socket] +
                                                self._client_socs, [], [])

                for sock in readable:
                    if sock == self._server_socket:
                        self._accept_client()
                    else:
                        message = glosocket.recv_mesg(sock)
                        header = json.loads(message)["header"]
                        
                        if header == gloutils.Headers.AUTH_LOGIN:
                            payload = json.loads(message)["payload"]
                            message = self._login(sock, payload)
                            glosocket.send_mesg(sock, json.dumps(message))
                        elif header == gloutils.Headers.AUTH_REGISTER:
                             payload = json.loads(message)["payload"]
                             message = self._create_account(sock, payload)
                             glosocket.send_mesg(sock, json.dumps(message))
                        elif header == gloutils.Headers.BYE:
                            self._remove_client(sock)
                        elif header == gloutils.Headers.INBOX_READING_REQUEST:
                            message = self._get_email_list(sock)
                            glosocket.send_mesg(sock, json.dumps(message))
                        elif header == gloutils.Headers.INBOX_READING_CHOICE:
                            payload = json.loads(message)["payload"]
                            message = self._get_email(sock, payload)
                            glosocket.send_mesg(sock, json.dumps(message))
                        elif header == gloutils.Headers.EMAIL_SENDING:
                            payload = json.loads(message)["payload"]
                            message = self._send_email(payload)
                            glosocket.send_mesg(sock, json.dumps(message))
                        elif header == gloutils.Headers.AUTH_LOGOUT:
                            self._logout(sock)
                        elif header == gloutils.Headers.STATS_REQUEST:
                            message= self._get_stats(sock)
                            glosocket.send_mesg(sock, json.dumps(message))
                                

            except KeyboardInterrupt:
                # Handle keyboard interrupt to gracefully exit the server
                self.cleanup()
                break



def _main() -> int:
    server = Server()
    try:
        server.run()
    except KeyboardInterrupt:
        server.cleanup()
    return 0


if __name__ == '__main__':
    sys.exit(_main())
